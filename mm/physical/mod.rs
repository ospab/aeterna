/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Physical memory manager for AETERNA microkernel.

Bitmap frame allocator: one bit per 4 KiB frame over [0, highest usable address).
A set bit means "not available" (used, reserved, or not RAM). The bitmap itself
lives in the first usable region above 1 MiB and is accessed through the HHDM.

Every frame handed out is zeroed, so a frame freed by one process never leaks
its contents to the next owner.
*/

use spin::Mutex;

/// Physical page frame size (4 KiB)
pub const FRAME_SIZE: u64 = 4096;

/// Huge page frame size (2 MiB)
pub const HUGE_FRAME_SIZE: u64 = 2 * 1024 * 1024;

/// Frames below this address are never handed out (real-mode/BIOS area, AP trampolines).
const LOW_MEMORY_LIMIT: u64 = 0x100000;

/// Maximum number of usable memory regions we track
const MAX_REGIONS: usize = 64;

/// A contiguous region of usable physical memory
#[derive(Debug, Clone, Copy)]
pub struct PhysRegion {
    pub base: u64,
    pub length: u64,
}

/// Physical memory statistics
#[derive(Debug, Clone, Copy)]
pub struct PhysMemStats {
    pub total_bytes: u64,
    pub usable_bytes: u64,
    pub reserved_bytes: u64,
    pub region_count: usize,
}

struct FrameBitmap {
    /// Virtual (HHDM) address of the bitmap words.
    words: *mut u64,
    /// Number of u64 words in the bitmap.
    word_count: usize,
    /// Number of frames covered (bits that are meaningful).
    frame_count: u64,
    /// HHDM offset, used to zero frames.
    hhdm: u64,
    /// Next-fit hint: word index where the last single-frame search succeeded.
    hint: usize,
    /// Frames currently free.
    free_frames: u64,
    /// Frames that were free right after init (usable RAM minus bitmap and low memory).
    managed_frames: u64,
}

// The raw pointer is only ever touched under the Mutex.
unsafe impl Send for FrameBitmap {}

impl FrameBitmap {
    const fn empty() -> Self {
        FrameBitmap {
            words: core::ptr::null_mut(),
            word_count: 0,
            frame_count: 0,
            hhdm: 0,
            hint: 0,
            free_frames: 0,
            managed_frames: 0,
        }
    }

    fn is_ready(&self) -> bool {
        !self.words.is_null()
    }

    #[inline]
    fn word(&self, i: usize) -> u64 {
        // SAFETY: callers keep i < word_count; the bitmap was sized and mapped in init().
        unsafe { *self.words.add(i) }
    }

    #[inline]
    fn word_mut(&mut self, i: usize) -> &mut u64 {
        // SAFETY: as above.
        unsafe { &mut *self.words.add(i) }
    }

    #[inline]
    fn is_used(&self, frame: u64) -> bool {
        self.word((frame / 64) as usize) & (1u64 << (frame % 64)) != 0
    }

    #[inline]
    fn set_used(&mut self, frame: u64) {
        *self.word_mut((frame / 64) as usize) |= 1u64 << (frame % 64);
    }

    #[inline]
    fn set_free(&mut self, frame: u64) {
        *self.word_mut((frame / 64) as usize) &= !(1u64 << (frame % 64));
    }

    fn zero_frames(&self, first: u64, count: u64) {
        let virt = (first * FRAME_SIZE + self.hhdm) as *mut u8;
        // SAFETY: the frames are usable RAM covered by the HHDM and now owned by the caller.
        unsafe { core::ptr::write_bytes(virt, 0, (count * FRAME_SIZE) as usize) };
    }

    /// Find and claim one free frame (next-fit over whole words).
    fn alloc_one(&mut self) -> Option<u64> {
        for step in 0..self.word_count {
            let i = (self.hint + step) % self.word_count;
            let w = self.word(i);
            if w != u64::MAX {
                let bit = (!w).trailing_zeros() as u64;
                let frame = i as u64 * 64 + bit;
                if frame >= self.frame_count {
                    continue;
                }
                self.set_used(frame);
                self.free_frames -= 1;
                self.hint = i;
                return Some(frame);
            }
        }
        None
    }

    /// Find and claim `count` contiguous free frames whose first frame is a
    /// multiple of `align` frames.
    fn alloc_contiguous(&mut self, count: u64, align: u64) -> Option<u64> {
        if count == 0 || count > self.free_frames {
            return None;
        }
        let align = align.max(1);
        let mut start = 0u64;
        while start + count <= self.frame_count {
            // Skip fully used words quickly when aligned to a word boundary.
            if start % 64 == 0 && self.word((start / 64) as usize) == u64::MAX {
                start += 64;
                start = (start + align - 1) / align * align;
                continue;
            }
            match (0..count).find(|&k| self.is_used(start + k)) {
                None => {
                    for k in 0..count {
                        self.set_used(start + k);
                    }
                    self.free_frames -= count;
                    return Some(start);
                }
                Some(k) => {
                    // Restart after the used frame, rounded up to the alignment.
                    start = (start + k + 1 + align - 1) / align * align;
                }
            }
        }
        None
    }

    /// Release `count` frames starting at `first`. Returns how many were actually in use.
    fn release(&mut self, first: u64, count: u64) -> u64 {
        let mut released = 0;
        for f in first..first.saturating_add(count).min(self.frame_count) {
            if self.is_used(f) {
                self.set_free(f);
                released += 1;
            }
        }
        self.free_frames += released;
        if first < self.frame_count {
            self.hint = self.hint.min((first / 64) as usize);
        }
        released
    }
}

static BITMAP: Mutex<FrameBitmap> = Mutex::new(FrameBitmap::empty());

static mut REGIONS: [PhysRegion; MAX_REGIONS] = [PhysRegion { base: 0, length: 0 }; MAX_REGIONS];
static mut REGION_COUNT: usize = 0;
static mut TOTAL_MEMORY: u64 = 0;
static mut USABLE_MEMORY: u64 = 0;

/// Run `f` with the bitmap locked and interrupts disabled, so an interrupt
/// handler that allocates can never deadlock against the code it interrupted.
fn with_bitmap<R>(f: impl FnOnce(&mut FrameBitmap) -> R) -> R {
    let rflags: u64;
    // SAFETY: reading RFLAGS and clearing IF has no memory effects.
    unsafe { core::arch::asm!("pushfq; pop {}; cli", out(reg) rflags, options(nomem)) };
    let result = f(&mut BITMAP.lock());
    if rflags & (1 << 9) != 0 {
        // SAFETY: restore interrupts only if they were enabled before.
        unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
    }
    result
}

/// Initialize the physical memory manager from the bootloader memory map.
pub fn init() {
    let serial = crate::arch::x86_64::serial::write_str;
    let memmap = match crate::arch::x86_64::boot::memory_map() {
        Some(m) => m,
        None => {
            serial("[MM] FATAL: No memory map from bootloader\r\n");
            return;
        }
    };
    let hhdm = crate::arch::x86_64::boot::hhdm_offset().unwrap_or(0);

    let mut total: u64 = 0;
    let mut usable: u64 = 0;
    let mut count: usize = 0;
    let mut highest: u64 = 0;

    for entry in memmap {
        total += entry.length;
        if entry.typ == crate::arch::x86_64::boot::MEMMAP_USABLE {
            usable += entry.length;
            highest = highest.max(entry.base + entry.length);
            if count < MAX_REGIONS {
                // SAFETY: single-threaded early boot.
                unsafe { REGIONS[count] = PhysRegion { base: entry.base, length: entry.length } };
                count += 1;
            } else {
                serial("[MM] WARN: too many memory regions, ignoring the rest\r\n");
            }
        }
    }

    // SAFETY: single-threaded early boot.
    let regions = unsafe {
        REGION_COUNT = count;
        TOTAL_MEMORY = total;
        USABLE_MEMORY = usable;
        &REGIONS[..count]
    };

    let frame_count = highest / FRAME_SIZE;
    let word_count = ((frame_count + 63) / 64) as usize;
    let bitmap_bytes = (word_count * 8) as u64;
    let bitmap_frames = (bitmap_bytes + FRAME_SIZE - 1) / FRAME_SIZE;

    // Place the bitmap at the start of the first region above 1 MiB that can hold it.
    let home = regions.iter().find_map(|r| {
        let base = (r.base.max(LOW_MEMORY_LIMIT) + FRAME_SIZE - 1) & !(FRAME_SIZE - 1);
        let end = r.base + r.length;
        (base + bitmap_frames * FRAME_SIZE <= end).then_some(base)
    });
    let bitmap_phys = match home {
        Some(p) => p,
        None => {
            serial("[MM] FATAL: no room for the frame bitmap\r\n");
            return;
        }
    };

    let mut bm = BITMAP.lock();
    bm.words = (bitmap_phys + hhdm) as *mut u64;
    bm.word_count = word_count;
    bm.frame_count = frame_count;
    bm.hhdm = hhdm;
    bm.hint = 0;

    // Everything starts as unavailable; then usable RAM is opened up.
    for i in 0..word_count {
        *bm.word_mut(i) = u64::MAX;
    }
    for r in regions {
        let first = (r.base.max(LOW_MEMORY_LIMIT) + FRAME_SIZE - 1) / FRAME_SIZE;
        let last = (r.base + r.length) / FRAME_SIZE; // exclusive
        for f in first..last {
            bm.set_free(f);
        }
    }
    // The bitmap's own frames are taken.
    let bitmap_first = bitmap_phys / FRAME_SIZE;
    for f in bitmap_first..bitmap_first + bitmap_frames {
        bm.set_used(f);
    }

    let mut free = 0u64;
    for i in 0..word_count {
        free += bm.word(i).count_zeros() as u64;
    }
    // Bits past frame_count in the last word were set to 1 above, so they are not counted.
    bm.free_frames = free;
    bm.managed_frames = free;
    drop(bm);

    serial("[MM] Physical memory: ");
    log_size(usable);
    serial(" usable / ");
    log_size(total);
    serial(" total, ");
    log_dec(count as u64);
    serial(" regions, bitmap ");
    log_size(bitmap_bytes);
    serial("\r\n");
}

/// Allocate a single zeroed 4 KiB frame. Returns its physical address.
pub fn alloc_frame() -> Option<u64> {
    with_bitmap(|bm| {
        if !bm.is_ready() {
            return None;
        }
        let f = bm.alloc_one()?;
        bm.zero_frames(f, 1);
        Some(f * FRAME_SIZE)
    })
}

/// Allocate `count` physically contiguous zeroed frames.
pub fn alloc_frames(count: u64) -> Option<u64> {
    alloc_frames_aligned(count, 1)
}

/// Allocate `count` contiguous zeroed frames, the first aligned to `align_frames` frames.
pub fn alloc_frames_aligned(count: u64, align_frames: u64) -> Option<u64> {
    with_bitmap(|bm| {
        if !bm.is_ready() {
            return None;
        }
        let f = bm.alloc_contiguous(count, align_frames)?;
        bm.zero_frames(f, count);
        Some(f * FRAME_SIZE)
    })
}

/// Allocate a single 2 MiB-aligned huge frame.
pub fn alloc_huge_frame() -> Option<u64> {
    alloc_huge_frames(1)
}

/// Allocate `count` contiguous 2 MiB huge frames (2 MiB aligned).
pub fn alloc_huge_frames(count: u64) -> Option<u64> {
    let per_huge = HUGE_FRAME_SIZE / FRAME_SIZE;
    alloc_frames_aligned(count * per_huge, per_huge)
}

/// Return a single frame to the allocator.
pub fn free_frame(phys: u64) {
    free_frames(phys, 1);
}

/// Return `count` contiguous frames starting at `phys` to the allocator.
/// Freeing a frame that is not allocated is reported on serial and ignored.
pub fn free_frames(phys: u64, count: u64) {
    if phys % FRAME_SIZE != 0 {
        crate::arch::x86_64::serial::write_str("[PMM] WARN: free of unaligned address ignored\r\n");
        return;
    }
    let released = with_bitmap(|bm| bm.release(phys / FRAME_SIZE, count));
    if released != count {
        crate::arch::x86_64::serial::write_str("[PMM] WARN: double free or free of unowned frame\r\n");
    }
}

/// Get memory statistics
pub fn stats() -> PhysMemStats {
    // SAFETY: written once during init.
    unsafe {
        PhysMemStats {
            total_bytes: TOTAL_MEMORY,
            usable_bytes: USABLE_MEMORY,
            reserved_bytes: TOTAL_MEMORY - USABLE_MEMORY,
            region_count: REGION_COUNT,
        }
    }
}

/// Number of frames currently allocated (out of the frames this allocator manages).
pub fn frames_allocated() -> u64 {
    with_bitmap(|bm| bm.managed_frames - bm.free_frames)
}

/// Number of frames currently free.
pub fn frames_free() -> u64 {
    with_bitmap(|bm| bm.free_frames)
}

/// Get usable memory in bytes
pub fn usable_memory() -> u64 {
    // SAFETY: written once during init.
    unsafe { USABLE_MEMORY }
}

/// Get total memory in bytes
pub fn total_memory() -> u64 {
    // SAFETY: written once during init.
    unsafe { TOTAL_MEMORY }
}

/// Allocate and free a few frames and check the accounting and zeroing.
/// Returns false and logs on serial if anything is off.
pub fn self_test() -> bool {
    let serial = crate::arch::x86_64::serial::write_str;
    let before = frames_free();

    let a = match alloc_frame() { Some(a) => a, None => { serial("[PMM] self-test: alloc failed\r\n"); return false; } };
    let hhdm = with_bitmap(|bm| bm.hhdm);
    // Dirty the frame, free it, take it again: it must come back zeroed.
    unsafe { core::ptr::write_bytes((a + hhdm) as *mut u8, 0xAB, FRAME_SIZE as usize) };
    free_frame(a);
    let b = match alloc_frame() { Some(b) => b, None => { serial("[PMM] self-test: realloc failed\r\n"); return false; } };
    let zeroed = unsafe { core::slice::from_raw_parts((b + hhdm) as *const u8, FRAME_SIZE as usize) }
        .iter()
        .all(|&x| x == 0);
    free_frame(b);

    let c = alloc_frames_aligned(512, 512);
    let aligned = c.map_or(false, |p| p % HUGE_FRAME_SIZE == 0);
    if let Some(p) = c {
        free_frames(p, 512);
    }

    let after = frames_free();
    let ok = zeroed && aligned && before == after;
    serial(if ok { "[PMM] self-test passed\r\n" } else { "[PMM] self-test FAILED\r\n" });
    if !zeroed { serial("[PMM]   reused frame was not zeroed\r\n"); }
    if !aligned { serial("[PMM]   2 MiB aligned allocation failed\r\n"); }
    if before != after { serial("[PMM]   free count changed after alloc/free cycle\r\n"); }
    ok
}

// Helper: log size in human-readable format to serial
fn log_size(bytes: u64) {
    if bytes >= 1024 * 1024 * 1024 {
        log_dec(bytes / (1024 * 1024 * 1024));
        crate::arch::x86_64::serial::write_str(" GiB");
    } else if bytes >= 1024 * 1024 {
        log_dec(bytes / (1024 * 1024));
        crate::arch::x86_64::serial::write_str(" MiB");
    } else if bytes >= 1024 {
        log_dec(bytes / 1024);
        crate::arch::x86_64::serial::write_str(" KiB");
    } else {
        log_dec(bytes);
        crate::arch::x86_64::serial::write_str(" B");
    }
}

// Helper: log decimal number
fn log_dec(mut val: u64) {
    if val == 0 {
        crate::arch::x86_64::serial::write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    for j in (0..i).rev() {
        crate::arch::x86_64::serial::write_byte(buf[j]);
    }
}

pub fn get_usable_regions() -> &'static [PhysRegion] {
    // SAFETY: written once during init.
    unsafe { &REGIONS[..REGION_COUNT] }
}
