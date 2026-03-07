/*
Business Source License 1.1
Copyright (c) 2026 ospab
Physical memory manager for AETERNA microkernel.
Parses Limine memory map, tracks usable regions, provides frame allocation.
*/

/// Physical page frame size (4 KiB)
pub const FRAME_SIZE: u64 = 4096;

/// Huge page frame size (2 MiB) — for TENSOR mapping
pub const HUGE_FRAME_SIZE: u64 = 2 * 1024 * 1024;

/// Ultra huge page frame size (1 GiB) — for heavy AI models
pub const GIGA_FRAME_SIZE: u64 = 1024 * 1024 * 1024;

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

/// Simple bump allocator for physical frames.
///
/// # Design note — intentional one-way allocator (v1.0.0)
///
/// This allocator only advances a pointer forward; there is no `free_frame()`.
/// Physical frames allocated here are permanent for the lifetime of the kernel.
/// This is acceptable for v1.0.0 because:
///   - The heap (linked_list_allocator) handles short-lived kernel allocations.
///   - Long-lived objects (heap arena, AHCI/DMA buffers, address spaces) are
///     never individually freed — they outlive the kernel.
/// A slab/free-list allocator is planned for Phase 9+ once multi-process
/// memory isolation requires frame recycling.
static mut REGIONS: [PhysRegion; MAX_REGIONS] = [PhysRegion { base: 0, length: 0 }; MAX_REGIONS];
static mut REGION_COUNT: usize = 0;
static mut TOTAL_MEMORY: u64 = 0;
static mut USABLE_MEMORY: u64 = 0;
static mut NEXT_FREE_FRAME: u64 = 0;
static mut FRAMES_ALLOCATED: u64 = 0;

/// Initialize physical memory manager from Limine memory map
pub fn init() {
    let memmap = crate::arch::x86_64::boot::memory_map();
    if memmap.is_none() {
        crate::arch::x86_64::serial::write_str("[AETERNA] FATAL: No memory map from bootloader\r\n");
        return;
    }

    let mut total: u64 = 0;
    let mut usable: u64 = 0;
    let mut count: usize = 0;

    for entry in memmap.unwrap() {
        total += entry.length;

        if entry.typ == crate::arch::x86_64::boot::MEMMAP_USABLE {
            usable += entry.length;
            if count < MAX_REGIONS {
                unsafe {
                    REGIONS[count] = PhysRegion {
                        base: entry.base,
                        length: entry.length,
                    };
                }
                count += 1;
            }
        }
    }

    unsafe {
        REGION_COUNT = count;
        TOTAL_MEMORY = total;
        USABLE_MEMORY = usable;

        // Find the first region that starts at or above 1 MiB (skip low memory)
        for i in 0..count {
            if REGIONS[i].base >= 0x100000 && REGIONS[i].length >= FRAME_SIZE {
                NEXT_FREE_FRAME = REGIONS[i].base;
                break;
            }
        }
    }

    // Log memory info
    crate::arch::x86_64::serial::write_str("[AETERNA] Physical memory: ");
    log_size(usable);
    crate::arch::x86_64::serial::write_str(" usable / ");
    log_size(total);
    crate::arch::x86_64::serial::write_str(" total, ");
    log_dec(count as u64);
    crate::arch::x86_64::serial::write_str(" regions\r\n");
}

/// Allocate a single physical page frame (4 KiB)
/// Returns physical address of the frame, or None if out of memory
pub fn alloc_frame() -> Option<u64> {
    unsafe {
        for i in 0..REGION_COUNT {
            let region = &REGIONS[i];
            let region_end = region.base + region.length;

            if NEXT_FREE_FRAME >= region.base && NEXT_FREE_FRAME + FRAME_SIZE <= region_end {
                let frame = NEXT_FREE_FRAME;
                NEXT_FREE_FRAME += FRAME_SIZE;
                FRAMES_ALLOCATED += 1;
                return Some(frame);
            }

            // If we're past this region, check next one
            if NEXT_FREE_FRAME < region.base {
                // Jump to this region
                NEXT_FREE_FRAME = region.base;
                if NEXT_FREE_FRAME + FRAME_SIZE <= region_end {
                    let frame = NEXT_FREE_FRAME;
                    NEXT_FREE_FRAME += FRAME_SIZE;
                    FRAMES_ALLOCATED += 1;
                    return Some(frame);
                }
            }
        }
        None
    }
}

/// Allocate contiguous physical frames
/// Returns physical address of the first frame, or None if not enough memory
pub fn alloc_frames(count: u64) -> Option<u64> {
    let bytes_needed = count * FRAME_SIZE;
    unsafe {
        for i in 0..REGION_COUNT {
            let region = &REGIONS[i];
            let region_end = region.base + region.length;

            // Align NEXT_FREE_FRAME to start of this region if needed
            let start = if NEXT_FREE_FRAME >= region.base {
                NEXT_FREE_FRAME
            } else {
                region.base
            };

            if start + bytes_needed <= region_end {
                NEXT_FREE_FRAME = start + bytes_needed;
                FRAMES_ALLOCATED += count;
                return Some(start);
            }
        }
        None
    }
}

/// Allocate a single 2 MiB huge frame.
/// Returns physical address aligned to 2 MiB, or None.
pub fn alloc_huge_frame() -> Option<u64> {
    alloc_huge_frames(1)
}

/// Allocate contiguous 2 MiB huge frames.
pub fn alloc_huge_frames(count: u64) -> Option<u64> {
    let bytes_needed = count * HUGE_FRAME_SIZE;
    unsafe {
        for i in 0..REGION_COUNT {
            let region = &REGIONS[i];
            let region_end = region.base + region.length;

            // Align current pointer to 2MB boundary
            let start = (NEXT_FREE_FRAME + HUGE_FRAME_SIZE - 1) & !(HUGE_FRAME_SIZE - 1);
            
            // Adjust start to be within this region
            let start = if start >= region.base { start } else {
                (region.base + HUGE_FRAME_SIZE - 1) & !(HUGE_FRAME_SIZE - 1)
            };

            if start + bytes_needed <= region_end {
                NEXT_FREE_FRAME = start + bytes_needed;
                FRAMES_ALLOCATED += count * (HUGE_FRAME_SIZE / FRAME_SIZE);
                return Some(start);
            }
        }
        None
    }
}

/// Get memory statistics
pub fn stats() -> PhysMemStats {
    unsafe {
        PhysMemStats {
            total_bytes: TOTAL_MEMORY,
            usable_bytes: USABLE_MEMORY,
            reserved_bytes: TOTAL_MEMORY - USABLE_MEMORY,
            region_count: REGION_COUNT,
        }
    }
}

/// Get number of frames allocated so far
pub fn frames_allocated() -> u64 {
    unsafe { FRAMES_ALLOCATED }
}

/// Get usable memory in bytes
pub fn usable_memory() -> u64 {
    unsafe { USABLE_MEMORY }
}

/// Get total memory in bytes
pub fn total_memory() -> u64 {
    unsafe { TOTAL_MEMORY }
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
    unsafe { &REGIONS[..REGION_COUNT] }
}
