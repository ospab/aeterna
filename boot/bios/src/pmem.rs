/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Memory of the BIOS front-end: the `alloc` heap, the E820 map, the page allocator and the
final memory map handed to the kernel.

Layout while the loader runs (identity mapped, first 4 GiB):
  0x00500..0x7FFFF  stage1/stage2 image, real-mode scratch (see rm.rs, disk.rs, vbe.rs)
  0x200000..        .bss: page tables, stack, heap (link.ld)
  ALLOC_MIN..       free: BootInfo, page tables of the kernel, the kernel, modules
*/
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::mem::{PageKind, PAGE};
use crate::proto::*;
use crate::rm::{self, Regs};

/// First address the page allocator may hand out (everything below belongs to the loader).
pub const ALLOC_MIN: u64 = 0x50_0000;
const ALLOC_MAX: u64 = 0xFFFF_0000;
const E820_BUF: u32 = 0x2410;

extern "C" {
    static __bss_end: u8;
}

// ─── Heap ───────────────────────────────────────────────────────────────────

const HEAP_SIZE: usize = 2 << 20;

#[repr(align(16))]
struct HeapMem([u8; HEAP_SIZE]);
static mut HEAP_MEM: HeapMem = HeapMem([0; HEAP_SIZE]);

struct Node {
    size: usize,
    next: *mut Node,
}

struct FreeList {
    head: *mut Node,
}

static mut FREE: FreeList = FreeList { head: ptr::null_mut() };

impl FreeList {
    /// Insert a free block (address ordered) and merge it with its neighbours.
    unsafe fn insert(&mut self, addr: usize, size: usize) {
        let node = addr as *mut Node;
        let mut prev: *mut Node = ptr::null_mut();
        let mut cur = self.head;
        while !cur.is_null() && (cur as usize) < addr {
            prev = cur;
            cur = (*cur).next;
        }
        (*node).size = size;
        (*node).next = cur;
        if prev.is_null() {
            self.head = node;
        } else {
            (*prev).next = node;
        }
        if !cur.is_null() && addr + size == cur as usize {
            (*node).size += (*cur).size;
            (*node).next = (*cur).next;
        }
        if !prev.is_null() && prev as usize + (*prev).size == addr {
            (*prev).size += (*node).size;
            (*prev).next = (*node).next;
        }
    }
}

struct Heap;

unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(16);
        let size = (layout.size().max(16) + 15) & !15;
        let mut prev: *mut Node = ptr::null_mut();
        let mut cur = FREE.head;
        while !cur.is_null() {
            let start = (cur as usize + align - 1) & !(align - 1);
            let end = start + size;
            let block_end = cur as usize + (*cur).size;
            if end <= block_end {
                let next = (*cur).next;
                if prev.is_null() {
                    FREE.head = next;
                } else {
                    (*prev).next = next;
                }
                if start > cur as usize {
                    FREE.insert(cur as usize, start - cur as usize);
                }
                if block_end > end {
                    FREE.insert(end, block_end - end);
                }
                return start as *mut u8;
            }
            prev = cur;
            cur = (*cur).next;
        }
        ptr::null_mut()
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        let size = (layout.size().max(16) + 15) & !15;
        FREE.insert(p as usize, size);
    }
}

#[global_allocator]
static ALLOCATOR: Heap = Heap;

// ─── E820 and the page allocator ────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Seg {
    base: u64,
    end: u64,
    kind: u64,
}

#[derive(Clone, Copy)]
struct Alloc {
    base: u64,
    end: u64,
    kind: PageKind,
}

struct State {
    /// Sanitised map: sorted, no overlaps, kinds are MEM_*.
    map: Vec<Seg>,
    allocs: Vec<Alloc>,
    cursor: u64,
}

static mut STATE: State = State { map: Vec::new(), allocs: Vec::new(), cursor: ALLOC_MIN };

fn state() -> &'static mut State {
    unsafe { &mut *ptr::addr_of_mut!(STATE) }
}

fn e820_kind(t: u32) -> (u64, u8) {
    // (MEM_* kind, rank when ranges overlap: the higher rank wins)
    match t {
        1 => (MEM_USABLE, 1),
        3 => (MEM_ACPI_RECLAIMABLE, 2),
        2 => (MEM_RESERVED, 3),
        4 => (MEM_ACPI_NVS, 4),
        5 => (MEM_BAD_MEMORY, 5),
        _ => (MEM_RESERVED, 3),
    }
}

/// Raw E820 entries as (base, length, type).
fn read_e820() -> Vec<(u64, u64, u32)> {
    let mut out = Vec::new();
    let mut cont = 0u32;
    for _ in 0..256 {
        unsafe {
            ptr::write_bytes(E820_BUF as *mut u8, 0, 32);
            ptr::write((E820_BUF + 20) as *mut u32, 1);
        }
        let mut r = Regs::new();
        r.eax = 0xE820;
        r.edx = 0x534D_4150;
        r.ecx = 24;
        r.ebx = cont;
        r.es_di(E820_BUF);
        rm::int(0x15, &mut r);
        if r.carry() || r.eax != 0x534D_4150 {
            break;
        }
        let (base, len, typ, attr) = unsafe {
            (
                ptr::read(E820_BUF as *const u64),
                ptr::read((E820_BUF + 8) as *const u64),
                ptr::read((E820_BUF + 16) as *const u32),
                ptr::read((E820_BUF + 20) as *const u32),
            )
        };
        if len != 0 && (r.ecx < 24 || attr & 1 != 0) {
            out.push((base, len, typ));
        }
        cont = r.ebx;
        if cont == 0 {
            break;
        }
    }
    if out.is_empty() {
        // INT 15h AX=E801 (up to 4 GiB), then AH=88 (up to 64 MiB).
        let mut r = Regs::new();
        r.eax = 0xE801;
        rm::int(0x15, &mut r);
        if !r.carry() && r.ax() != 0 {
            let (low_kb, high_64k) = if r.ecx as u16 != 0 { (r.ecx as u16, r.edx as u16) } else { (r.ax(), r.ebx as u16) };
            out.push((0x10_0000, low_kb as u64 * 1024, 1));
            if high_64k != 0 {
                out.push((0x100_0000, high_64k as u64 * 65536, 1));
            }
        } else {
            let mut r = Regs::new();
            r.eax = 0x8800;
            rm::int(0x15, &mut r);
            if !r.carry() && r.ax() != 0 {
                out.push((0x10_0000, r.ax() as u64 * 1024, 1));
            }
        }
        out.push((0, 0x9F000, 1));
    }
    out
}

/// Resolve overlaps (the strongest kind wins), drop holes, align usable memory to pages.
fn sanitize(raw: &[(u64, u64, u32)]) -> Vec<Seg> {
    let mut points: Vec<u64> = Vec::new();
    for &(b, l, _) in raw {
        points.push(b);
        points.push(b.saturating_add(l));
    }
    points.sort_unstable();
    points.dedup();
    let mut out: Vec<Seg> = Vec::new();
    for w in points.windows(2) {
        let (a, b) = (w[0], w[1]);
        let mut best: Option<(u64, u8)> = None;
        for &(rb, rl, t) in raw {
            if rb <= a && b <= rb.saturating_add(rl) {
                let k = e820_kind(t);
                if best.map_or(true, |(_, r)| k.1 > r) {
                    best = Some(k);
                }
            }
        }
        let Some((kind, _)) = best else { continue };
        let (mut a, mut b) = (a, b);
        if kind == MEM_USABLE {
            a = (a + PAGE - 1) & !(PAGE - 1);
            b &= !(PAGE - 1);
            if a >= b {
                continue;
            }
        }
        if let Some(last) = out.last_mut() {
            if last.kind == kind && last.end == a {
                last.end = b;
                continue;
            }
        }
        out.push(Seg { base: a, end: b, kind });
    }
    out
}

pub fn init() {
    unsafe {
        FREE.head = ptr::null_mut();
        FREE.insert(ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE);
    }
}

/// Read the BIOS memory map. Call after `init`.
pub fn read_map() {
    let raw = read_e820();
    let st = state();
    st.map = sanitize(&raw);
    let bss_end = ptr::addr_of!(__bss_end) as u64;
    assert!(bss_end <= ALLOC_MIN, "loader image too big");
}

pub fn usable_total() -> u64 {
    state().map.iter().filter(|s| s.kind == MEM_USABLE).map(|s| s.end - s.base).sum()
}

/// Zeroed pages of physical memory, identity mapped, 4 GiB at most.
pub fn alloc_pages(pages: usize, kind: PageKind) -> u64 {
    let st = state();
    let len = pages as u64 * PAGE;
    for s in st.map.iter().filter(|s| s.kind == MEM_USABLE) {
        let start = s.base.max(st.cursor).max(ALLOC_MIN);
        let end = s.end.min(ALLOC_MAX);
        if start + len <= end {
            st.cursor = start + len;
            st.allocs.push(Alloc { base: start, end: start + len, kind });
            unsafe { ptr::write_bytes(start as *mut u8, 0, len as usize) };
            return start;
        }
    }
    panic!("out of memory ({} pages)", pages);
}

/// End of the highest RAM or ACPI region: the direct map must cover it.
pub fn ram_top() -> u64 {
    state()
        .map
        .iter()
        .filter(|s| matches!(s.kind, MEM_USABLE | MEM_ACPI_RECLAIMABLE | MEM_ACPI_NVS))
        .map(|s| s.end)
        .max()
        .unwrap_or(0)
}

/// Replace the part of `segs` inside [a, b) by one segment of `kind`
/// (only the usable parts when `only_usable`).
fn carve(segs: &mut Vec<Seg>, a: u64, b: u64, kind: u64, only_usable: bool) {
    let mut out: Vec<Seg> = Vec::with_capacity(segs.len() + 2);
    for s in segs.iter() {
        if s.end <= a || s.base >= b || (only_usable && s.kind != MEM_USABLE) {
            out.push(*s);
            continue;
        }
        if s.base < a {
            out.push(Seg { base: s.base, end: a, kind: s.kind });
        }
        out.push(Seg { base: s.base.max(a), end: s.end.min(b), kind });
        if s.end > b {
            out.push(Seg { base: b, end: s.end, kind: s.kind });
        }
    }
    *segs = out;
}

fn normalize(segs: &mut Vec<Seg>) {
    segs.sort_by_key(|s| s.base);
    let mut out: Vec<Seg> = Vec::with_capacity(segs.len());
    for s in segs.iter() {
        if s.base >= s.end {
            continue;
        }
        if let Some(l) = out.last_mut() {
            if l.kind == s.kind && l.end == s.base {
                l.end = s.end;
                continue;
            }
        }
        out.push(*s);
    }
    *segs = out;
}

/// The memory map for the kernel: E820 plus what the loader allocated, low memory and the
/// loader's own memory as bootloader-reclaimable, the framebuffer as its own region.
/// Call after the last allocation.
pub fn final_map(out: &mut [MemoryRegion], fb: &FramebufferInfo) -> usize {
    let st = state();
    let mut segs = st.map.clone();
    // Real-mode scratch, stage2 and BIOS data stay untouched until the kernel is done with boot info.
    carve(&mut segs, 0, 0x10_0000, MEM_BOOTLOADER_RECLAIMABLE, true);
    let bss_end = ptr::addr_of!(__bss_end) as u64;
    carve(&mut segs, 0x20_0000, bss_end, MEM_BOOTLOADER_RECLAIMABLE, true);
    for a in &st.allocs {
        let kind = match a.kind {
            PageKind::Kernel => MEM_KERNEL_AND_MODULES,
            PageKind::Reclaim => MEM_BOOTLOADER_RECLAIMABLE,
        };
        carve(&mut segs, a.base, a.end, kind, true);
    }
    if fb.phys_addr != 0 {
        let end = (fb.phys_addr + fb.pitch * fb.height + PAGE - 1) & !(PAGE - 1);
        carve(&mut segs, fb.phys_addr, end, MEM_FRAMEBUFFER, false);
        if !segs.iter().any(|s| s.kind == MEM_FRAMEBUFFER) {
            segs.push(Seg { base: fb.phys_addr, end, kind: MEM_FRAMEBUFFER });
        }
    }
    normalize(&mut segs);
    let n = segs.len().min(out.len());
    for (o, s) in out.iter_mut().zip(segs.iter()).take(n) {
        *o = MemoryRegion { base: s.base, length: s.end - s.base, kind: s.kind };
    }
    n
}

/// Free RAM above ALLOC_MIN as (start, bytes) for the memory test, page aligned.
pub fn test_ranges() -> Vec<(u64, u64)> {
    let st = state();
    let mut segs = st.map.clone();
    for a in &st.allocs {
        carve(&mut segs, a.base, a.end, MEM_RESERVED, true);
    }
    normalize(&mut segs);
    segs.iter()
        .filter(|s| s.kind == MEM_USABLE && s.end > ALLOC_MIN)
        .map(|s| {
            let b = s.base.max(ALLOC_MIN);
            (b, s.end - b)
        })
        .collect()
}
