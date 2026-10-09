/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
ELF64 program loader.

Loads a statically linked x86-64 ELF executable (ET_EXEC) into a fresh user
address space and hands it to the scheduler as a ring-3 task:

  * every PT_LOAD segment is copied into newly allocated, zeroed frames and
    mapped with the segment's permissions (writable only if PF_W, no-execute
    unless PF_X when the CPU supports NX); `.bss` is the zeroed tail;
  * a user stack is mapped below USER_STACK_TOP and filled with the System V
    start-up layout: argc, argv[], NULL, envp[] (empty), NULL, auxv (AT_PAGESZ,
    AT_ENTRY, AT_NULL), with the argument strings above it.

All frames are mapped with FLAG_OWNED, so the address space frees them on exit.
*/

use alloc::vec::Vec;
use crate::mm::{physical, r#virtual as vmm};

const PAGE: u64 = physical::FRAME_SIZE;

/// Highest address of the user stack (exclusive); the stack grows down from here.
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_F000;
/// Size of the user stack mapped for a new program.
const USER_STACK_PAGES: u64 = 16; // 64 KiB
/// Programs may not load below this (keeps the null page and low memory unmapped).
const MIN_LOAD_ADDR: u64 = 0x0000_0000_0040_0000;
/// Upper bound for program segments (the mmap area starts at 0x1000_0000_0000).
const MAX_LOAD_ADDR: u64 = 0x0000_1000_0000_0000;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;

const AT_NULL: u64 = 0;
const AT_PAGESZ: u64 = 6;
const AT_ENTRY: u64 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    TooSmall,
    BadMagic,
    NotElf64LittleEndian,
    NotX86_64,
    NotExecutable,
    BadProgramHeaders,
    SegmentOutOfRange,
    SegmentTooLarge,
    TooManyArgs,
    OutOfMemory,
    SpawnFailed,
}

impl ElfError {
    pub fn as_str(self) -> &'static str {
        match self {
            ElfError::TooSmall => "file too small",
            ElfError::BadMagic => "not an ELF file",
            ElfError::NotElf64LittleEndian => "not a 64-bit little-endian ELF",
            ElfError::NotX86_64 => "not an x86-64 program",
            ElfError::NotExecutable => "not a static executable (ET_EXEC)",
            ElfError::BadProgramHeaders => "corrupt program headers",
            ElfError::SegmentOutOfRange => "segment outside the user load area",
            ElfError::SegmentTooLarge => "segment file size larger than memory size or file",
            ElfError::TooManyArgs => "arguments do not fit on the stack",
            ElfError::OutOfMemory => "out of memory",
            ElfError::SpawnFailed => "no free task slot",
        }
    }
}

struct Segment {
    vaddr: u64,
    memsz: u64,
    offset: u64,
    filesz: u64,
    flags: u32,
}

fn u16_at(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }
fn u32_at(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn u64_at(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

/// Parse and validate the ELF header and PT_LOAD segments. Returns (entry, segments).
fn parse(image: &[u8]) -> Result<(u64, Vec<Segment>), ElfError> {
    if image.len() < 64 {
        return Err(ElfError::TooSmall);
    }
    if &image[0..4] != b"\x7fELF" {
        return Err(ElfError::BadMagic);
    }
    if image[4] != 2 || image[5] != 1 {
        return Err(ElfError::NotElf64LittleEndian);
    }
    if u16_at(image, 18) != 62 {
        return Err(ElfError::NotX86_64);
    }
    if u16_at(image, 16) != 2 {
        return Err(ElfError::NotExecutable);
    }
    let entry = u64_at(image, 24);
    let phoff = u64_at(image, 32) as usize;
    let phentsize = u16_at(image, 54) as usize;
    let phnum = u16_at(image, 56) as usize;
    if phentsize < 56 || phnum == 0 || phnum > 64 {
        return Err(ElfError::BadProgramHeaders);
    }
    let table_end = phoff
        .checked_add(phentsize * phnum)
        .ok_or(ElfError::BadProgramHeaders)?;
    if table_end > image.len() {
        return Err(ElfError::BadProgramHeaders);
    }

    let mut segs = Vec::new();
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        if u32_at(image, p) != PT_LOAD {
            continue;
        }
        let seg = Segment {
            flags: u32_at(image, p + 4),
            offset: u64_at(image, p + 8),
            vaddr: u64_at(image, p + 16),
            filesz: u64_at(image, p + 32),
            memsz: u64_at(image, p + 40),
        };
        if seg.memsz == 0 {
            continue;
        }
        let end = seg.vaddr.checked_add(seg.memsz).ok_or(ElfError::SegmentOutOfRange)?;
        if seg.vaddr < MIN_LOAD_ADDR || end > MAX_LOAD_ADDR {
            return Err(ElfError::SegmentOutOfRange);
        }
        let file_end = seg.offset.checked_add(seg.filesz).ok_or(ElfError::SegmentTooLarge)?;
        if seg.filesz > seg.memsz || file_end > image.len() as u64 {
            return Err(ElfError::SegmentTooLarge);
        }
        segs.push(seg);
    }
    if segs.is_empty() {
        return Err(ElfError::BadProgramHeaders);
    }
    if !segs.iter().any(|s| s.flags & PF_X != 0 && entry >= s.vaddr && entry < s.vaddr + s.memsz) {
        return Err(ElfError::BadProgramHeaders);
    }
    Ok((entry, segs))
}

/// Map (or find already mapped) the page at `va` in `cr3` and return its frame.
/// Pages shared by two segments get the union of their permissions.
fn page_for(cr3: u64, va: u64, flags: u64) -> Result<u64, ElfError> {
    if let Some(phys) = vmm::translate(cr3, va) {
        let phys = phys & !(PAGE - 1);
        // Already mapped by a previous segment: widen permissions if needed.
        let (p, old) = vmm::unmap_page_entry(cr3, va).ok_or(ElfError::OutOfMemory)?;
        let mut merged = old | flags;
        if old & vmm::FLAG_NX == 0 || flags & vmm::FLAG_NX == 0 {
            merged &= !vmm::FLAG_NX; // executable if either segment is
        }
        if !vmm::map_page(cr3, va, p, merged & !vmm::FLAG_PRESENT) {
            return Err(ElfError::OutOfMemory);
        }
        return Ok(phys);
    }
    let phys = physical::alloc_frame().ok_or(ElfError::OutOfMemory)?;
    if !vmm::map_page(cr3, va, phys, flags) {
        physical::free_frame(phys);
        return Err(ElfError::OutOfMemory);
    }
    Ok(phys)
}

fn load_segment(cr3: u64, image: &[u8], s: &Segment) -> Result<(), ElfError> {
    let mut flags = vmm::FLAG_USER | vmm::FLAG_OWNED;
    if s.flags & PF_W != 0 {
        flags |= vmm::FLAG_WRITABLE;
    }
    if s.flags & PF_X == 0 {
        flags |= vmm::nx_flag();
    }
    let start = s.vaddr & !(PAGE - 1);
    let end = (s.vaddr + s.memsz + PAGE - 1) & !(PAGE - 1);
    let mut va = start;
    while va < end {
        let phys = page_for(cr3, va, flags)?;
        // Copy the part of the file image that falls into this page; the rest stays zero.
        let file_lo = s.vaddr.max(va);
        let file_hi = (s.vaddr + s.filesz).min(va + PAGE);
        if file_lo < file_hi {
            let src = (s.offset + (file_lo - s.vaddr)) as usize;
            let len = (file_hi - file_lo) as usize;
            let dst = (vmm::phys_to_virt(phys) + (file_lo - va)) as *mut u8;
            // SAFETY: dst lies inside the frame just mapped (via HHDM); src range was validated.
            unsafe { core::ptr::copy_nonoverlapping(image[src..src + len].as_ptr(), dst, len) };
        }
        va += PAGE;
    }
    Ok(())
}

/// Build the initial stack. Returns the user RSP (pointing at argc).
fn build_stack(cr3: u64, entry: u64, args: &[&str]) -> Result<u64, ElfError> {
    let bottom = USER_STACK_TOP - USER_STACK_PAGES * PAGE;
    let mut frames = Vec::with_capacity(USER_STACK_PAGES as usize);
    let flags = vmm::FLAG_USER | vmm::FLAG_WRITABLE | vmm::FLAG_OWNED | vmm::nx_flag();
    for i in 0..USER_STACK_PAGES {
        let va = bottom + i * PAGE;
        let phys = physical::alloc_frame().ok_or(ElfError::OutOfMemory)?;
        if !vmm::map_page(cr3, va, phys, flags) {
            physical::free_frame(phys);
            return Err(ElfError::OutOfMemory);
        }
        frames.push(phys);
    }
    // Writes go through the HHDM alias of the (top) stack pages.
    let write = |va: u64, bytes: &[u8]| {
        for (k, &b) in bytes.iter().enumerate() {
            let a = va + k as u64;
            let phys = frames[((a - bottom) / PAGE) as usize];
            // SAFETY: a is inside the freshly mapped stack; the frame is reached via HHDM.
            unsafe { *((vmm::phys_to_virt(phys) + (a % PAGE)) as *mut u8) = b };
        }
    };

    // Strings first, at the very top.
    let mut sp = USER_STACK_TOP;
    let mut argv_ptrs = Vec::with_capacity(args.len());
    for a in args {
        let need = a.len() as u64 + 1;
        if sp - need < bottom + PAGE {
            return Err(ElfError::TooManyArgs);
        }
        sp -= need;
        write(sp, a.as_bytes());
        write(sp + a.len() as u64, &[0]);
        argv_ptrs.push(sp);
    }

    // Then the vector: argc, argv..., NULL, (envp) NULL, auxv pairs. 16-byte aligned at argc.
    let mut words: Vec<u64> = Vec::new();
    words.push(args.len() as u64);
    words.extend_from_slice(&argv_ptrs);
    words.push(0); // argv terminator
    words.push(0); // empty envp
    words.extend_from_slice(&[AT_PAGESZ, PAGE, AT_ENTRY, entry, AT_NULL, 0]);
    sp = (sp - words.len() as u64 * 8) & !0xF;
    if sp < bottom + PAGE {
        return Err(ElfError::TooManyArgs);
    }
    for (i, w) in words.iter().enumerate() {
        write(sp + i as u64 * 8, &w.to_le_bytes());
    }
    Ok(sp)
}

/// Load `image` into a new address space and spawn it as a ring-3 task.
pub fn spawn(
    name: &str,
    image: &[u8],
    args: &[&str],
    capabilities: Vec<crate::core::scheduler::Capability>,
) -> Result<u32, ElfError> {
    let (entry, segs) = parse(image)?;
    let cr3 = vmm::create_address_space().ok_or(ElfError::OutOfMemory)?;

    let result = (|| {
        for s in &segs {
            load_segment(cr3, image, s)?;
        }
        let rsp = build_stack(cr3, entry, args)?;
        vmm::sync_kernel_mappings(cr3);
        crate::core::scheduler::spawn_user_task(
            name,
            crate::core::scheduler::Priority::Normal,
            cr3,
            entry,
            rsp,
            capabilities,
        )
        .ok_or(ElfError::SpawnFailed)
    })();

    if result.is_err() {
        vmm::destroy_address_space(cr3);
    }
    result
}
