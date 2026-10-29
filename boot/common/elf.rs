/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Kernel ELF loading shared by the UEFI and BIOS front-ends.
*/
use core::ptr;

use crate::mem::{PageKind, PAGE};
use crate::paging::{PageTables, NX, W};

pub struct KernelImage {
    pub entry: u64,
    pub phys_base: u64,
    pub virt_base: u64,
}

fn rd16(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }
fn rd32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn rd64(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

/// Copy the PT_LOAD segments into one physically contiguous block and map them
/// at their linked addresses.
pub fn load_elf(file: &[u8], pt: &mut PageTables) -> Result<KernelImage, &'static str> {
    if file.len() < 64 || &file[0..4] != b"\x7fELF" || file[4] != 2 || file[5] != 1 {
        return Err("not an ELF64 little-endian file");
    }
    if rd16(file, 18) != 0x3E {
        return Err("not an x86_64 ELF");
    }
    let entry = rd64(file, 24);
    let phoff = rd64(file, 32) as usize;
    let phentsize = rd16(file, 54) as usize;
    let phnum = rd16(file, 56) as usize;
    if phoff + phnum * phentsize > file.len() {
        return Err("truncated program headers");
    }
    let phdrs = || (0..phnum).map(|i| &file[phoff + i * phentsize..]).filter(|p| rd32(p, 0) == 1);

    let mut lo = u64::MAX;
    let mut hi = 0u64;
    for p in phdrs() {
        let (vaddr, memsz) = (rd64(p, 16), rd64(p, 40));
        lo = lo.min(vaddr & !(PAGE - 1));
        hi = hi.max((vaddr + memsz + PAGE - 1) & !(PAGE - 1));
    }
    if lo >= hi || lo < 0xFFFF_8000_0000_0000 {
        return Err("no higher-half PT_LOAD segments");
    }
    let phys = crate::plat::alloc_pages(((hi - lo) / PAGE) as usize, PageKind::Kernel);

    for p in phdrs() {
        let flags = rd32(p, 4);
        let (off, vaddr, filesz, memsz) = (rd64(p, 8) as usize, rd64(p, 16), rd64(p, 32) as usize, rd64(p, 40));
        if off + filesz > file.len() || filesz as u64 > memsz {
            return Err("segment outside the file");
        }
        unsafe {
            ptr::copy_nonoverlapping(file.as_ptr().add(off), (phys + (vaddr - lo)) as *mut u8, filesz);
        }
        let mut pte = 0;
        if flags & 2 != 0 { pte |= W; }
        if flags & 1 == 0 { pte |= NX; }
        let mut va = vaddr & !(PAGE - 1);
        while va < vaddr + memsz {
            pt.map_4k(va, phys + (va - lo), pte);
            va += PAGE;
        }
    }
    Ok(KernelImage { entry, phys_base: phys, virt_base: lo })
}
