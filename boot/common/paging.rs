/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Page tables for the kernel (see ospab_proto.rs for the contract):
HHDM with 2 MiB pages, the kernel image with 4 KiB pages and per-segment
permissions, plus an identity map of the hand-off trampoline (the kernel drops
the lower half on entry). Tables live in OSPAB_RECLAIM_MEMORY pages, which the
firmware identity-maps, so they are written through their physical address.
*/
use crate::mem::{PageKind, PAGE};

pub const P: u64 = 1 << 0;
pub const W: u64 = 1 << 1;
pub const PS: u64 = 1 << 7;
pub const NX: u64 = 1 << 63;
const ADDR: u64 = 0x000F_FFFF_FFFF_F000;

pub struct PageTables {
    pub pml4: u64,
}

fn new_table() -> u64 {
    crate::plat::alloc_pages(1, PageKind::Reclaim)
}

unsafe fn entry(table: u64, index: u64) -> *mut u64 {
    (table as *mut u64).add(index as usize)
}

impl PageTables {
    pub fn new() -> Self {
        PageTables { pml4: new_table() }
    }

    /// Walk to the table at `level` (3 = PDPT, 2 = PD, 1 = PT) for `virt`,
    /// creating intermediate tables. Upper levels are always P|W (no NX) so the
    /// leaf decides.
    unsafe fn table_for(&mut self, virt: u64, level: u32) -> u64 {
        let mut table = self.pml4;
        let mut lvl = 4;
        while lvl > level {
            let idx = (virt >> (12 + 9 * (lvl - 1))) & 0x1FF;
            let e = entry(table, idx);
            if *e & P == 0 {
                *e = new_table() | P | W;
            }
            assert!(*e & PS == 0, "huge page in the way");
            table = *e & ADDR;
            lvl -= 1;
        }
        table
    }

    /// Map one 4 KiB page. An existing mapping of the same frame gets the more
    /// permissive flags (segments may share a page).
    pub fn map_4k(&mut self, virt: u64, phys: u64, flags: u64) {
        unsafe {
            let pt = self.table_for(virt, 1);
            let e = entry(pt, (virt >> 12) & 0x1FF);
            let mut f = flags | P;
            if *e & P != 0 {
                f |= *e & W;
                if *e & NX == 0 {
                    f &= !NX;
                }
            }
            *e = (phys & ADDR) | f;
        }
    }

    /// Map [phys, phys+len) at virt with 2 MiB pages (both 2 MiB aligned).
    pub fn map_2m_range(&mut self, virt: u64, phys: u64, len: u64, flags: u64) {
        let mut off = 0;
        while off < len {
            unsafe {
                let pd = self.table_for(virt + off, 2);
                let e = entry(pd, ((virt + off) >> 21) & 0x1FF);
                if *e & P == 0 {
                    *e = ((phys + off) & ADDR) | flags | P | PS;
                }
            }
            off += 2 << 20;
        }
    }

    /// Identity-map the pages covering [addr, addr+len).
    pub fn identity(&mut self, addr: u64, len: u64) {
        let start = addr & !(PAGE - 1);
        let end = (addr + len + PAGE - 1) & !(PAGE - 1);
        let mut a = start;
        while a < end {
            self.map_4k(a, a, W);
            a += PAGE;
        }
    }
}
