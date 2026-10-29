/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Memory helpers shared by the UEFI and BIOS front-ends.

Each front-end provides `crate::plat::alloc_pages(pages, kind) -> u64`: zeroed, 4 KiB
aligned, physically addressable memory that stays valid for the kernel
(`PageKind::Reclaim`: bootloader data the kernel frees later; `PageKind::Kernel`: kernel
image and modules).
*/
use core::ptr;

pub const PAGE: u64 = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PageKind {
    /// Kernel image and modules (MEM_KERNEL_AND_MODULES).
    Kernel,
    /// Loader data the kernel may free once it has copied what it needs.
    Reclaim,
}

/// Copies strings into reclaimable pages and returns their physical addresses.
pub struct StrArena {
    base: u64,
    used: u64,
    cap: u64,
}

impl StrArena {
    pub fn new() -> Self {
        StrArena { base: crate::plat::alloc_pages(2, PageKind::Reclaim), used: 0, cap: 2 * PAGE }
    }

    pub fn push(&mut self, s: &str) -> u64 {
        let len = s.len() as u64 + 1;
        if self.used + len > self.cap {
            panic!("string arena full");
        }
        let at = self.base + self.used;
        unsafe {
            ptr::copy_nonoverlapping(s.as_ptr(), at as *mut u8, s.len());
            *((at + s.len() as u64) as *mut u8) = 0;
        }
        self.used += len;
        at
    }
}
