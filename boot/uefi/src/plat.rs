/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Platform hooks for the shared code in boot/common (UEFI: firmware page allocator).
*/
use crate::efi::{OSPAB_KERNEL_MEMORY, OSPAB_RECLAIM_MEMORY};
use crate::mem::PageKind;

pub fn alloc_pages(pages: usize, kind: PageKind) -> u64 {
    crate::console::alloc_pages(
        pages,
        match kind {
            PageKind::Kernel => OSPAB_KERNEL_MEMORY,
            PageKind::Reclaim => OSPAB_RECLAIM_MEMORY,
        },
    )
}
