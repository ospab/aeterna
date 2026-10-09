/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Boot information, independent of the loader that started the kernel.

Two providers:
- `limine`: the Limine protocol (requests in .limine_requests);
- `ospab`:  our own loaders (boot/uefi today, a BIOS stage2 later), which pass a
            `BootInfo` (ospab_proto.rs) in registers.
`early_init` is called first thing from the kernel entry point and picks the
provider; everything below dispatches to it and returns the same types.
*/
pub mod limine;
pub mod ospab;
pub mod ospab_proto;

pub use limine::{
    BootloaderInfoResponse, Framebuffer, LimineFile, MemmapEntry, MemmapIterator, ModuleIterator,
    VideoMode, MEMMAP_ACPI_NVS, MEMMAP_ACPI_RECLAIMABLE, MEMMAP_BAD_MEMORY,
    MEMMAP_BOOTLOADER_RECLAIMABLE, MEMMAP_FRAMEBUFFER, MEMMAP_KERNEL_AND_MODULES, MEMMAP_RESERVED,
    MEMMAP_USABLE,
};

/// Which loader started the kernel.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Loader {
    Limine,
    Ospab,
}

/// Pick the boot provider from the entry registers (RDI, RSI, RDX).
/// Limine zeroes them; an ospab loader passes BootInfo, magic and HHDM.
///
/// # Safety
/// Call once, first thing in the kernel entry point.
pub unsafe fn early_init(arg0: u64, arg1: u64, arg2: u64) -> Loader {
    if ospab::early_init(arg0, arg1, arg2) { Loader::Ospab } else { Loader::Limine }
}

#[inline]
pub fn loader() -> Loader {
    if ospab::active() { Loader::Ospab } else { Loader::Limine }
}

/// Human-readable loader name for logs.
pub fn loader_name() -> &'static str {
    match loader() {
        Loader::Ospab => ospab::loader_name(),
        Loader::Limine => "Limine",
    }
}

/// True if the boot protocol handshake succeeded (Limine base revision accepted;
/// always true for the ospab protocol, which is checked in `early_init`).
pub fn base_revision_supported() -> bool {
    match loader() {
        Loader::Ospab => true,
        Loader::Limine => limine::base_revision_supported(),
    }
}

pub fn get_base_revision_raw() -> u64 {
    limine::get_base_revision_raw()
}

pub fn bootloader_info() -> Option<&'static BootloaderInfoResponse> {
    limine::bootloader_info()
}

pub fn hhdm_offset() -> Option<u64> {
    match loader() {
        Loader::Ospab => ospab::hhdm_offset(),
        Loader::Limine => limine::hhdm_offset(),
    }
}

pub fn framebuffer() -> Option<&'static Framebuffer> {
    match loader() {
        Loader::Ospab => ospab::framebuffer(),
        Loader::Limine => limine::framebuffer(),
    }
}

pub fn memory_map() -> Option<MemmapIterator> {
    match loader() {
        Loader::Ospab => ospab::memory_map(),
        Loader::Limine => limine::memory_map(),
    }
}

pub fn modules() -> Option<ModuleIterator> {
    match loader() {
        Loader::Ospab => ospab::modules(),
        Loader::Limine => limine::modules(),
    }
}

pub fn get_module(index: usize) -> Option<&'static LimineFile> {
    match loader() {
        Loader::Ospab => ospab::get_module(index),
        Loader::Limine => limine::get_module(index),
    }
}

pub fn module_count() -> usize {
    match loader() {
        Loader::Ospab => ospab::module_count(),
        Loader::Limine => limine::module_count(),
    }
}

/// RSDP as a pointer through the HHDM.
pub fn rsdp_address() -> Option<*const u8> {
    match loader() {
        Loader::Ospab => ospab::rsdp_address(),
        Loader::Limine => limine::rsdp_address(),
    }
}

pub fn kernel_cmdline() -> &'static str {
    match loader() {
        Loader::Ospab => ospab::kernel_cmdline(),
        Loader::Limine => limine::kernel_cmdline(),
    }
}

/// Check if "key=VALUE" or bare "key" is present in the kernel cmdline.
pub fn cmdline_has(key: &str) -> bool {
    for tok in kernel_cmdline().split_whitespace() {
        if tok == key { return true; }
        let kb = key.as_bytes();
        let tb = tok.as_bytes();
        if tb.len() > kb.len() && &tb[..kb.len()] == kb && tb[kb.len()] == b'=' {
            return true;
        }
    }
    false
}

/// Get value for key= in the kernel cmdline. Returns "" if not found.
pub fn cmdline_get(key: &str) -> &'static str {
    for tok in kernel_cmdline().split_whitespace() {
        if tok.starts_with(key) && tok.as_bytes().get(key.len()) == Some(&b'=') {
            return &tok[key.len() + 1..];
        }
    }
    ""
}

pub fn kernel_phys_base() -> u64 {
    match loader() {
        Loader::Ospab => ospab::kernel_phys_base(),
        Loader::Limine => limine::kernel_phys_base(),
    }
}

pub fn kernel_virt_base() -> u64 {
    match loader() {
        Loader::Ospab => ospab::kernel_virt_base(),
        Loader::Limine => limine::kernel_virt_base(),
    }
}

/// `phys = virt - kernel_virt_offset()` for addresses inside the kernel image.
#[inline]
pub fn kernel_virt_offset() -> u64 {
    kernel_virt_base() - kernel_phys_base()
}
