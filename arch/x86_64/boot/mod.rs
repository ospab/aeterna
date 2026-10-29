/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Boot information, independent of the firmware the machine runs.

The kernel is started by ospab-boot only (boot/bios for BIOS, boot/uefi for UEFI), which
passes a `BootInfo` (ospab_proto.rs) in registers. `early_init` is called first thing from
the kernel entry point and copies it into statics (ospab.rs); everything below returns it in
the shapes of types.rs.
*/
pub mod ospab;
pub mod ospab_proto;
pub mod types;

pub use types::{
    BootFile, Framebuffer, MemmapEntry, MemmapIterator, ModuleIterator, VideoMode,
    MEMMAP_ACPI_NVS, MEMMAP_ACPI_RECLAIMABLE, MEMMAP_BAD_MEMORY, MEMMAP_BOOTLOADER_RECLAIMABLE,
    MEMMAP_FRAMEBUFFER, MEMMAP_KERNEL_AND_MODULES, MEMMAP_RESERVED, MEMMAP_USABLE,
};

/// Take over the `BootInfo` of the loader (RDI, RSI, RDX at the kernel entry).
/// Halts with a message on COM1 when the kernel was not started by ospab-boot.
///
/// # Safety
/// Call once, first thing in the kernel entry point.
pub unsafe fn early_init(arg0: u64, arg1: u64, arg2: u64) {
    if ospab::early_init(arg0, arg1, arg2) {
        return;
    }
    for b in b"ospab: no valid BootInfo. This kernel must be started by ospab-boot (BIOS or UEFI).\r\n" {
        core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") *b, options(nomem, nostack));
    }
    loop {
        core::arch::asm!("cli; hlt", options(nomem, nostack));
    }
}

/// Human-readable loader name for logs.
pub fn loader_name() -> &'static str {
    ospab::loader_name()
}

/// True once the BootInfo handshake succeeded (checked in `early_init`; kept for the boot log).
pub fn base_revision_supported() -> bool {
    ospab::active()
}

/// Firmware the loader ran on: `ospab_proto::FIRMWARE_BIOS` or `FIRMWARE_UEFI`.
pub fn firmware() -> u32 {
    ospab::firmware()
}

/// True when the loader ran on a BIOS (the installer then sets up the BIOS boot code).
pub fn is_bios() -> bool {
    firmware() == ospab_proto::FIRMWARE_BIOS
}

pub fn hhdm_offset() -> Option<u64> {
    ospab::hhdm_offset()
}

pub fn framebuffer() -> Option<&'static Framebuffer> {
    ospab::framebuffer()
}

pub fn memory_map() -> Option<MemmapIterator> {
    ospab::memory_map()
}

pub fn modules() -> Option<ModuleIterator> {
    ospab::modules()
}

pub fn get_module(index: usize) -> Option<&'static BootFile> {
    ospab::get_module(index)
}

pub fn module_count() -> usize {
    ospab::module_count()
}

/// RSDP as a pointer through the HHDM.
pub fn rsdp_address() -> Option<*const u8> {
    ospab::rsdp_address()
}

pub fn kernel_cmdline() -> &'static str {
    ospab::kernel_cmdline()
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
    ospab::kernel_phys_base()
}

pub fn kernel_virt_base() -> u64 {
    ospab::kernel_virt_base()
}

/// `phys = virt - kernel_virt_offset()` for addresses inside the kernel image.
#[inline]
pub fn kernel_virt_offset() -> u64 {
    kernel_virt_base() - kernel_phys_base()
}
