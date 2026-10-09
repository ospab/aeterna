/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
ospab boot protocol: the contract between our own loaders and the kernel.

This file is shared verbatim by the kernel (arch/x86_64/boot/ospab.rs) and by the
loaders (boot/uefi, later a BIOS stage2), so it must stay `no_std`, dependency-free
and free of firmware-specific types.

Rules:
- Every address in these structures is PHYSICAL. The kernel turns them into
  pointers through the direct map (HHDM) itself.
- All strings are NUL-terminated UTF-8 in physical memory.
- The structures and everything they point to live in memory the loader marks as
  `BOOTLOADER_RECLAIMABLE` (or `KERNEL_AND_MODULES` for module data).

Machine state at the kernel entry point (ELF `e_entry`):
- 64-bit long mode, CPL0, interrupts disabled (RFLAGS.IF = 0), DF = 0.
- CR0.PG = CR0.PE = 1, CR4.PAE = 1. EFER.LME = 1. The kernel enables EFER.NXE and
  CR0.WP itself, so a loader that uses no NX bits need not set them.
- RDI = physical address of `BootInfo`, RSI = `OSPAB_BOOT_MAGIC`,
  RDX = HHDM offset (the same value as `BootInfo::hhdm_offset`).
  Other general purpose registers carry nothing (the UEFI loader leaves the entry
  address in RAX and zeroes the rest). Limine zeroes RDI/RSI/RDX, which is how
  the kernel tells the two protocols apart.
- RSP = top of a stack of at least 64 KiB, reachable through the HHDM, with a zero
  return address pushed (RSP + 8 is 16-byte aligned).
- GDT/IDT/segment registers: anything usable for 64-bit code; the kernel loads its
  own GDT and IDT before enabling interrupts.

Page tables (deliberately simple so that a small BIOS stage2 can build them):
- HHDM: physical [0, max(4 GiB, end of the highest RAM/ACPI/kernel/bootloader
  region)) mapped at
  `hhdm_offset` (canonical, 1 GiB aligned; the loaders use 0xFFFF_8000_0000_0000),
  read/write. 4 KiB, 2 MiB or 1 GiB pages are all fine.
  The framebuffer must be covered by it too.
- Kernel: every PT_LOAD segment mapped at its linked virtual address onto
  `kernel_phys_base + (vaddr - kernel_virt_base)`; the image is physically contiguous.
  4 KiB pages. Per-segment W/NX bits are recommended but optional.
- Lower half: may contain anything (e.g. the identity map the loader jumped from);
  the kernel clears PML4 entries 0..256 on entry.
*/

/// Value in RSI at the kernel entry point and in `BootInfo::magic` ("OSPABOOT").
pub const OSPAB_BOOT_MAGIC: u64 = 0x544F_4F42_4150_534F;
/// Current protocol version.
pub const OSPAB_BOOT_VERSION: u32 = 1;

/// Firmware the loader ran on (informational).
pub const FIRMWARE_BIOS: u32 = 1;
pub const FIRMWARE_UEFI: u32 = 2;

/// Memory region kinds. The numbering matches the kernel's memory map format
/// (`MEMMAP_*` in arch/x86_64/boot), so regions are passed through unchanged.
pub const MEM_USABLE: u64 = 0;
pub const MEM_RESERVED: u64 = 1;
pub const MEM_ACPI_RECLAIMABLE: u64 = 2;
pub const MEM_ACPI_NVS: u64 = 3;
pub const MEM_BAD_MEMORY: u64 = 4;
pub const MEM_BOOTLOADER_RECLAIMABLE: u64 = 5;
pub const MEM_KERNEL_AND_MODULES: u64 = 6;
pub const MEM_FRAMEBUFFER: u64 = 7;

/// One physical memory region. Regions are sorted by base, do not overlap, and
/// `MEM_USABLE` regions are 4 KiB aligned.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryRegion {
    pub base: u64,
    pub length: u64,
    pub kind: u64,
}

/// Linear framebuffer. `phys_addr == 0` means "no framebuffer".
/// Only direct-colour modes (memory_model = 1, like VBE/GOP) are described.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FramebufferInfo {
    pub phys_addr: u64,
    pub width: u64,
    pub height: u64,
    /// Bytes per scan line.
    pub pitch: u64,
    pub bpp: u16,
    pub memory_model: u8,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
    pub _reserved: [u8; 7],
}

/// A file the loader placed in memory for the kernel (e.g. the kernel image itself
/// for the installer).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Module {
    pub phys_addr: u64,
    pub size: u64,
    /// Physical address of the NUL-terminated path the module was loaded from.
    pub path: u64,
    /// Physical address of the NUL-terminated module command line ("" if none).
    pub cmdline: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u32,
    /// `size_of::<BootInfo>()` as the loader saw it.
    pub size: u32,
    /// `FIRMWARE_BIOS` or `FIRMWARE_UEFI`.
    pub firmware: u32,
    pub _reserved0: u32,
    /// Physical address of a NUL-terminated loader name/version string.
    pub loader_name: u64,
    pub hhdm_offset: u64,
    pub kernel_phys_base: u64,
    pub kernel_virt_base: u64,
    /// Physical address of the ACPI RSDP, 0 if not found.
    pub rsdp: u64,
    /// Physical address of the NUL-terminated kernel command line.
    pub cmdline: u64,
    pub framebuffer: FramebufferInfo,
    /// Physical address of `[MemoryRegion; memmap_count]`.
    pub memmap: u64,
    pub memmap_count: u64,
    /// Physical address of `[Module; module_count]`.
    pub modules: u64,
    pub module_count: u64,
    pub _reserved: [u64; 8],
}
