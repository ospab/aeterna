/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
ospab boot protocol: the loaders of boot/uefi and boot/bios.

The loader hands over a `BootInfo` with physical addresses only (see ospab_proto.rs).
`early_init` copies it into kernel statics (types.rs) so the rest of the kernel does not
care whether the BIOS or the UEFI loader started it.
*/
use core::ptr;

use super::types::{BootFile, Framebuffer, MemmapEntry, MemmapIterator, ModuleIterator};
use super::ospab_proto::*;

const MAX_MEMMAP: usize = 512;
const MAX_MODULES: usize = 16;

static mut ACTIVE: bool = false;
static mut HHDM: u64 = 0;
static mut KERNEL_PHYS: u64 = 0;
static mut KERNEL_VIRT: u64 = 0;
static mut RSDP: u64 = 0;
static mut FIRMWARE: u32 = 0;
static mut CMDLINE: &str = "";
static mut LOADER_NAME: &str = "";

static mut FB_PRESENT: bool = false;
static mut FB: Framebuffer = Framebuffer {
    address: ptr::null_mut(),
    width: 0,
    height: 0,
    pitch: 0,
    bpp: 0,
    memory_model: 0,
    red_mask_size: 0,
    red_mask_shift: 0,
    green_mask_size: 0,
    green_mask_shift: 0,
    blue_mask_size: 0,
    blue_mask_shift: 0,
    unused: [0; 7],
    edid_size: 0,
    edid: ptr::null_mut(),
    mode_count: 0,
    modes: ptr::null_mut(),
};

static mut MEMMAP: [MemmapEntry; MAX_MEMMAP] =
    [const { MemmapEntry { base: 0, length: 0, typ: 0 } }; MAX_MEMMAP];
static mut MEMMAP_PTRS: [*mut MemmapEntry; MAX_MEMMAP] = [ptr::null_mut(); MAX_MEMMAP];
static mut MEMMAP_COUNT: usize = 0;

static mut MODULES: [BootFile; MAX_MODULES] = [const {
    BootFile { address: ptr::null_mut(), size: 0, path: ptr::null(), cmdline: ptr::null() }
}; MAX_MODULES];
static mut MODULE_PTRS: [*mut BootFile; MAX_MODULES] = [ptr::null_mut(); MAX_MODULES];
static mut MODULE_COUNT: usize = 0;

/// Called first thing from the kernel entry point with the entry registers
/// (RDI, RSI, RDX). Returns true if an ospab loader started the kernel.
/// Runs before serial/GDT/IDT: no output, no allocation.
///
/// # Safety
/// Must be called once, on the boot CPU, before anything reads boot data.
pub unsafe fn early_init(info_phys: u64, magic: u64, hhdm: u64) -> bool {
    if magic != OSPAB_BOOT_MAGIC || info_phys == 0 || hhdm == 0 {
        return false; // not started by an ospab loader
    }
    let info = &*((info_phys + hhdm) as *const BootInfo);
    if info.magic != OSPAB_BOOT_MAGIC || info.version != OSPAB_BOOT_VERSION {
        return false;
    }

    enable_nx_wp();
    drop_lower_half(hhdm);

    HHDM = info.hhdm_offset;
    KERNEL_PHYS = info.kernel_phys_base;
    KERNEL_VIRT = info.kernel_virt_base;
    RSDP = if info.rsdp != 0 { info.rsdp + hhdm } else { 0 };
    FIRMWARE = info.firmware;
    CMDLINE = c_str(info.cmdline, hhdm);
    LOADER_NAME = c_str(info.loader_name, hhdm);

    let fb = &info.framebuffer;
    if fb.phys_addr != 0 {
        FB.address = (fb.phys_addr + hhdm) as *mut u8;
        FB.width = fb.width;
        FB.height = fb.height;
        FB.pitch = fb.pitch;
        FB.bpp = fb.bpp;
        FB.memory_model = fb.memory_model;
        FB.red_mask_size = fb.red_mask_size;
        FB.red_mask_shift = fb.red_mask_shift;
        FB.green_mask_size = fb.green_mask_size;
        FB.green_mask_shift = fb.green_mask_shift;
        FB.blue_mask_size = fb.blue_mask_size;
        FB.blue_mask_shift = fb.blue_mask_shift;
        FB_PRESENT = true;
    }

    let regions = (info.memmap + hhdm) as *const MemoryRegion;
    let n = (info.memmap_count as usize).min(MAX_MEMMAP);
    for i in 0..n {
        let r = &*regions.add(i);
        MEMMAP[i] = MemmapEntry { base: r.base, length: r.length, typ: r.kind };
        MEMMAP_PTRS[i] = ptr::addr_of_mut!(MEMMAP[i]);
    }
    MEMMAP_COUNT = n;

    let mods = (info.modules + hhdm) as *const Module;
    let n = (info.module_count as usize).min(MAX_MODULES);
    for i in 0..n {
        let m = &*mods.add(i);
        let f = &mut *ptr::addr_of_mut!(MODULES[i]);
        f.address = (m.phys_addr + hhdm) as *mut u8;
        f.size = m.size;
        f.path = c_ptr(m.path, hhdm);
        f.cmdline = c_ptr(m.cmdline, hhdm);
        MODULE_PTRS[i] = f;
    }
    MODULE_COUNT = n;

    ACTIVE = true;
    true
}

/// EFER.NXE (the kernel maps pages with NX) and CR0.WP.
unsafe fn enable_nx_wp() {
    let (lo, hi): (u32, u32);
    core::arch::asm!("rdmsr", in("ecx") 0xC000_0080u32, out("eax") lo, out("edx") hi,
                     options(nomem, nostack));
    core::arch::asm!("wrmsr", in("ecx") 0xC000_0080u32, in("eax") lo | (1 << 11), in("edx") hi,
                     options(nomem, nostack));
    let cr0: u64;
    core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
    core::arch::asm!("mov cr0, {}", in(reg) cr0 | (1 << 16), options(nostack));
}

/// Remove whatever the loader left in the lower half (it jumped from an identity map).
unsafe fn drop_lower_half(hhdm: u64) {
    let cr3: u64;
    core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    let pml4 = ((cr3 & 0x000F_FFFF_FFFF_F000) + hhdm) as *mut u64;
    for i in 0..256 {
        pml4.add(i).write_volatile(0);
    }
    core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack));
}

unsafe fn c_ptr(phys: u64, hhdm: u64) -> *const core::ffi::c_char {
    if phys == 0 { ptr::null() } else { (phys + hhdm) as *const core::ffi::c_char }
}

unsafe fn c_str(phys: u64, hhdm: u64) -> &'static str {
    if phys == 0 {
        return "";
    }
    let p = (phys + hhdm) as *const u8;
    let mut len = 0usize;
    while *p.add(len) != 0 && len < 4096 {
        len += 1;
    }
    core::str::from_utf8(core::slice::from_raw_parts(p, len)).unwrap_or("")
}

// ─── Accessors ──────────────────────────────────────────────────────────────────────────────────────

pub fn active() -> bool { unsafe { ACTIVE } }
pub fn hhdm_offset() -> Option<u64> { unsafe { Some(HHDM) } }
pub fn kernel_phys_base() -> u64 { unsafe { KERNEL_PHYS } }
pub fn kernel_virt_base() -> u64 { unsafe { KERNEL_VIRT } }
pub fn kernel_cmdline() -> &'static str { unsafe { CMDLINE } }
pub fn loader_name() -> &'static str { unsafe { LOADER_NAME } }
pub fn firmware() -> u32 { unsafe { FIRMWARE } }

pub fn rsdp_address() -> Option<*const u8> {
    unsafe { if RSDP == 0 { None } else { Some(RSDP as *const u8) } }
}

pub fn framebuffer() -> Option<&'static Framebuffer> {
    unsafe { if FB_PRESENT { Some(&*ptr::addr_of!(FB)) } else { None } }
}

pub fn memory_map() -> Option<MemmapIterator> {
    unsafe {
        if MEMMAP_COUNT == 0 { return None; }
        Some(MemmapIterator::from_raw(ptr::addr_of_mut!(MEMMAP_PTRS) as *mut *mut MemmapEntry,
                                      MEMMAP_COUNT))
    }
}

pub fn modules() -> Option<ModuleIterator> {
    unsafe {
        if MODULE_COUNT == 0 { return None; }
        Some(ModuleIterator::from_raw(ptr::addr_of_mut!(MODULE_PTRS) as *mut *mut BootFile,
                                      MODULE_COUNT))
    }
}

pub fn module_count() -> usize { unsafe { MODULE_COUNT } }

pub fn get_module(index: usize) -> Option<&'static BootFile> {
    unsafe {
        if index >= MODULE_COUNT { None } else { Some(&*ptr::addr_of!(MODULES[index])) }
    }
}
