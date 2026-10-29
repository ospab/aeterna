/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Boot data in the shapes the rest of the kernel uses: framebuffer, memory map entries and
boot modules. `ospab.rs` fills them from the loader's `BootInfo` (ospab_proto.rs).
*/
use core::ffi::c_char;

#[repr(C)]
pub struct Framebuffer {
    pub address: *mut u8,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bpp: u16,
    pub memory_model: u8,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
    pub unused: [u8; 7],
    /// EDID and mode list are not passed by the loaders (always empty).
    pub edid_size: u64,
    pub edid: *mut u8,
    pub mode_count: u64,
    pub modes: *mut *mut VideoMode,
}

#[repr(C)]
pub struct VideoMode {
    pub pitch: u64,
    pub width: u64,
    pub height: u64,
    pub bpp: u16,
    pub memory_model: u8,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
}

// Memory map kinds; the numbering is the one of `MEM_*` in ospab_proto.rs.
pub const MEMMAP_USABLE: u64 = 0;
pub const MEMMAP_RESERVED: u64 = 1;
pub const MEMMAP_ACPI_RECLAIMABLE: u64 = 2;
pub const MEMMAP_ACPI_NVS: u64 = 3;
pub const MEMMAP_BAD_MEMORY: u64 = 4;
pub const MEMMAP_BOOTLOADER_RECLAIMABLE: u64 = 5;
pub const MEMMAP_KERNEL_AND_MODULES: u64 = 6;
pub const MEMMAP_FRAMEBUFFER: u64 = 7;

#[repr(C)]
pub struct MemmapEntry {
    pub base: u64,
    pub length: u64,
    pub typ: u64,
}

pub struct MemmapIterator {
    entries: *mut *mut MemmapEntry,
    count: usize,
    index: usize,
}

impl MemmapIterator {
    pub(super) fn from_raw(entries: *mut *mut MemmapEntry, count: usize) -> Self {
        MemmapIterator { entries, count, index: 0 }
    }
}

impl Iterator for MemmapIterator {
    type Item = &'static MemmapEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        unsafe {
            let p = *self.entries.add(self.index);
            self.index += 1;
            if p.is_null() { None } else { Some(&*p) }
        }
    }
}

/// A file the loader placed in memory for the kernel (a `module` line of the entry).
#[repr(C)]
pub struct BootFile {
    pub address: *mut u8,
    pub size: u64,
    /// NUL-terminated path the file was loaded from.
    pub path: *const c_char,
    /// NUL-terminated module command line ("" if none).
    pub cmdline: *const c_char,
}

pub struct ModuleIterator {
    modules: *mut *mut BootFile,
    count: usize,
    index: usize,
}

impl ModuleIterator {
    pub(super) fn from_raw(modules: *mut *mut BootFile, count: usize) -> Self {
        ModuleIterator { modules, count, index: 0 }
    }
}

impl Iterator for ModuleIterator {
    type Item = &'static BootFile;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        unsafe {
            let p = *self.modules.add(self.index);
            self.index += 1;
            if p.is_null() { None } else { Some(&*p) }
        }
    }
}
