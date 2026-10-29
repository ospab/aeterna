/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
ospab-boot, BIOS front-end (stage2).

Runs in 64-bit mode on an identity map of the first 4 GiB; BIOS services are called
through the real-mode thunk (rm.S). Finds the boot volume (FAT32 or ISO9660 on the boot
drive), reads and checks ospab.cfg, shows the menu on VGA text and runs the chosen entry:
boot a kernel (load the ELF and modules, set a VBE mode, build page tables, jump with a
`BootInfo`, see arch/x86_64/boot/ospab_proto.rs), memory test, reboot or power off.
The firmware-settings and EFI-chainload entries do not exist on BIOS and are dropped.
Documentation: docs/en/boot.md.
*/
#![no_std]
#![no_main]
#![allow(static_mut_refs, dead_code)]

extern crate alloc;

#[macro_use]
mod hw;
mod disk;
mod memtest_ui;
mod pmem;
mod rm;
mod vbe;
#[allow(dead_code)]
#[path = "../../../arch/x86_64/boot/ospab_proto.rs"]
mod proto;
#[path = "../../common/config.rs"]
mod config;
#[path = "../../common/elf.rs"]
mod elf;
#[path = "../../common/handoff.rs"]
mod handoff;
#[path = "../../common/mem.rs"]
mod mem;
#[path = "../../common/memtest.rs"]
mod memtest;
#[path = "../../common/menu.rs"]
mod menu;
#[path = "../../common/modesel.rs"]
mod modesel;
#[path = "../../common/paging.rs"]
mod paging;

/// Page allocator hook for boot/common.
mod plat {
    pub use crate::pmem::alloc_pages;
}

use alloc::string::String;
use alloc::vec::Vec;

use config::{Config, EntryType};
use disk::{Loaded, Volume};
use elf::load_elf;
use handoff::enter_kernel;
use mem::{PageKind, StrArena, PAGE};
use paging::{PageTables, NX, W};
use proto::*;

const LOADER_NAME: &str = "ospab-boot 0.2 (BIOS)";
const CONFIG_PATH: &str = "/boot/ospab.cfg";
const DEFAULT_KERNEL: &str = "/boot/KERNEL";
const HHDM_OFFSET: u64 = 0xFFFF_8000_0000_0000;
const KERNEL_STACK: u64 = 128 * 1024;
const MAX_REGIONS: usize = 512;
const GIB: u64 = 1 << 30;
const MIB2: u64 = 2 << 20;

fn fail(msg: &str) -> ! {
    println!("\nospab-boot: {}", msg);
    println!("System halted.");
    hw::halt()
}

/// Boot the kernel of an `ospab` entry. Does not return.
fn boot_kernel(vol: &mut Volume, cfg: &Config, entry: &config::Entry, cmdline: &str) -> ! {
    println!("Booting '{}' from {} volume", entry.title, vol.kind());

    // The kernel file is also a module when the entry lists it (installer).
    let kernel_is_module = entry.modules.iter().any(|(p, _)| *p == entry.kernel);
    let kernel_file = vol
        .load(&entry.kernel, if kernel_is_module { PageKind::Kernel } else { PageKind::Reclaim })
        .unwrap_or_else(|| fail(&alloc::format!("cannot read the kernel file {}", entry.kernel)));
    println!("Kernel: {} ({} KiB)", entry.kernel, kernel_file.size / 1024);

    let mut pt = PageTables::new();
    let kernel = load_elf(
        unsafe { core::slice::from_raw_parts(kernel_file.addr as *const u8, kernel_file.size as usize) },
        &mut pt,
    )
    .unwrap_or_else(|e| fail(e));

    let mut loaded: Vec<(Loaded, &str, &str)> = Vec::new();
    for (path, args) in &entry.modules {
        let file = if *path == entry.kernel { Some(kernel_file) } else { vol.load(path, PageKind::Kernel) };
        match file {
            Some(f) => loaded.push((f, path.as_str(), args.as_str())),
            None => println!("Module {} not found, skipped", path),
        }
    }

    let rsdp = hw::find_rsdp();

    // Boot info and everything it points to. Allocate it all before the final memory map.
    let mut strings = StrArena::new();
    let info_phys = plat::alloc_pages(1, PageKind::Reclaim);
    let mods_phys = plat::alloc_pages(1, PageKind::Reclaim);
    let mods = unsafe { core::slice::from_raw_parts_mut(mods_phys as *mut Module, loaded.len().min(PAGE as usize / 32)) };
    for (m, (f, path, args)) in mods.iter_mut().zip(loaded.iter()) {
        *m = Module { phys_addr: f.addr, size: f.size, path: strings.push(path), cmdline: strings.push(args) };
    }
    let regions_pages = (MAX_REGIONS * core::mem::size_of::<MemoryRegion>()).div_ceil(PAGE as usize);
    let regions_phys = plat::alloc_pages(regions_pages, PageKind::Reclaim);
    let stack_phys = plat::alloc_pages((KERNEL_STACK / PAGE) as usize, PageKind::Reclaim);
    let name_phys = strings.push(LOADER_NAME);
    let cmdline_phys = strings.push(cmdline);

    // HHDM over all RAM-like memory (at least 4 GiB).
    let top = pmem::ram_top().max(4 * GIB).next_multiple_of(GIB);
    pt.map_2m_range(HHDM_OFFSET, 0, top, W | NX);

    // The video mode is the last visible change: the text console is gone afterwards.
    println!("Kernel entry {:#x}, phys base {:#x}, HHDM up to {} GiB", kernel.entry, kernel.phys_base, top / GIB);
    let fb = vbe::setup(cfg.resolution);
    if fb.phys_addr != 0 {
        let start = fb.phys_addr & !(MIB2 - 1);
        let end = (fb.phys_addr + fb.pitch * fb.height).next_multiple_of(MIB2);
        pt.map_2m_range(HHDM_OFFSET + start, start, end - start, W | NX);
    }
    pt.identity(handoff::ospab_handoff as *const () as u64, 2 * PAGE);

    let info = unsafe { &mut *(info_phys as *mut BootInfo) };
    *info = BootInfo {
        magic: OSPAB_BOOT_MAGIC,
        version: OSPAB_BOOT_VERSION,
        size: core::mem::size_of::<BootInfo>() as u32,
        firmware: FIRMWARE_BIOS,
        _reserved0: 0,
        loader_name: name_phys,
        hhdm_offset: HHDM_OFFSET,
        kernel_phys_base: kernel.phys_base,
        kernel_virt_base: kernel.virt_base,
        rsdp,
        cmdline: cmdline_phys,
        framebuffer: fb,
        memmap: regions_phys,
        memmap_count: 0,
        modules: mods_phys,
        module_count: mods.len() as u64,
        _reserved: [0; 8],
    };
    hw::enable_sse();
    let regions = unsafe { core::slice::from_raw_parts_mut(regions_phys as *mut MemoryRegion, MAX_REGIONS) };
    info.memmap_count = pmem::final_map(regions, &fb) as u64;

    unsafe {
        enter_kernel(
            info_phys,
            OSPAB_BOOT_MAGIC,
            HHDM_OFFSET,
            pt.pml4,
            HHDM_OFFSET + stack_phys + KERNEL_STACK,
            kernel.entry,
        )
    }
}

#[no_mangle]
pub extern "sysv64" fn bios_main(_drive: u32) -> ! {
    pmem::init();
    hw::serial_init();
    hw::init_idt();
    hw::calibrate_tsc();
    hw::vga_clear(0x07);
    println!("{}", LOADER_NAME);
    pmem::read_map();
    println!("Memory: {} MiB usable", pmem::usable_total() >> 20);
    let power_ok = hw::acpi_init();

    let drive = rm::boot_drive();
    println!("Boot drive: {:#04x}", drive);
    let mut vol: Volume = disk::find_volume(drive, &[CONFIG_PATH, DEFAULT_KERNEL])
        .unwrap_or_else(|| fail("no volume with ospab.cfg or /boot/KERNEL on the boot drive"));

    let mut source = String::from("built-in defaults (no ospab.cfg found)");
    let mut parsed = None;
    if let Some(text) = vol.read_small(CONFIG_PATH) {
        source = String::from(CONFIG_PATH);
        parsed = Some(config::parse(&String::from_utf8_lossy(&text)));
    }
    let config::Parsed { mut cfg, errors } = parsed.unwrap_or_else(|| config::Parsed { cfg: config::builtin(None), errors: Vec::new() });
    if cfg.entries.is_empty() {
        cfg = config::builtin(None);
    }
    // Entries that cannot work on BIOS are dropped.
    cfg.retain_entries(|e| match e.typ {
        EntryType::Firmware | EntryType::EfiChainload => false,
        EntryType::Poweroff => power_ok,
        _ => true,
    });
    if cfg.entries.is_empty() {
        fail("ospab.cfg has no entry that works on BIOS");
    }
    hw::set_serial(cfg.serial);
    for e in &errors {
        println!("ospab.cfg:{}: {}", e.line, e.msg);
    }

    let pal = menu::Palette::new(cfg.theme);
    let mut tm = hw::BiosTerm::new();

    let mut selected = cfg.default.min(cfg.entries.len() - 1);
    // One visible entry and no errors: no menu. timeout = 0: no menu unless a key is waiting.
    let visible = cfg.entries.iter().filter(|e| !e.hidden).count();
    let mut skip_menu = errors.is_empty()
        && (visible <= 1 || (cfg.timeout == Some(0) && menu::Term::poll_key(&mut tm).is_none()));

    loop {
        let (index, cmdline) = if skip_menu {
            (selected, cfg.entries[selected].cmdline.clone())
        } else {
            let info = menu::MenuInfo { loader: LOADER_NAME, source: &source, errors: &errors, selected };
            let c = menu::run(&mut tm, &pal, &cfg, &info);
            (c.index, c.cmdline)
        };
        skip_menu = false;
        let entry = &cfg.entries[index];
        match entry.typ {
            EntryType::Ospab => {
                menu::Term::clear(&mut tm, 0x07);
                menu::Term::set_cursor(&mut tm, 0, 0, true);
                boot_kernel(&mut vol, &cfg, entry, &cmdline);
            }
            EntryType::Memtest => memtest_ui::run(&mut tm, &pal, &cfg, &cmdline),
            EntryType::Reboot => hw::reboot(),
            EntryType::Poweroff => {
                hw::power_off();
                menu::message(&mut tm, &pal, &entry.title, &[String::from("The firmware did not power off.")]);
            }
            EntryType::Firmware | EntryType::EfiChainload => {}
        }
        selected = index;
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("\nospab-boot panic: {}", info);
    hw::halt()
}
