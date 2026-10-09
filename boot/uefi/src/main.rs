/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
ospab.os UEFI loader.

Reads /boot/ospab.cfg (optional), loads the kernel ELF and its modules from the
boot volume (FAT via the firmware, or ISO9660 directly), sets up GOP, builds page
tables (HHDM + higher-half kernel), collects the memory map, leaves boot services
and jumps to the kernel with a `BootInfo` (arch/x86_64/boot/ospab_proto.rs).
*/
#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod console;
mod efi;
mod fs;
mod paging;
#[allow(dead_code)]
#[path = "../../../arch/x86_64/boot/ospab_proto.rs"]
mod proto;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr;

use console::{alloc_pages, bs, st, PAGE};
use efi::*;
use fs::{Loaded, Volume};
use paging::{PageTables, NX, W};
use proto::*;

const LOADER_NAME: &str = "ospab-boot 0.1 (UEFI)";
const CONFIG_PATH: &str = "/boot/ospab.cfg";
const DEFAULT_KERNEL: &str = "/boot/KERNEL";
/// Same offset Limine uses without KASLR, so kernel logs stay comparable.
const HHDM_OFFSET: u64 = 0xFFFF_8000_0000_0000;
const KERNEL_STACK: u64 = 128 * 1024;
const MAX_REGIONS: usize = 512;
const GIB: u64 = 1 << 30;
const MIB2: u64 = 2 << 20;

// ─── Configuration ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Resolution {
    Keep,
    /// The display's preferred mode (EDID), else the firmware's current mode.
    Auto,
    Max,
    Exact(u32, u32),
}

struct Entry {
    title: String,
    kernel: String,
    cmdline: String,
    modules: Vec<(String, String)>,
}

struct Config {
    timeout: u32,
    default: usize,
    resolution: Resolution,
    entries: Vec<Entry>,
}

/// Format (one `key=value` per line, `#` comments, indentation ignored):
///   timeout=3            seconds the menu waits (0 = boot the default at once)
///   default=1            1-based entry number
///   resolution=auto      auto (EDID preferred) | max | keep | 1280x800
///   entry=Title          starts an entry; the keys below belong to it
///   kernel=/boot/KERNEL
///   cmdline=mode=live
///   module=/boot/KERNEL kernel     path, then the module command line
fn parse_config(text: &str) -> Config {
    let mut cfg = Config { timeout: 3, default: 0, resolution: Resolution::Auto, entries: Vec::new() };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "timeout" => cfg.timeout = value.parse().unwrap_or(3),
            "default" => cfg.default = value.parse::<usize>().unwrap_or(1).saturating_sub(1),
            "resolution" => {
                cfg.resolution = match value {
                    "auto" => Resolution::Auto,
                    "max" => Resolution::Max,
                    "keep" => Resolution::Keep,
                    v => match v.split_once('x') {
                        Some((w, h)) => Resolution::Exact(w.parse().unwrap_or(0), h.parse().unwrap_or(0)),
                        None => Resolution::Auto,
                    },
                }
            }
            "entry" => cfg.entries.push(Entry {
                title: value.to_string(),
                kernel: DEFAULT_KERNEL.to_string(),
                cmdline: String::new(),
                modules: Vec::new(),
            }),
            _ => {
                let Some(e) = cfg.entries.last_mut() else { continue };
                match key {
                    "kernel" => e.kernel = value.to_string(),
                    "cmdline" => e.cmdline = value.to_string(),
                    "module" => {
                        let (path, args) = value.split_once(' ').unwrap_or((value, ""));
                        e.modules.push((path.to_string(), args.trim().to_string()));
                    }
                    _ => {}
                }
            }
        }
    }
    cfg
}

fn default_config() -> Config {
    parse_config(
        "timeout=0\nentry=ospab.os\ncmdline=mode=live\n\
         module=/boot/KERNEL kernel\nmodule=/EFI/BOOT/BOOTX64.EFI efi\n",
    )
}

// ─── Menu ───────────────────────────────────────────────────────────────────

fn read_key() -> Option<InputKey> {
    unsafe {
        let cin = st().con_in;
        let mut key = InputKey { scan_code: 0, unicode_char: 0 };
        if is_error(((*cin).read_key_stroke)(cin, &mut key)) {
            return None;
        }
        Some(key)
    }
}

fn set_attr(attr: usize) {
    unsafe {
        let out = st().con_out;
        ((*out).set_attribute)(out, attr);
    }
}

/// Redraw the whole menu. `countdown` is the seconds left, or None once a key was pressed.
fn draw_menu(cfg: &Config, sel: usize, countdown: Option<u32>) {
    unsafe {
        let out = st().con_out;
        set_attr(ATTR_NORMAL);
        ((*out).clear_screen)(out);
        ((*out).enable_cursor)(out, false);
    }
    set_attr(ATTR_BRIGHT);
    println!("\n  ospab loader\n");
    let width = cfg.entries.iter().map(|e| e.title.chars().count()).max().unwrap_or(0) + 4;
    for (i, e) in cfg.entries.iter().enumerate() {
        print!("  ");
        set_attr(if i == sel { ATTR_SELECTED } else { ATTR_NORMAL });
        print!(" {}. {:<w$}", i + 1, e.title, w = width);
        set_attr(ATTR_NORMAL);
        println!();
    }
    set_attr(ATTR_DIM);
    println!("\n  \u{2191}/\u{2193} select   Enter boot   1-{} boot that entry", cfg.entries.len());
    match countdown {
        Some(s) => println!("  Booting the selected entry in {} s, any key stops the countdown", s),
        None => println!(),
    }
    set_attr(ATTR_NORMAL);
}

fn choose_entry(cfg: &Config) -> usize {
    let count = cfg.entries.len();
    let mut sel = cfg.default.min(count - 1);
    if count == 1 || cfg.timeout == 0 {
        return sel;
    }
    let mut countdown = Some(cfg.timeout);
    draw_menu(cfg, sel, countdown);
    unsafe {
        // One-second tick drives the visible countdown.
        let mut tick: Event = ptr::null_mut();
        (bs().create_event)(EVT_TIMER, 0, ptr::null_mut(), ptr::null_mut(), &mut tick);
        (bs().set_timer)(tick, TIMER_PERIODIC, 10_000_000);
        let chosen = loop {
            let events = [(*st().con_in).wait_for_key, tick];
            let mut index = 0usize;
            (bs().wait_for_event)(2, events.as_ptr(), &mut index);
            if index == 1 {
                if let Some(s) = countdown {
                    if s <= 1 {
                        break sel;
                    }
                    countdown = Some(s - 1);
                    draw_menu(cfg, sel, countdown);
                }
                continue;
            }
            let Some(key) = read_key() else { continue };
            countdown = None; // any key stops the countdown
            match (key.scan_code, char::from_u32(key.unicode_char as u32).unwrap_or('\0')) {
                (_, '\r') | (_, '\n') => break sel,
                (_, c @ '1'..='9') if (c as usize - '1' as usize) < count => break c as usize - '1' as usize,
                (SCAN_UP, _) | (_, 'k') => sel = if sel == 0 { count - 1 } else { sel - 1 },
                (SCAN_DOWN, _) | (_, 'j') => sel = (sel + 1) % count,
                (SCAN_HOME, _) => sel = 0,
                (SCAN_END, _) => sel = count - 1,
                _ => {}
            }
            draw_menu(cfg, sel, countdown);
        };
        (bs().close_event)(tick);
        let out = st().con_out;
        ((*out).clear_screen)(out);
        chosen
    }
}

// ─── Hardware info ──────────────────────────────────────────────────────────

fn find_rsdp() -> u64 {
    let st = st();
    let tables = unsafe { core::slice::from_raw_parts(st.configuration_table, st.number_of_table_entries) };
    for guid in [ACPI20_GUID, ACPI10_GUID] {
        if let Some(t) = tables.iter().find(|t| t.vendor_guid == guid) {
            return t.vendor_table as u64;
        }
    }
    0
}

fn mask_info(mask: u32) -> (u8, u8) {
    if mask == 0 { (0, 0) } else { (mask.count_ones() as u8, mask.trailing_zeros() as u8) }
}

/// Preferred resolution from the first detailed timing descriptor of the EDID.
fn edid_preferred() -> Option<(u32, u32)> {
    unsafe {
        let mut count = 0usize;
        let mut handles: *mut Handle = ptr::null_mut();
        if is_error((bs().locate_handle_buffer)(BY_PROTOCOL, &GOP_GUID, ptr::null_mut(), &mut count, &mut handles)) {
            return None;
        }
        let mut found = None;
        for &h in core::slice::from_raw_parts(handles, count) {
            for guid in [EDID_ACTIVE_GUID, EDID_DISCOVERED_GUID] {
                let mut p: *mut c_void = ptr::null_mut();
                if is_error((bs().handle_protocol)(h, &guid, &mut p)) {
                    continue;
                }
                let e = &*(p as *const Edid);
                if e.size < 128 || e.edid.is_null() {
                    continue;
                }
                let d = core::slice::from_raw_parts(e.edid, 128);
                let w = d[56] as u32 | ((d[58] as u32 & 0xF0) << 4);
                let h = d[59] as u32 | ((d[61] as u32 & 0xF0) << 4);
                if w != 0 && h != 0 {
                    found = Some((w, h));
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        (bs().free_pool)(handles as *mut u8);
        found
    }
}

fn setup_framebuffer(res: Resolution) -> FramebufferInfo {
    let mut fb = FramebufferInfo {
        phys_addr: 0, width: 0, height: 0, pitch: 0, bpp: 0, memory_model: 0,
        red_mask_size: 0, red_mask_shift: 0, green_mask_size: 0, green_mask_shift: 0,
        blue_mask_size: 0, blue_mask_shift: 0, _reserved: [0; 7],
    };
    unsafe {
        let mut gop: *mut c_void = ptr::null_mut();
        if is_error((bs().locate_protocol)(&GOP_GUID, ptr::null_mut(), &mut gop)) {
            println!("GOP: not available, booting without a framebuffer");
            return fb;
        }
        let gop = gop as *mut Gop;
        let usable = |info: &GopModeInfo| info.pixel_format <= PIXEL_BITMASK;

        // Best (largest) usable mode accepted by `fits`.
        let pick = |fits: &dyn Fn(u32, u32) -> bool| -> Option<u32> {
            let mut best: Option<(u32, u64)> = None;
            for m in 0..(*(*gop).mode).max_mode {
                let mut size = 0usize;
                let mut info: *mut GopModeInfo = ptr::null_mut();
                if is_error(((*gop).query_mode)(gop, m, &mut size, &mut info)) {
                    continue;
                }
                let i = &*info;
                let (w, h) = (i.horizontal_resolution, i.vertical_resolution);
                let area = w as u64 * h as u64;
                if usable(i) && fits(w, h) && best.map_or(true, |(_, a)| area > a) {
                    best = Some((m, area));
                }
            }
            best.map(|(m, _)| m)
        };
        let chosen = match res {
            Resolution::Keep => None,
            Resolution::Max => pick(&|_, _| true),
            Resolution::Exact(ew, eh) => pick(&|w, h| w == ew && h == eh),
            // EDID preferred mode; else the firmware's current mode (it already
            // picked the panel's native one); else the largest up to 1920x1200.
            Resolution::Auto => edid_preferred()
                .and_then(|(ew, eh)| pick(&|w, h| w == ew && h == eh))
                .or_else(|| if usable(&*(*(*gop).mode).info) { None } else { pick(&|w, h| w <= 1920 && h <= 1200) }),
        };
        if let Some(m) = chosen {
            if m != (*(*gop).mode).mode {
                ((*gop).set_mode)(gop, m);
            }
        }

        let mode = &*(*gop).mode;
        let info = &*mode.info;
        if !usable(info) {
            println!("GOP: mode has no linear framebuffer");
            return fb;
        }
        let (r, g, b) = match info.pixel_format {
            PIXEL_RGB => ((8, 0), (8, 8), (8, 16)),
            PIXEL_BGR => ((8, 16), (8, 8), (8, 0)),
            _ => {
                let p = &info.pixel_information;
                (mask_info(p.red), mask_info(p.green), mask_info(p.blue))
            }
        };
        fb.phys_addr = mode.frame_buffer_base;
        fb.width = info.horizontal_resolution as u64;
        fb.height = info.vertical_resolution as u64;
        fb.bpp = 32;
        fb.pitch = info.pixels_per_scan_line as u64 * 4;
        fb.memory_model = 1;
        (fb.red_mask_size, fb.red_mask_shift) = r;
        (fb.green_mask_size, fb.green_mask_shift) = g;
        (fb.blue_mask_size, fb.blue_mask_shift) = b;
        println!("GOP: {}x{} @ {:#x}", fb.width, fb.height, fb.phys_addr);
    }
    fb
}

// ─── Kernel ELF ─────────────────────────────────────────────────────────────

struct KernelImage {
    entry: u64,
    phys_base: u64,
    virt_base: u64,
}

fn rd16(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }
fn rd32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn rd64(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

/// Copy the PT_LOAD segments into one physically contiguous block and map them
/// at their linked addresses.
fn load_elf(file: &[u8], pt: &mut PageTables) -> Result<KernelImage, &'static str> {
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
    let phys = alloc_pages(((hi - lo) / PAGE) as usize, OSPAB_KERNEL_MEMORY);

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

// ─── Memory map ─────────────────────────────────────────────────────────────

struct RawMap {
    buf: u64,
    buf_pages: usize,
    size: usize,
    desc_size: usize,
    key: usize,
}

impl RawMap {
    fn descriptors(&self) -> impl Iterator<Item = MemoryDescriptor> + '_ {
        (0..self.size / self.desc_size)
            .map(move |i| unsafe { ptr::read_unaligned((self.buf as usize + i * self.desc_size) as *const MemoryDescriptor) })
    }
}

/// Buffer big enough for the current map plus slack for the allocations that follow.
fn alloc_map_buffer() -> RawMap {
    let mut size = 0usize;
    let (mut key, mut dsize, mut ver) = (0usize, 0usize, 0u32);
    unsafe { (bs().get_memory_map)(&mut size, ptr::null_mut(), &mut key, &mut dsize, &mut ver) };
    let bytes = size as u64 + 64 * dsize.max(48) as u64;
    let pages = ((bytes + PAGE - 1) / PAGE) as usize;
    RawMap { buf: alloc_pages(pages, LOADER_DATA), buf_pages: pages, size: 0, desc_size: dsize.max(48), key: 0 }
}

fn get_map(map: &mut RawMap) -> Status {
    let mut ver = 0u32;
    map.size = map.buf_pages * PAGE as usize;
    unsafe {
        (bs().get_memory_map)(&mut map.size, map.buf as *mut MemoryDescriptor, &mut map.key, &mut map.desc_size, &mut ver)
    }
}

/// Memory the HHDM must cover beyond 4 GiB: RAM and firmware tables, not
/// reserved holes or MMIO (OVMF reports a reserved range near 1 TiB).
fn is_ram(typ: u32) -> bool {
    matches!(
        typ,
        LOADER_CODE | LOADER_DATA | BOOT_SERVICES_CODE | BOOT_SERVICES_DATA | RUNTIME_SERVICES_CODE
            | RUNTIME_SERVICES_DATA | CONVENTIONAL_MEMORY | ACPI_RECLAIM_MEMORY | ACPI_MEMORY_NVS
            | PERSISTENT_MEMORY
    ) || typ >= 0x8000_0000
}

fn convert_type(typ: u32) -> Option<u64> {
    Some(match typ {
        CONVENTIONAL_MEMORY | BOOT_SERVICES_CODE | BOOT_SERVICES_DATA => MEM_USABLE,
        LOADER_CODE | LOADER_DATA | OSPAB_RECLAIM_MEMORY => MEM_BOOTLOADER_RECLAIMABLE,
        OSPAB_KERNEL_MEMORY => MEM_KERNEL_AND_MODULES,
        ACPI_RECLAIM_MEMORY => MEM_ACPI_RECLAIMABLE,
        ACPI_MEMORY_NVS => MEM_ACPI_NVS,
        UNUSABLE_MEMORY => MEM_BAD_MEMORY,
        MEMORY_MAPPED_IO | MEMORY_MAPPED_IO_PORT_SPACE => return None,
        _ => MEM_RESERVED,
    })
}

/// Final map in the kernel's format: sorted, framebuffer carved out, neighbours of
/// the same kind merged. Runs after ExitBootServices: no allocation.
fn convert_map(map: &RawMap, fb: &FramebufferInfo, out: &mut [MemoryRegion]) -> usize {
    let mut n = 0;
    let fb_start = fb.phys_addr;
    let fb_end = fb.phys_addr + fb.pitch * fb.height;
    for d in map.descriptors() {
        let Some(kind) = convert_type(d.typ) else { continue };
        let (start, end) = (d.physical_start, d.physical_start + d.number_of_pages * PAGE);
        // The parts outside the framebuffer (the whole region if they don't overlap).
        let pieces = if fb_start != 0 && start < fb_end && fb_start < end {
            [(start, fb_start.max(start)), (fb_end.min(end), end)]
        } else {
            [(start, end), (0, 0)]
        };
        for (s, e) in pieces {
            if s < e && n < out.len() {
                out[n] = MemoryRegion { base: s, length: e - s, kind };
                n += 1;
            }
        }
    }
    if fb_start != 0 && n < out.len() {
        out[n] = MemoryRegion { base: fb_start, length: (fb_end - fb_start + PAGE - 1) & !(PAGE - 1), kind: MEM_FRAMEBUFFER };
        n += 1;
    }
    // Insertion sort (a few hundred entries at most).
    for i in 1..n {
        let mut j = i;
        while j > 0 && out[j - 1].base > out[j].base {
            out.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut m = 0;
    for i in 0..n {
        if m > 0 && out[m - 1].kind == out[i].kind && out[m - 1].base + out[m - 1].length == out[i].base {
            out[m - 1].length += out[i].length;
        } else {
            out[m] = out[i];
            m += 1;
        }
    }
    m
}

// ─── Hand-off ───────────────────────────────────────────────────────────────

core::arch::global_asm!(
    ".global ospab_handoff",
    "ospab_handoff:",
    "cli",
    "mov cr3, rcx",
    "mov rsp, r8",
    "push 0",
    "mov rax, r9",
    "xor ebx, ebx",
    "xor ecx, ecx",
    "xor ebp, ebp",
    "xor r8d, r8d",
    "xor r9d, r9d",
    "xor r10d, r10d",
    "xor r11d, r11d",
    "xor r12d, r12d",
    "xor r13d, r13d",
    "xor r14d, r14d",
    "xor r15d, r15d",
    "jmp rax",
);

extern "sysv64" {
    /// RDI = BootInfo phys, RSI = magic, RDX = HHDM, RCX = PML4, R8 = stack top, R9 = entry.
    fn ospab_handoff(info: u64, magic: u64, hhdm: u64, cr3: u64, stack: u64, entry: u64) -> !;
}

/// Copies strings into reclaimable pages and returns their physical addresses.
struct StrArena {
    base: u64,
    used: u64,
    cap: u64,
}

impl StrArena {
    fn new() -> Self {
        StrArena { base: alloc_pages(2, OSPAB_RECLAIM_MEMORY), used: 0, cap: 2 * PAGE }
    }

    fn push(&mut self, s: &str) -> u64 {
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

fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("cli; hlt") };
    }
}

fn fail(msg: &str) -> ! {
    println!("\nospab-boot: {}", msg);
    println!("System halted.");
    halt()
}

#[no_mangle]
extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    unsafe {
        console::init(system_table);
        (bs().set_watchdog_timer)(0, 0, 0, ptr::null());
    }
    println!("{}", LOADER_NAME);

    // Boot volume and configuration.
    let mut vol: Volume = fs::find_volume(image, CONFIG_PATH)
        .or_else(|| fs::find_volume(image, DEFAULT_KERNEL))
        .unwrap_or_else(|| fail("no volume with /boot/ospab.cfg or /boot/KERNEL"));
    let cfg = match vol.read_small(CONFIG_PATH) {
        Some(text) => parse_config(core::str::from_utf8(&text).unwrap_or("")),
        None => default_config(),
    };
    if cfg.entries.is_empty() {
        fail("no entries in /boot/ospab.cfg");
    }
    let entry = &cfg.entries[choose_entry(&cfg)];
    println!("Booting '{}' from {} volume", entry.title, vol.kind());

    // Kernel file; it is also a module when the config lists it (installer).
    let kernel_is_module = entry.modules.iter().any(|(p, _)| *p == entry.kernel);
    let kernel_file = vol
        .load(&entry.kernel, if kernel_is_module { OSPAB_KERNEL_MEMORY } else { OSPAB_RECLAIM_MEMORY })
        .unwrap_or_else(|| fail("cannot read the kernel file"));
    println!("Kernel: {} ({} KiB)", entry.kernel, kernel_file.size / 1024);

    let mut pt = PageTables::new();
    let kernel = load_elf(
        unsafe { core::slice::from_raw_parts(kernel_file.addr as *const u8, kernel_file.size as usize) },
        &mut pt,
    )
    .unwrap_or_else(|e| fail(e));

    // Modules.
    let mut loaded: Vec<(Loaded, &str, &str)> = Vec::new();
    for (path, args) in &entry.modules {
        let file = if *path == entry.kernel {
            Some(kernel_file)
        } else {
            vol.load(path, OSPAB_KERNEL_MEMORY)
        };
        match file {
            Some(f) => loaded.push((f, path.as_str(), args.as_str())),
            None => println!("Module {} not found, skipped", path),
        }
    }

    let fb = setup_framebuffer(cfg.resolution);
    let rsdp = find_rsdp();

    // Boot info and everything it points to.
    let mut strings = StrArena::new();
    let info_phys = alloc_pages(1, OSPAB_RECLAIM_MEMORY);
    let mods_phys = alloc_pages(1, OSPAB_RECLAIM_MEMORY);
    let mods = unsafe { core::slice::from_raw_parts_mut(mods_phys as *mut Module, loaded.len().min(PAGE as usize / 32)) };
    for (m, (f, path, args)) in mods.iter_mut().zip(loaded.iter()) {
        *m = Module { phys_addr: f.addr, size: f.size, path: strings.push(path), cmdline: strings.push(args) };
    }
    let regions_pages = (MAX_REGIONS * core::mem::size_of::<MemoryRegion>()).div_ceil(PAGE as usize);
    let regions_phys = alloc_pages(regions_pages, OSPAB_RECLAIM_MEMORY);
    let stack_phys = alloc_pages((KERNEL_STACK / PAGE) as usize, OSPAB_RECLAIM_MEMORY);

    let info = unsafe { &mut *(info_phys as *mut BootInfo) };
    *info = BootInfo {
        magic: OSPAB_BOOT_MAGIC,
        version: OSPAB_BOOT_VERSION,
        size: core::mem::size_of::<BootInfo>() as u32,
        firmware: FIRMWARE_UEFI,
        _reserved0: 0,
        loader_name: strings.push(LOADER_NAME),
        hhdm_offset: HHDM_OFFSET,
        kernel_phys_base: kernel.phys_base,
        kernel_virt_base: kernel.virt_base,
        rsdp,
        cmdline: strings.push(&entry.cmdline),
        framebuffer: fb,
        memmap: regions_phys,
        memmap_count: 0,
        modules: mods_phys,
        module_count: mods.len() as u64,
        _reserved: [0; 8],
    };

    // HHDM over all RAM-like memory (at least 4 GiB) and the framebuffer.
    let mut map = alloc_map_buffer();
    if is_error(get_map(&mut map)) {
        fail("GetMemoryMap failed");
    }
    let mut top = 4 * GIB;
    for d in map.descriptors().filter(|d| is_ram(d.typ)) {
        top = top.max(d.physical_start + d.number_of_pages * PAGE);
    }
    top = top.next_multiple_of(GIB);
    pt.map_2m_range(HHDM_OFFSET, 0, top, W | NX);
    if fb.phys_addr != 0 {
        let start = fb.phys_addr & !(MIB2 - 1);
        let end = (fb.phys_addr + fb.pitch * fb.height).next_multiple_of(MIB2);
        pt.map_2m_range(HHDM_OFFSET + start, start, end - start, W | NX);
    }
    pt.identity(ospab_handoff as *const () as u64, 2 * PAGE);

    let cr4: u64;
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) cr4) };
    if cr4 & (1 << 12) != 0 {
        fail("firmware runs with 5-level paging, not supported yet");
    }

    println!("Kernel entry {:#x}, phys base {:#x}, HHDM up to {} GiB", kernel.entry, kernel.phys_base, top / GIB);
    println!("Exiting boot services...");

    // ExitBootServices: the map key must be fresh; retry once if it went stale.
    let mut tries = 0;
    loop {
        if is_error(get_map(&mut map)) {
            fail("GetMemoryMap failed");
        }
        let s = unsafe { (bs().exit_boot_services)(image, map.key) };
        if !is_error(s) {
            break;
        }
        tries += 1;
        if tries > 4 {
            fail("ExitBootServices failed");
        }
    }
    console::boot_services_done();

    let regions = unsafe { core::slice::from_raw_parts_mut(regions_phys as *mut MemoryRegion, MAX_REGIONS) };
    info.memmap_count = convert_map(&map, &fb, regions) as u64;

    unsafe {
        // NX bits are used in the tables, so EFER.NXE must be on before CR3 switches.
        let (lo, hi): (u32, u32);
        core::arch::asm!("rdmsr", in("ecx") 0xC000_0080u32, out("eax") lo, out("edx") hi);
        core::arch::asm!("wrmsr", in("ecx") 0xC000_0080u32, in("eax") lo | (1 << 11), in("edx") hi);
        ospab_handoff(
            info_phys,
            OSPAB_BOOT_MAGIC,
            HHDM_OFFSET,
            pt.pml4,
            HHDM_OFFSET + stack_phys + KERNEL_STACK,
            kernel.entry,
        )
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("\nospab-boot panic: {}", info);
    halt()
}
