/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Hardware access of the BIOS front-end: port I/O, VGA text console, COM1, TSC timing,
keyboard (INT 16h), ACPI lookup (RSDP, power off) and reset.
*/
use alloc::string::String;
use core::fmt;
use core::ptr;

use crate::menu::{Key, Term};
use crate::rm::{self, Regs};

// ─── Ports and timing ───────────────────────────────────────────────────────

pub fn outb(port: u16, v: u8) {
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack)) };
}

pub fn outw(port: u16, v: u16) {
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack)) };
}

pub fn outl(port: u16, v: u32) {
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack)) };
}

pub fn inb(port: u16) -> u8 {
    let v: u8;
    unsafe { core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack)) };
    v
}

pub fn inw(port: u16) -> u16 {
    let v: u16;
    unsafe { core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack)) };
    v
}

pub fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    ((hi as u64) << 32) | lo as u64
}

static mut TSC_PER_MS: u64 = 2_000_000;

pub fn tsc_per_ms() -> u64 {
    unsafe { TSC_PER_MS }
}

/// Measure the TSC against PIT channel 2 (50 ms).
pub fn calibrate_tsc() {
    unsafe {
        let p61 = inb(0x61);
        outb(0x61, (p61 & 0xFC) | 1);
        outb(0x43, 0xB0);
        outb(0x42, (59659 & 0xFF) as u8);
        outb(0x42, (59659 >> 8) as u8);
        let t0 = rdtsc();
        let mut guard = 0u64;
        while inb(0x61) & 0x20 == 0 {
            guard += 1;
            if guard > 400_000_000 {
                return; // no PIT: keep the default
            }
        }
        let t1 = rdtsc();
        outb(0x61, p61);
        let per_ms = t1.wrapping_sub(t0) / 50;
        if per_ms > 10_000 {
            TSC_PER_MS = per_ms;
        }
    }
}

/// Busy-wait `us` microseconds.
pub fn delay_us(us: u64) {
    let end = rdtsc() + us * tsc_per_ms() / 1000;
    while rdtsc() < end {
        core::hint::spin_loop();
    }
}

// ─── Serial (COM1) ──────────────────────────────────────────────────────────

static mut SERIAL_ON: bool = false;
static mut SERIAL_PRESENT: bool = false;

pub fn serial_init() {
    unsafe {
        if inb(0x3FD) == 0xFF {
            return; // no UART
        }
        SERIAL_PRESENT = true;
        SERIAL_ON = true;
        outb(0x3F9, 0);
        outb(0x3FB, 0x80);
        outb(0x3F8, 1);
        outb(0x3F9, 0);
        outb(0x3FB, 3);
        outb(0x3FA, 0xC7);
        outb(0x3FC, 0x0B);
    }
}

/// Config `serial = yes|no` (the early log goes to COM1 until the config is read).
pub fn set_serial(on: bool) {
    unsafe { SERIAL_ON = on && SERIAL_PRESENT };
}

fn serial_byte(b: u8) {
    for _ in 0..50_000 {
        if inb(0x3FD) & 0x20 != 0 {
            break;
        }
    }
    outb(0x3F8, b);
}

// ─── VGA text console (log output) ──────────────────────────────────────────

const VGA: *mut u16 = 0xB8000 as *mut u16;
pub const COLS: usize = 80;
pub const ROWS: usize = 25;
static mut LOG_ROW: usize = 0;
static mut LOG_COL: usize = 0;

pub fn vga_clear(attr: u8) {
    for i in 0..COLS * ROWS {
        unsafe { ptr::write_volatile(VGA.add(i), (attr as u16) << 8 | b' ' as u16) };
    }
    unsafe {
        LOG_ROW = 0;
        LOG_COL = 0;
    }
}

fn log_newline() {
    unsafe {
        LOG_COL = 0;
        LOG_ROW += 1;
        if LOG_ROW >= ROWS {
            for i in 0..COLS * (ROWS - 1) {
                let v = ptr::read_volatile(VGA.add(i + COLS));
                ptr::write_volatile(VGA.add(i), v);
            }
            for i in 0..COLS {
                ptr::write_volatile(VGA.add(COLS * (ROWS - 1) + i), 0x0720);
            }
            LOG_ROW = ROWS - 1;
        }
    }
}

pub struct Console;

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            unsafe {
                if SERIAL_ON {
                    if b == b'\n' {
                        serial_byte(b'\r');
                    }
                    serial_byte(b);
                }
                match b {
                    b'\n' => log_newline(),
                    b'\r' => LOG_COL = 0,
                    _ => {
                        if LOG_COL >= COLS {
                            log_newline();
                        }
                        let c = if (0x20..0x7F).contains(&b) { b } else { b'?' };
                        ptr::write_volatile(VGA.add(LOG_ROW * COLS + LOG_COL), 0x0700 | c as u16);
                        LOG_COL += 1;
                    }
                }
            }
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let _ = core::fmt::Write::write_fmt(&mut $crate::hw::Console, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{ $crate::print!($($arg)*); $crate::print!("\n"); }};
}

// ─── Menu terminal: VGA text 80x25 + INT 16h ────────────────────────────────

pub struct BiosTerm;

impl BiosTerm {
    pub fn new() -> Self {
        // Mode 3 (80x25 colour text), also restores the console if a loader entry changed it.
        let mut r = Regs::new();
        r.eax = 0x0003;
        rm::int(0x10, &mut r);
        // 16 background colours instead of blinking.
        let mut r = Regs::new();
        r.eax = 0x1003;
        r.ebx = 0;
        rm::int(0x10, &mut r);
        BiosTerm
    }
}

fn crtc(reg: u8, v: u8) {
    outb(0x3D4, reg);
    outb(0x3D5, v);
}

impl Term for BiosTerm {
    fn size(&self) -> (usize, usize) {
        (COLS, ROWS)
    }

    fn clear(&mut self, attr: u8) {
        vga_clear(attr);
    }

    fn put(&mut self, row: usize, col: usize, s: &str, attr: u8) {
        if row >= ROWS || col >= COLS {
            return;
        }
        for (i, c) in s.chars().take(COLS - col).enumerate() {
            let b = if (' '..='~').contains(&c) { c as u8 } else { b'?' };
            unsafe { ptr::write_volatile(VGA.add(row * COLS + col + i), (attr as u16) << 8 | b as u16) };
        }
    }

    fn set_cursor(&mut self, row: usize, col: usize, visible: bool) {
        let pos = (row * COLS + col) as u16;
        crtc(0x0F, pos as u8);
        crtc(0x0E, (pos >> 8) as u8);
        crtc(0x0A, if visible { 14 } else { 0x20 });
        crtc(0x0B, 15);
    }

    fn wait_key(&mut self, ms: u32) -> Option<Key> {
        let end = rdtsc() + ms as u64 * tsc_per_ms();
        loop {
            if let Some(k) = self.poll_key() {
                return Some(k);
            }
            if rdtsc() >= end {
                return None;
            }
        }
    }

    fn poll_key(&mut self) -> Option<Key> {
        let mut r = Regs::new();
        r.eax = 0x0100;
        rm::int(0x16, &mut r);
        if r.zero() {
            return None;
        }
        let mut r = Regs::new();
        r.eax = 0x0000;
        rm::int(0x16, &mut r);
        let (ascii, scan) = (r.eax as u8, (r.eax >> 8) as u8);
        Some(match scan {
            0x48 if ascii == 0 || ascii == 0xE0 => Key::Up,
            0x50 if ascii == 0 || ascii == 0xE0 => Key::Down,
            0x4B if ascii == 0 || ascii == 0xE0 => Key::Left,
            0x4D if ascii == 0 || ascii == 0xE0 => Key::Right,
            0x47 if ascii == 0 || ascii == 0xE0 => Key::Home,
            0x4F if ascii == 0 || ascii == 0xE0 => Key::End,
            0x53 if ascii == 0 || ascii == 0xE0 => Key::Delete,
            _ => match ascii {
                0x0D | 0x0A => Key::Enter,
                0x08 => Key::Backspace,
                0x1B => Key::Esc,
                0x20..=0x7E => Key::Char(ascii as char),
                _ => Key::Other,
            },
        })
    }
}

// ─── ACPI ───────────────────────────────────────────────────────────────────

fn checksum_ok(p: u64, len: usize) -> bool {
    let mut sum = 0u8;
    for i in 0..len {
        sum = sum.wrapping_add(unsafe { ptr::read(((p as usize) + i) as *const u8) });
    }
    sum == 0
}

/// Physical address of the ACPI RSDP (EBDA, then 0xE0000..0xFFFFF), 0 if none.
pub fn find_rsdp() -> u64 {
    let ebda = (unsafe { ptr::read(0x40E as *const u16) } as u64) << 4;
    let areas: [(u64, u64); 2] = [(ebda, ebda + 1024), (0xE0000, 0x100000)];
    for (start, end) in areas {
        if start < 0x400 {
            continue;
        }
        let mut p = start & !15;
        while p + 20 <= end {
            if unsafe { core::slice::from_raw_parts(p as *const u8, 8) } == b"RSD PTR " && checksum_ok(p, 20) {
                return p;
            }
            p += 16;
        }
    }
    0
}

fn rd32(p: u64) -> u32 {
    unsafe { ptr::read_unaligned(p as *const u32) }
}

fn rd64(p: u64) -> u64 {
    unsafe { ptr::read_unaligned(p as *const u64) }
}

fn sig(p: u64) -> [u8; 4] {
    unsafe { ptr::read_unaligned(p as *const [u8; 4]) }
}

/// What is needed for an ACPI S5 (soft off).
#[derive(Clone, Copy)]
pub struct PowerInfo {
    pm1a: u16,
    pm1b: u16,
    smi_cmd: u16,
    acpi_enable: u8,
    typ_a: u16,
    typ_b: u16,
}

static mut POWER: Option<PowerInfo> = None;

/// Parse FADT and the `_S5_` object of the DSDT. True when ACPI power off is possible.
pub fn acpi_init() -> bool {
    let rsdp = find_rsdp();
    if rsdp == 0 || rsdp >= 0xFFFF_F000 {
        return false;
    }
    let rev = unsafe { ptr::read((rsdp + 15) as *const u8) };
    let mut fadt = 0u64;
    let scan = |table: u64, entry: usize, count_from: u64| -> u64 {
        let len = rd32(table + 4) as u64;
        if len < 36 || len > 0x10000 {
            return 0;
        }
        let n = (len - 36) / entry as u64;
        for i in 0..n {
            let e = if entry == 8 { rd64(count_from + i * 8) } else { rd32(count_from + i * 4) as u64 };
            if e != 0 && e < 0xFFFF_F000 && &sig(e) == b"FACP" {
                return e;
            }
        }
        0
    };
    if rev >= 2 {
        let x = rd64(rsdp + 24);
        if x != 0 && x < 0xFFFF_F000 && &sig(x) == b"XSDT" {
            fadt = scan(x, 8, x + 36);
        }
    }
    if fadt == 0 {
        let r = rd32(rsdp + 16) as u64;
        if r != 0 && &sig(r) == b"RSDT" {
            fadt = scan(r, 4, r + 36);
        }
    }
    if fadt == 0 {
        return false;
    }
    let flen = rd32(fadt + 4);
    let mut dsdt = rd32(fadt + 40) as u64;
    if flen >= 148 {
        let x = rd64(fadt + 140);
        if x != 0 && x < 0xFFFF_F000 {
            dsdt = x;
        }
    }
    if dsdt == 0 || &sig(dsdt) != b"DSDT" {
        return false;
    }
    let dlen = (rd32(dsdt + 4) as u64).min(0x100000);
    let bytes = unsafe { core::slice::from_raw_parts(dsdt as *const u8, dlen as usize) };
    let mut i = 36;
    while i + 8 < bytes.len() {
        if &bytes[i..i + 4] == b"_S5_" && i > 0 && (bytes[i - 1] == 0x08 || (i > 1 && bytes[i - 2] == 0x08 && bytes[i - 1] == b'\\')) && bytes[i + 4] == 0x12 {
            // PackageOp, PkgLength (1..4 bytes), NumElements, then the elements.
            let lead = bytes[i + 5];
            let mut j = i + 6 + (lead >> 6) as usize;
            j += 1; // NumElements
            let val = |j: &mut usize| -> Option<u16> {
                let b = *bytes.get(*j)?;
                *j += 1;
                match b {
                    0x00 => Some(0),
                    0x01 => Some(1),
                    0xFF => Some(0xFF),
                    0x0A => {
                        let v = *bytes.get(*j)?;
                        *j += 1;
                        Some(v as u16)
                    }
                    0x0B => {
                        let v = u16::from_le_bytes([*bytes.get(*j)?, *bytes.get(*j + 1)?]);
                        *j += 2;
                        Some(v)
                    }
                    _ => None,
                }
            };
            let (Some(a), Some(b)) = (val(&mut j), val(&mut j)) else { return false };
            unsafe {
                POWER = Some(PowerInfo {
                    pm1a: rd32(fadt + 64) as u16,
                    pm1b: rd32(fadt + 68) as u16,
                    smi_cmd: rd32(fadt + 48) as u16,
                    acpi_enable: ptr::read((fadt + 52) as *const u8),
                    typ_a: a,
                    typ_b: b,
                });
                return POWER.map_or(false, |p| p.pm1a != 0);
            }
        }
        i += 1;
    }
    false
}

pub fn power_off_available() -> bool {
    unsafe { POWER.is_some() }
}

/// ACPI S5. Returns only if the machine did not switch off.
pub fn power_off() {
    let Some(p) = (unsafe { POWER }) else { return };
    // Switch to ACPI mode when the firmware has not done it yet.
    if inw(p.pm1a) & 1 == 0 && p.smi_cmd != 0 && p.acpi_enable != 0 {
        outb(p.smi_cmd, p.acpi_enable);
        for _ in 0..300 {
            if inw(p.pm1a) & 1 != 0 {
                break;
            }
            delay_us(10_000);
        }
    }
    outw(p.pm1a, (p.typ_a << 10) | (1 << 13));
    if p.pm1b != 0 {
        outw(p.pm1b, (p.typ_b << 10) | (1 << 13));
    }
    delay_us(1_000_000);
}

/// Reset: keyboard controller, then the reset control register, then a triple fault.
pub fn reboot() {
    for _ in 0..10_000 {
        if inb(0x64) & 2 == 0 {
            break;
        }
    }
    outb(0x64, 0xFE);
    delay_us(100_000);
    outb(0xCF9, 0x02);
    outb(0xCF9, 0x06);
    delay_us(100_000);
    unsafe {
        let null_idt: [u8; 10] = [0; 10];
        core::arch::asm!("lidt [{0}]", "int3", in(reg) null_idt.as_ptr(), options(noreturn));
    }
}

pub fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("cli; hlt") };
    }
}

pub fn hex(v: u64) -> String {
    alloc::format!("{:#x}", v)
}

/// The kernel uses SSE: enable it the way UEFI firmware leaves the CPU (CR0.EM = 0,
/// CR0.MP = 1, CR4.OSFXSR = 1, CR4.OSXMMEXCPT = 1) and reset the x87 unit.
pub fn enable_sse() {
    unsafe {
        core::arch::asm!(
            "mov {t}, cr0",
            "and {t}, -5",
            "or {t}, 2",
            "mov cr0, {t}",
            "mov {t}, cr4",
            "or {t}, 0x600",
            "mov cr4, {t}",
            "fninit",
            t = out(reg) _,
        );
    }
}

// ─── Exceptions in long mode ────────────────────────────────────────────────

#[repr(C, align(16))]
struct Idt([[u64; 2]; 32]);
static mut IDT: Idt = Idt([[0; 2]; 32]);

#[repr(C, packed)]
pub struct IdtPtr {
    limit: u16,
    base: u64,
}

/// Loaded again by the real-mode thunk after every BIOS call (rm.S, `lm_back`).
#[no_mangle]
pub static mut ospab_idt_ptr: IdtPtr = IdtPtr { limit: 0, base: 0 };

extern "C" {
    static exc_stubs: u8;
}

/// Install handlers for the 32 CPU exceptions: a crash prints a message instead of resetting.
pub fn init_idt() {
    unsafe {
        let base = &exc_stubs as *const u8 as u64;
        for i in 0..32u64 {
            let h = base + i * 8;
            IDT.0[i as usize] = [
                (h & 0xFFFF) | (0x08 << 16) | (0x8E << 40) | (((h >> 16) & 0xFFFF) << 48),
                h >> 32,
            ];
        }
        ospab_idt_ptr = IdtPtr { limit: 32 * 16 - 1, base: core::ptr::addr_of!(IDT) as u64 };
        core::arch::asm!("lidt [{}]", in(reg) core::ptr::addr_of!(ospab_idt_ptr), options(nostack));
    }
}

/// `frame[0]` is the vector; for vectors with an error code `frame[1]` is the code, then RIP, CS, RFLAGS.
#[no_mangle]
pub extern "sysv64" fn exception_handler(frame: *const u64) -> ! {
    let f = unsafe { core::slice::from_raw_parts(frame, 6) };
    let cr2: u64;
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2) };
    println!("\nospab-boot: CPU exception {} (stack {:#x} {:#x} {:#x} {:#x} {:#x}) CR2={:#x}", f[0], f[1], f[2], f[3], f[4], f[5], cr2);
    println!("System halted.");
    halt()
}
