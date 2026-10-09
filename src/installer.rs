/*
 * AETERNA Installer — aeterna-install
 *
 * Full-screen, step-by-step disk installer for AETERNA Microkernel.
 *
 * Screens:
 *   1 Welcome   system check (kernel + Limine modules, disks)
 *   2 Disk      pick the target disk (device, size, bus, model)
 *   3 Options   ESP size, hostname, root password, locale + layout preview
 *   4 Confirm   review the plan, red erase warning, type "yes"
 *   5 Install   per-step status + progress bars (nothing is written before this)
 *   6 Done      verification results, "remove the ISO", reboot / shell
 *
 * On-disk result:
 *   Sector  0       Protective MBR (0xEE)
 *   Sector  1       GPT header (EFI PART)
 *   Sectors 2-33    GPT partition entries (128 × 128 B)
 *   ESP (FAT32):
 *     /EFI/BOOT/BOOTX64.EFI  — Limine UEFI payload
 *     /boot/KERNEL           — AETERNA kernel ELF
 *     /limine.conf           — boot config (Limine syntax)
 *   Root partition:
 *     Identity sector        — magic + version + hostname + geometry
 *     (RamFS persistence lives a few sectors further, see vfs/disk_sync.rs)
 *   Backup GPT               — at last sector
 *
 * Readback verify: GPT signature + CRCs, FAT32 BPB, EFI MZ, kernel, identity.
 */

#![allow(dead_code)]

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use ospab_os::arch::x86_64::framebuffer;
use ospab_os::arch::x86_64::keyboard;
use ospab_os::arch::x86_64::serial;

// ── Palette (0x00RRGGBB — the framebuffer converts to its native order) ─────
const BG: u32       = 0x000B1018; // screen background
const FG: u32       = 0x00E6E9EF; // normal text
const FG_TITLE: u32 = 0x00FFFFFF; // page titles
const FG_DIM: u32   = 0x00828C9E; // secondary text
const FG_OK: u32    = 0x0046D07A; // green
const FG_WARN: u32  = 0x00FFC24B; // amber
const FG_ERR: u32   = 0x00FF5C5C; // red
const ACCENT: u32   = 0x0049A6FF; // blue accent
const BAR_BG: u32   = 0x00142B45; // header / footer bar
const KEY_BG: u32   = 0x002D5A8A; // key-cap chips in the footer
const SEL_BG: u32   = 0x001E3F66; // selected list row
const FIELD_BG: u32 = 0x001B2433; // text input field
const RULE: u32     = 0x002A3446; // separator lines
const TRACK: u32    = 0x00263040; // progress bar track
const ERR_BG: u32   = 0x00361318; // red warning box fill
const OK_BG: u32    = 0x0010301E; // green success box fill
const WARN_BG: u32  = 0x00352A10; // amber box fill
const ESP_COL: u32  = 0x0049A6FF; // layout preview: ESP
const ROOT_COL: u32 = 0x002E9E6A; // layout preview: root

const CW: u64 = framebuffer::CHAR_WIDTH;
const CH: u64 = framebuffer::CHAR_HEIGHT;

// ── Screen geometry (text cells) ─────────────────────────────────────────────
static COLS: AtomicU64  = AtomicU64::new(80);
static ROWS: AtomicU64  = AtomicU64::new(30);
static LEFT: AtomicU64  = AtomicU64::new(2);
static WIDTH: AtomicU64 = AtomicU64::new(76);

fn cols() -> u64  { COLS.load(Ordering::Relaxed) }
fn rows() -> u64  { ROWS.load(Ordering::Relaxed) }
fn left() -> u64  { LEFT.load(Ordering::Relaxed) }
fn width() -> u64 { WIDTH.load(Ordering::Relaxed) }

fn geom_init() {
    let c = framebuffer::screen_cols().max(40);
    let r = framebuffer::screen_rows().max(25);
    let w = c.saturating_sub(4).min(76);
    COLS.store(c, Ordering::Relaxed);
    ROWS.store(r, Ordering::Relaxed);
    WIDTH.store(w, Ordering::Relaxed);
    LEFT.store((c - w) / 2, Ordering::Relaxed);
}

// Fixed rows of the page frame
const R_TITLE: u64 = 5;
const R_SUB: u64   = 6;
const R_BODY: u64  = 8;

// ── Drawing primitives (absolute cells, no wrapping or scrolling) ────────────
fn cell(col: u64, row: u64, ch: char, fg: u32, bg: u32) {
    if col >= cols() || row >= rows() { return; }
    framebuffer::draw_char_at(col * CW, row * CH, ch, fg, bg);
}
fn abs_text(col: u64, row: u64, s: &str, fg: u32, bg: u32) -> u64 {
    let mut c = col;
    for ch in s.chars() { cell(c, row, ch, fg, bg); c += 1; }
    c
}
fn fill_cells(col: u64, row: u64, w: u64, h: u64, color: u32) {
    framebuffer::fill_rect(col * CW, row * CH, w * CW, h * CH, color);
}
fn clen(s: &str) -> u64 { s.chars().count() as u64 }

/// Text cursor relative to the centred panel.
struct Pen { col: u64, row: u64, bg: u32 }
impl Pen {
    fn at(col: u64, row: u64) -> Pen { Pen { col: left() + col, row, bg: BG } }
    fn on(mut self, bg: u32) -> Pen { self.bg = bg; self }
    fn put(&mut self, s: &str, fg: u32) -> &mut Pen {
        self.col = abs_text(self.col, self.row, s, fg, self.bg); self
    }
    fn pad(&mut self, col: u64) -> &mut Pen {
        let target = left() + col;
        while self.col < target { cell(self.col, self.row, ' ', FG, self.bg); self.col += 1; }
        self
    }
}
fn t(col: u64, row: u64, s: &str, fg: u32) { Pen::at(col, row).put(s, fg); }
fn clear_panel_row(row: u64) { fill_cells(left(), row, width(), 1, BG); }

fn hrule(row: u64) {
    let mut p = Pen::at(0, row);
    for _ in 0..width() { p.put("\u{2500}", RULE); }
}

/// Pixel-precise progress bar `cells` wide, `permille` 0..=1000 filled.
fn pbar(col: u64, row: u64, cells: u64, permille: u64, fg: u32, thick: bool) {
    let x = (left() + col) * CW;
    let y = row * CH;
    let w = cells * CW;
    let h = if thick { CH - 4 } else { CH / 2 };
    let yo = y + (CH - h) / 2;
    framebuffer::fill_rect(x, y, w, CH, BG);
    framebuffer::fill_rect(x, yo, w, h, TRACK);
    let f = w * permille.min(1000) / 1000;
    if f > 0 { framebuffer::fill_rect(x, yo, f, h, fg); }
}

/// Bordered box across the panel, rows `r0..r0+h`, interior filled with `fill`.
fn draw_box(r0: u64, h: u64, border: u32, fill: u32, title: &str) {
    let w = width();
    fill_cells(left(), r0, w, h, fill);
    let mut p = Pen::at(0, r0).on(fill);
    p.put("\u{250C}", border);
    let mut used = 1;
    if !title.is_empty() {
        p.put("\u{2500} ", border); p.put(title, border); p.put(" ", border);
        used += 3 + clen(title);
    }
    for _ in used..w - 1 { p.put("\u{2500}", border); }
    p.put("\u{2510}", border);
    for r in r0 + 1..r0 + h - 1 {
        abs_text(left(), r, "\u{2502}", border, fill);
        abs_text(left() + w - 1, r, "\u{2502}", border, fill);
    }
    let mut p = Pen::at(0, r0 + h - 1).on(fill);
    p.put("\u{2514}", border);
    for _ in 1..w - 1 { p.put("\u{2500}", border); }
    p.put("\u{2518}", border);
}

// ── Page frame: header bar, stepper, title, footer ───────────────────────────
const STEP_NAMES: [&str; 6] = ["Welcome", "Disk", "Options", "Confirm", "Install", "Done"];

fn chrome(step: usize, title: &str, title_fg: u32, sub: &str, keys: &[(&str, &str)]) {
    framebuffer::clear(BG);
    let c = cols();
    // Header bar
    fill_cells(0, 0, c, 1, BAR_BG);
    let x = abs_text(1, 0, " AETERNA ", BG, ACCENT);
    abs_text(x + 1, 0, "System Installer", FG, BAR_BG);
    let right = format!("ospab.os {}  \u{00B7}  {}", crate::version::VERSION_STR, crate::version::ARCH);
    abs_text(c.saturating_sub(clen(&right) + 2), 0, &right, FG_DIM, BAR_BG);

    // Stepper: ✓ done   [ 3 Current ]   4 future
    let mut segs: Vec<(String, u32, u32)> = Vec::new();
    for (i, name) in STEP_NAMES.iter().enumerate() {
        if i > 0 { segs.push((String::from(" \u{2500}\u{2500} "), RULE, BG)); }
        if i < step       { segs.push((format!("\u{2713} {}", name), FG_OK, BG)); }
        else if i == step { segs.push((format!(" {} {} ", i + 1, name), BG, ACCENT)); }
        else              { segs.push((format!("{} {}", i + 1, name), FG_DIM, BG)); }
    }
    let total: u64 = segs.iter().map(|s| clen(&s.0)).sum();
    let mut p = Pen::at(width().saturating_sub(total) / 2, 2);
    for (s, fg, bg) in &segs { p.bg = *bg; p.put(s, *fg); }
    hrule(3);

    // Title
    t(0, R_TITLE, "\u{2588}", title_fg);
    t(2, R_TITLE, title, title_fg);
    t(2, R_SUB, sub, FG_DIM);

    footer(keys, "");
}

fn footer(keys: &[(&str, &str)], note: &str) {
    let r = rows() - 1;
    fill_cells(0, r, cols(), 1, BAR_BG);
    let mut x = 2;
    for (k, d) in keys {
        x = abs_text(x, r, &format!(" {} ", k), FG_TITLE, KEY_BG);
        x = abs_text(x, r, &format!(" {}    ", d), FG_DIM, BAR_BG);
    }
    if !note.is_empty() { abs_text(x, r, note, FG_DIM, BAR_BG); }
}

// ── Formatting helpers ───────────────────────────────────────────────────────
fn fmt_size(mb: u64) -> String {
    if mb >= 1024 { format!("{}.{} GiB", mb / 1024, (mb % 1024) * 10 / 1024) }
    else { format!("{} MiB", mb) }
}
fn fmt_bytes(b: u64) -> String {
    if b >= 1024 * 1024 { format!("{}.{} MiB", b / (1024 * 1024), (b % (1024 * 1024)) * 10 / (1024 * 1024)) }
    else if b >= 1024 { format!("{} KiB", b / 1024) }
    else { format!("{} B", b) }
}
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return String::from(s); }
    let mut o: String = s.chars().take(max.saturating_sub(1)).collect();
    o.push('\u{2026}');
    o
}

// ── Keyboard ─────────────────────────────────────────────────────────────────
const ESC: char = '\x1B';
const CTRL_C: char = '\x03';
const BKSP: char = '\x08';

fn key() -> char {
    loop { if let Some(c) = keyboard::poll_key() { return c; } }
}
fn drain_keys() { for _ in 0..64 { let _ = keyboard::try_read_key(); } }

/// Inline single-line editor at panel (`col`,`row`), `w` cells wide.
/// Enter accepts, Esc restores the old value.  Returns true if accepted.
fn edit_field(col: u64, row: u64, w: u64, buf: &mut [u8; 32], len: &mut usize,
              mask: bool, allow: fn(char) -> bool) -> bool {
    let saved = (*buf, *len);
    loop {
        let mut p = Pen::at(col, row).on(FIELD_BG);
        p.put(" ", FG);
        for i in 0..*len {
            let ch = if mask { '*' } else { buf[i] as char };
            cell(p.col, row, ch, FG_TITLE, FIELD_BG); p.col += 1;
        }
        p.put("_", ACCENT);
        p.pad(col + w);
        match key() {
            '\n' => return true,
            ESC | CTRL_C => { *buf = saved.0; *len = saved.1; return false; }
            BKSP => { if *len > 0 { *len -= 1; } }
            c if allow(c) && *len < buf.len() - 1 && *len < (w as usize).saturating_sub(3) => {
                buf[*len] = c as u8; *len += 1;
            }
            _ => {}
        }
    }
}
fn host_char(c: char) -> bool { c.is_ascii_alphanumeric() || c == '-' }
fn pass_char(c: char) -> bool { c.is_ascii_graphic() }

// ── Disk abstraction ─────────────────────────────────────────────────────────
/// `index == usize::MAX` → NVMe;  otherwise AHCI/ATA disk index.
#[derive(Clone, Copy)]
struct VDisk {
    index:    usize,
    sectors:  u64,
    size_mb:  u64,
    kind_str: &'static str,
    bus:      &'static str,
    model:    &'static str,
}
impl VDisk {
    fn name(&self) -> &'static str { self.kind_str }
    fn is_nvme(&self) -> bool { self.index == usize::MAX }
    /// NVMe uses "p" before partition number (nvme0n1p1); AHCI uses "" (sda1).
    fn part_sep(&self) -> &'static str { if self.is_nvme() { "p" } else { "" } }
    fn too_small(&self) -> bool { self.sectors < MIN_DISK_SECTORS }
}

/// Smallest disk we accept (100 MiB).
const MIN_DISK_SECTORS: u64 = 204_800;
/// Root partition must leave room for the persistence area (see vfs/disk_sync.rs).
const MIN_ROOT_SECTORS: u64 = 32 * 2048;
const ESP_SIZES: [u64; 4] = [64, 128, 256, 512];
const ESP_DEFAULT: u64 = 256;

fn esp_fits(d: &VDisk, esp_mb: u64) -> bool {
    2048 + esp_mb * 2048 + MIN_ROOT_SECTORS + 34 <= d.sectors
}

fn ahci_dev_name(d: &ospab_os::drivers::DiskInfo) -> &'static str {
    let idx = ospab_os::drivers::disk_info_count_before(d.index, d.kind);
    match d.kind {
        ospab_os::drivers::DiskKind::Ahci => match idx { 0=>"sda",1=>"sdb",2=>"sdc",3=>"sdd",_=>"sdX" },
        ospab_os::drivers::DiskKind::Ata  => match idx { 0=>"hda",1=>"hdb",2=>"hdc",3=>"hdd",_=>"hdX" },
    }
}

fn scan_disks() -> Vec<VDisk> {
    let mut v: Vec<VDisk> = Vec::new();
    if ospab_os::drivers::nvme::is_initialized() {
        let sc = ospab_os::drivers::nvme::sector_count();
        let ss = ospab_os::drivers::nvme::sector_size();
        let mb = (sc as u64).saturating_mul(ss as u64) / (1024 * 1024);
        v.push(VDisk { index: usize::MAX, sectors: sc, size_mb: mb, kind_str: "nvme0n1",
                       bus: "NVMe", model: "NVMe SSD" });
    }
    for i in 0..ospab_os::drivers::disk_count() {
        if let Some(d) = ospab_os::drivers::disk_info(i) {
            let bus = match d.kind {
                ospab_os::drivers::DiskKind::Ahci => "SATA",
                ospab_os::drivers::DiskKind::Ata  => "IDE",
            };
            v.push(VDisk { index: d.index, sectors: d.sectors, size_mb: d.size_mb,
                           kind_str: ahci_dev_name(d), bus,
                           model: ospab_os::drivers::model_str(d).trim() });
        }
    }
    v
}

// ── Progress accounting (driven from disk_write) ─────────────────────────────
static P_DONE: AtomicU64  = AtomicU64::new(0);  // sector writes so far
static P_TOTAL: AtomicU64 = AtomicU64::new(0);  // expected sector writes (0 = no UI)
static P_LAST: AtomicU64  = AtomicU64::new(u64::MAX);
static S_DONE: AtomicU64  = AtomicU64::new(0);  // current step's writes
static S_TOTAL: AtomicU64 = AtomicU64::new(0);  // current step's expected writes (0 = no bar)
static S_ROW: AtomicU64   = AtomicU64::new(0);
static S_LAST: AtomicU64  = AtomicU64::new(u64::MAX);
static WRITE_ERRS: AtomicU64 = AtomicU64::new(0);

// Install-screen layout
const R_STEPS: u64 = 8;
const R_OVR: u64   = 16;
const R_CHECKS: u64 = 19;
const STEP_BAR_COL: u64 = 40;
const STEP_BAR_W: u64   = 14;

fn draw_overall(permille: u64) {
    let w = width();
    pbar(0, R_OVR + 1, w - 7, permille, if permille >= 1000 { FG_OK } else { ACCENT }, true);
    let pct = format!("{:>3}%", permille / 10);
    fill_cells(left() + w - 6, R_OVR + 1, 6, 1, BG);
    t(w - 5, R_OVR + 1, &pct, FG_TITLE);
}

fn progress_tick() {
    let tot = P_TOTAL.load(Ordering::Relaxed);
    if tot == 0 { return; }
    let d = P_DONE.fetch_add(1, Ordering::Relaxed) + 1;
    // Overall bar: redraw when the filled pixel width changes
    let pm = (d * 1000 / tot).min(999);
    let px_w = (width() - 7) * CW;
    if P_LAST.load(Ordering::Relaxed) != pm * px_w / 1000 {
        P_LAST.store(pm * px_w / 1000, Ordering::Relaxed);
        draw_overall(pm);
    }
    // Per-step bar (copy steps)
    let st = S_TOTAL.load(Ordering::Relaxed);
    if st > 0 {
        let sd = S_DONE.fetch_add(1, Ordering::Relaxed) + 1;
        let spm = (sd * 1000 / st).min(1000);
        if S_LAST.load(Ordering::Relaxed) != spm / 10 {
            S_LAST.store(spm / 10, Ordering::Relaxed);
            let r = S_ROW.load(Ordering::Relaxed);
            pbar(STEP_BAR_COL, r, STEP_BAR_W, spm, ACCENT, false);
            fill_cells(left() + STEP_BAR_COL + STEP_BAR_W, r, 5, 1, BG);
            t(STEP_BAR_COL + STEP_BAR_W + 1, r, &format!("{:>3}%", spm / 10), FG);
        }
    }
}

// ── I/O with retry ────────────────────────────────────────────────────────────
fn disk_write(disk: usize, lba: u64, count: u32, data: &[u8]) -> bool {
    let ok = if disk == usize::MAX {
        ospab_os::drivers::nvme::write_sectors(lba, count, data)
    } else {
        let mut ok = false;
        for attempt in 0..3 {
            if ospab_os::drivers::write(disk, lba, count, data) { ok = true; break; }
            if attempt < 2 { for _ in 0..100_000usize { unsafe { core::arch::asm!("pause"); } } }
        }
        ok
    };
    if ok { progress_tick(); }
    else {
        WRITE_ERRS.fetch_add(1, Ordering::Relaxed);
        slog("[INSTALLER] write error at LBA "); slog_dec(lba); slog("\r\n");
    }
    ok
}

fn disk_read(disk: usize, lba: u64, count: u32, buf: &mut [u8]) -> bool {
    if disk == usize::MAX { return ospab_os::drivers::nvme::read_sectors(lba, count, buf); }
    for attempt in 0..3 {
        if ospab_os::drivers::read(disk, lba, count, buf) { return true; }
        if attempt < 2 { for _ in 0..100_000usize { unsafe { core::arch::asm!("pause"); } } }
    }
    false
}

// ── Write-cache flush barrier ─────────────────────────────────────────────────
//
// After writing the GPT and FAT32 structures, we issue a storage write-barrier
// so that UEFI firmware reads consistent sector data on the next power-cycle.
// NVMe : Flush command (opcode 0x00), writes volatile WC to non-volatile store.
// AHCI : ATA FLUSH CACHE EXT (0xEA), same effect for SATA/AHCI drives.
// Also adds a brief pause so the controller settles before we read back.
fn disk_flush(disk: usize) {
    slog("[INSTALLER] Issuing write-cache flush...\r\n");
    if disk == usize::MAX {
        ospab_os::drivers::nvme::flush();
    } else {
        ospab_os::drivers::ahci::flush_cache(disk);
    }
    // Short stall to let the controller drain its internal pipeline
    for _ in 0..500_000usize { unsafe { core::arch::asm!("pause"); } }
    slog("[INSTALLER] Flush done\r\n");
}

// ── Binary sources from Limine boot modules ───────────────────────────────────
fn get_limine_efi_binary() -> (&'static [u8], usize) {
    use ospab_os::arch::x86_64::boot;
    // Pass 1: by name
    if let Some(mut mods) = boot::modules() {
        while let Some(m) = mods.next() {
            let path = unsafe {
                if m.path.is_null() { continue; }
                let mut len = 0;
                while *m.path.add(len) != 0 { len += 1; }
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(m.path as *const u8, len))
            };
            if path.contains("BOOTX64") || path.contains("bootx64") || path.contains("limine") {
                let size = m.size as usize;
                slog("[INSTALLER] Limine EFI: "); slog(path); slog("\r\n");
                return (unsafe { core::slice::from_raw_parts(m.address, size) }, size);
            }
        }
    }
    // Pass 2: by MZ signature
    if let Some(mut mods) = boot::modules() {
        while let Some(m) = mods.next() {
            let size = m.size as usize;
            if size >= 2 {
                let data = unsafe { core::slice::from_raw_parts(m.address, size) };
                if data[0] == b'M' && data[1] == b'Z' {
                    slog("[INSTALLER] Limine EFI: MZ match\r\n");
                    return (data, size);
                }
            }
        }
    }
    slog("[INSTALLER] No Limine EFI module\r\n");
    (&[], 0)
}

fn get_kernel_binary() -> (&'static [u8], usize) {
    use ospab_os::arch::x86_64::boot;
    if let Some(mut mods) = boot::modules() {
        while let Some(m) = mods.next() {
            let path = unsafe {
                if m.path.is_null() { continue; }
                let mut len = 0;
                while *m.path.add(len) != 0 { len += 1; }
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(m.path as *const u8, len))
            };
            if path.contains("aeterna") || path.contains("ospab")
                || path.contains("KERNEL") || path.contains("kernel")
            {
                let size = m.size as usize;
                slog("[INSTALLER] Kernel: "); slog(path); slog("\r\n");
                return (unsafe { core::slice::from_raw_parts(m.address, size) }, size);
            }
        }
    }
    slog("[INSTALLER] No kernel module\r\n");
    (&[], 0)
}

fn slog(s: &str) { serial::write_str(s); }
fn slog_dec(mut v: u64) {
    if v == 0 { serial::write_byte(b'0'); return; }
    let mut b = [0u8; 20]; let mut i = 0;
    while v > 0 { b[i] = b'0' + (v % 10) as u8; v /= 10; i += 1; }
    for j in (0..i).rev() { serial::write_byte(b[j]); }
}
fn slog_hex32(v: u32) {
    const HEX: &[u8] = b"0123456789abcdef";
    serial::write_str("0x");
    for i in (0..8).rev() { serial::write_byte(HEX[((v >> (i * 4)) & 0xF) as usize]); }
}

// ── GPT ───────────────────────────────────────────────────────────────────────
const ESP_GUID:  [u8; 16] = [0x28,0x73,0x2A,0xC1,0x1F,0xF8,0xD2,0x11,0xBA,0x4B,0x00,0xA0,0xC9,0x3E,0xC9,0x3B];
const LINUX_GUID:[u8; 16] = [0xAF,0x3D,0xC6,0x0F,0x83,0x84,0x72,0x47,0x8E,0x79,0x3D,0x69,0xD8,0x47,0x7D,0xE4];

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data { crc ^= b as u32; for _ in 0..8 { crc = if crc & 1 != 0 { (crc>>1)^0xEDB8_8320 } else { crc>>1 }; } }
    !crc
}
fn make_uuid(a: u64, b: u64) -> [u8; 16] {
    let mut u = [0u8; 16];
    let x = a.wrapping_mul(0x5DEECE66D).wrapping_add(b) ^ 0xAE05AE05AE05AE05;
    let y = x.wrapping_mul(0x6C078965).wrapping_add(1);
    u[0..8].copy_from_slice(&x.to_le_bytes()); u[8..16].copy_from_slice(&y.to_le_bytes());
    u[6] = (u[6]&0x0F)|0x40; u[8] = (u[8]&0x3F)|0x80; u
}
fn w16(buf: &mut [u8], o: usize, v: u16) { buf[o..o+2].copy_from_slice(&v.to_le_bytes()); }
fn w32(buf: &mut [u8], o: usize, v: u32) { buf[o..o+4].copy_from_slice(&v.to_le_bytes()); }
fn w64(buf: &mut [u8], o: usize, v: u64) { buf[o..o+8].copy_from_slice(&v.to_le_bytes()); }

// ════════════════════════════════════════════════════════════════════════════
// Wizard state + pages
// ════════════════════════════════════════════════════════════════════════════
const LOCALES: &[&str] = &["en_US.UTF-8","ru_RU.UTF-8","de_DE.UTF-8","fr_FR.UTF-8","zh_CN.UTF-8"];

struct Config {
    disk:     Option<usize>,
    esp_mb:   u64,
    host:     [u8; 32],
    host_len: usize,
    pass:     [u8; 32],
    pass_len: usize,
    locale:   usize,
}
impl Config {
    fn hostname(&self) -> &str { core::str::from_utf8(&self.host[..self.host_len]).unwrap_or("aeterna") }
}

struct Images { efi: &'static [u8], kernel: &'static [u8] }

enum Nav { Next, Back, Quit }

#[derive(Clone, Copy)]
enum Page { Welcome, Disk, Options, Confirm }

// ════════════════════════════════════════════════════════════════════════════
// Main entry point
// ════════════════════════════════════════════════════════════════════════════
pub fn run() {
    geom_init();
    P_TOTAL.store(0, Ordering::Relaxed);
    S_TOTAL.store(0, Ordering::Relaxed);
    slog("[INSTALLER] started\r\n");

    let disks = scan_disks();
    let (efi, _) = get_limine_efi_binary();
    let (kernel, _) = get_kernel_binary();
    let img = Images { efi, kernel };

    let mut cfg = Config {
        disk: None, esp_mb: ESP_DEFAULT,
        host: [0u8; 32], host_len: 0,
        pass: [0u8; 32], pass_len: 0,
        locale: 0,
    };
    cfg.host[..7].copy_from_slice(b"aeterna"); cfg.host_len = 7;

    let mut page = Page::Welcome;
    loop {
        let nav = match page {
            Page::Welcome => page_welcome(&disks, &img),
            Page::Disk    => page_disk(&disks, &mut cfg),
            Page::Options => page_options(&disks, &mut cfg),
            Page::Confirm => page_confirm(&disks, &cfg, &img),
        };
        page = match (page, nav) {
            (_, Nav::Quit) => { cancelled(); return; }
            (Page::Welcome, Nav::Next) => Page::Disk,
            (Page::Welcome, Nav::Back) => { cancelled(); return; }
            (Page::Disk, Nav::Next)    => Page::Options,
            (Page::Disk, Nav::Back)    => Page::Welcome,
            (Page::Options, Nav::Next) => Page::Confirm,
            (Page::Options, Nav::Back) => Page::Disk,
            (Page::Confirm, Nav::Back) => Page::Options,
            (Page::Confirm, Nav::Next) => {
                let d = disks[cfg.disk.unwrap_or(0)];
                do_install(d, &cfg, &img);
                leave();
                return;
            }
        };
    }
}

fn leave() {
    P_TOTAL.store(0, Ordering::Relaxed);
    S_TOTAL.store(0, Ordering::Relaxed);
    framebuffer::clear(0); framebuffer::set_cursor_pos(0, 0);
}

fn cancelled() {
    slog("[INSTALLER] cancelled, nothing written\r\n");
    leave();
    framebuffer::draw_string("install: cancelled \u{2014} no changes were made to any disk.\n", FG_DIM, 0);
}

fn check_line(row: u64, ok: bool, label: &str, detail: &str) {
    let mut p = Pen::at(4, row);
    if ok { p.put("\u{2713}", FG_OK); } else { p.put("\u{2717}", FG_ERR); }
    p.put("  ", FG).put(label, FG).pad(30);
    p.put(detail, if ok { FG_DIM } else { FG_ERR });
}

// ── 1. Welcome ───────────────────────────────────────────────────────────────
fn page_welcome(disks: &[VDisk], img: &Images) -> Nav {
    slog("[INSTALLER] page: welcome\r\n");
    let usable = disks.iter().filter(|d| !d.too_small()).count();
    let ready = !img.efi.is_empty() && !img.kernel.is_empty() && usable > 0;
    let keys: &[(&str, &str)] = if ready { &[("Enter", "Begin"), ("Esc", "Quit")] } else { &[("Esc", "Quit")] };
    chrome(0, "Welcome to AETERNA", FG_TITLE, "This wizard installs ospab.os onto a disk in this computer.", keys);

    t(2, R_BODY, "The installer will:", FG);
    t(4, R_BODY + 1, "\u{2022}  create a new GPT partition table on the disk you choose", FG_DIM);
    t(4, R_BODY + 2, "\u{2022}  format an EFI System Partition (FAT32) for the bootloader", FG_DIM);
    t(4, R_BODY + 3, "\u{2022}  copy the Limine UEFI loader and the AETERNA kernel", FG_DIM);
    t(4, R_BODY + 4, "\u{2022}  read everything back to verify it", FG_DIM);

    t(2, R_BODY + 6, "System check", FG_TITLE);
    check_line(R_BODY + 7, !img.kernel.is_empty(), "Kernel image",
        &if img.kernel.is_empty() { String::from("not found \u{2014} boot the live ISO") } else { fmt_bytes(img.kernel.len() as u64) });
    check_line(R_BODY + 8, !img.efi.is_empty(), "Limine UEFI loader",
        &if img.efi.is_empty() { String::from("not found \u{2014} boot the live ISO") } else { fmt_bytes(img.efi.len() as u64) });
    check_line(R_BODY + 9, usable > 0, "Storage devices",
        &if disks.is_empty() { String::from("no disks detected") }
         else if usable == 0 { String::from("all disks are smaller than 100 MiB") }
         else { format!("{} found", disks.len()) });

    if ready {
        t(2, R_BODY + 12, "Nothing is written to disk until you confirm on the Confirm page.", FG_DIM);
        t(2, R_BODY + 13, "Press Enter to begin, or Esc to leave the installer.", FG);
    } else {
        draw_box(R_BODY + 11, 4, FG_ERR, ERR_BG, "Cannot install");
        Pen::at(3, R_BODY + 12).on(ERR_BG).put("The checks above must all pass. Start the installer from the", FG);
        Pen::at(3, R_BODY + 13).on(ERR_BG).put("ospab.os live ISO with a disk of at least 100 MiB attached.", FG);
    }

    loop {
        match key() {
            '\n' if ready => return Nav::Next,
            ESC | CTRL_C | 'q' | 'Q' => return Nav::Quit,
            _ => {}
        }
    }
}

// ── 2. Choose disk ───────────────────────────────────────────────────────────
fn page_disk(disks: &[VDisk], cfg: &mut Config) -> Nav {
    slog("[INSTALLER] page: disk\r\n");
    let mut sel = cfg.disk.unwrap_or(0).min(disks.len().saturating_sub(1));
    let mut msg: Option<String> = None;
    chrome(1, "Choose the target disk", FG_TITLE,
           "The whole disk is used. Everything on it will be erased.",
           &[("\u{2191}\u{2193}", "Select"), ("Enter", "Use this disk"), ("Esc", "Back"), ("Q", "Quit")]);
    Pen::at(2, R_BODY).put("DEVICE", FG_DIM).pad(18).put("SIZE", FG_DIM).pad(30).put("BUS", FG_DIM).pad(38).put("MODEL", FG_DIM);
    hrule(R_BODY + 1);
    loop {
        for (i, d) in disks.iter().enumerate() {
            let r = R_BODY + 2 + i as u64;
            let bg = if i == sel { SEL_BG } else { BG };
            let fg = if d.too_small() { FG_DIM } else { FG };
            let mut p = Pen::at(0, r).on(bg);
            p.put(if i == sel { "\u{25B6} " } else { "  " }, ACCENT);
            p.put("/dev/", FG_DIM).put(d.name(), if i == sel { FG_TITLE } else { fg }).pad(18);
            p.put(&fmt_size(d.size_mb), fg).pad(30);
            p.put(d.bus, FG_DIM).pad(38);
            if d.too_small() { p.put("too small (min 100 MiB)", FG_ERR); }
            else { p.put(&truncate(if d.model.is_empty() { "(unknown model)" } else { d.model }, (width() - 40) as usize), fg); }
            p.pad(width());
        }
        let mr = R_BODY + 3 + disks.len() as u64;
        clear_panel_row(mr);
        if let Some(m) = &msg { t(2, mr, m, FG_ERR); }

        match key() {
            keyboard::KEY_UP   => { sel = if sel == 0 { disks.len() - 1 } else { sel - 1 }; msg = None; }
            keyboard::KEY_DOWN => { sel = (sel + 1) % disks.len(); msg = None; }
            '\n' => {
                let d = &disks[sel];
                if d.too_small() {
                    msg = Some(format!("/dev/{} is too small \u{2014} at least 100 MiB is required.", d.name()));
                } else {
                    cfg.disk = Some(sel);
                    if !esp_fits(d, cfg.esp_mb) {
                        cfg.esp_mb = ESP_SIZES.iter().rev().copied()
                            .find(|&e| e <= ESP_DEFAULT && esp_fits(d, e)).unwrap_or(ESP_SIZES[0]);
                    }
                    return Nav::Next;
                }
            }
            ESC => return Nav::Back,
            CTRL_C | 'q' | 'Q' => return Nav::Quit,
            _ => {}
        }
    }
}

// ── 3. Options ───────────────────────────────────────────────────────────────
fn page_options(disks: &[VDisk], cfg: &mut Config) -> Nav {
    slog("[INSTALLER] page: options\r\n");
    let d = disks[cfg.disk.unwrap_or(0)];
    const N: usize = 5; // ESP, hostname, password, locale, Continue
    let mut cur = 0usize;
    let mut msg: Option<&str> = None;
    chrome(2, "Installation options", FG_TITLE,
           "Defaults are fine for most systems.",
           &[("\u{2191}\u{2193}", "Move"), ("\u{2190}\u{2192}", "Change"), ("Enter", "Edit / Continue"), ("Esc", "Back")]);
    loop {
        let row_of = |i: usize| R_BODY + i as u64 + if i == 4 { 1 } else { 0 };
        for i in 0..N {
            let r = row_of(i);
            let selb = i == cur;
            let bg = if selb { SEL_BG } else { BG };
            if i == 4 {
                clear_panel_row(r);
                let mut p = Pen::at(2, r).on(if selb { ACCENT } else { KEY_BG });
                p.put("  Continue \u{2192}  ", if selb { BG } else { FG });
                continue;
            }
            let mut p = Pen::at(0, r).on(bg);
            p.put(if selb { "\u{25B6} " } else { "  " }, ACCENT);
            let (label, hint) = match i {
                0 => ("EFI partition size", "\u{2190} \u{2192}"),
                1 => ("Hostname", "Enter to edit"),
                2 => ("Root password", "Enter to edit"),
                _ => ("Locale", "\u{2190} \u{2192}"),
            };
            p.put(label, if selb { FG_TITLE } else { FG }).pad(24);
            match i {
                0 => { p.put(&fmt_size(cfg.esp_mb), FG_TITLE);
                       if cfg.esp_mb == ESP_DEFAULT { p.put("  (recommended)", FG_OK); } }
                1 => { p.put(cfg.hostname(), FG_TITLE); }
                2 => { if cfg.pass_len == 0 { p.put("(none)", FG_DIM); }
                       else { for _ in 0..cfg.pass_len { p.put("*", FG_TITLE); } } }
                _ => { p.put(LOCALES[cfg.locale], FG_TITLE); }
            }
            p.pad(58);
            if selb { p.put(hint, FG_DIM); }
            p.pad(width());
        }

        // Disk layout preview
        let lr = R_BODY + 8;
        let esp_s = cfg.esp_mb * 2048;
        let root_s = d.sectors.saturating_sub(2048 + esp_s + 34);
        clear_panel_row(lr);
        Pen::at(2, lr).put("Disk layout", FG_TITLE).put("   /dev/", FG_DIM).put(d.name(), FG).put("  ", FG).put(&fmt_size(d.size_mb), FG_DIM);
        let bw = width() - 4;
        let esp_cells = ((bw * esp_s) / d.sectors.max(1)).max(2).min(bw - 2);
        let x = (left() + 2) * CW;
        let y = (lr + 1) * CH;
        framebuffer::fill_rect(x, y, bw * CW, CH, BG);
        framebuffer::fill_rect(x, y + 2, esp_cells * CW - 2, CH - 4, ESP_COL);
        framebuffer::fill_rect(x + esp_cells * CW, y + 2, (bw - esp_cells) * CW, CH - 4, ROOT_COL);
        clear_panel_row(lr + 2);
        Pen::at(2, lr + 2).put("\u{2588}", ESP_COL).put(" EFI System (FAT32)  ", FG).put(&fmt_size(cfg.esp_mb), FG_DIM)
            .put("      ", FG).put("\u{2588}", ROOT_COL).put(" AETERNA root  ", FG).put(&fmt_size(root_s / 2048), FG_DIM);
        clear_panel_row(lr + 4);
        if let Some(m) = msg { t(2, lr + 4, m, FG_ERR); }
        else if cur == 2 { t(2, lr + 4, "Note: the password is not yet used by this release of AETERNA.", FG_DIM); }

        let k = key();
        msg = None;
        let cycle = |cfg: &mut Config, fwd: bool| {
            let fits: Vec<u64> = ESP_SIZES.iter().copied().filter(|&e| esp_fits(&d, e)).collect();
            if fits.is_empty() { return; }
            let pos = fits.iter().position(|&e| e == cfg.esp_mb).unwrap_or(0);
            let n = fits.len();
            cfg.esp_mb = fits[if fwd { (pos + 1) % n } else { (pos + n - 1) % n }];
        };
        match k {
            keyboard::KEY_UP   => { cur = if cur == 0 { N - 1 } else { cur - 1 }; }
            keyboard::KEY_DOWN | '\t' => { cur = (cur + 1) % N; }
            keyboard::KEY_LEFT | keyboard::KEY_RIGHT => {
                let fwd = k == keyboard::KEY_RIGHT;
                match cur {
                    0 => cycle(cfg, fwd),
                    3 => { let n = LOCALES.len(); cfg.locale = if fwd { (cfg.locale + 1) % n } else { (cfg.locale + n - 1) % n }; }
                    _ => {}
                }
            }
            '\n' => match cur {
                0 => cycle(cfg, true),
                1 => {
                    let r = row_of(1);
                    if edit_field(24, r, 34, &mut cfg.host, &mut cfg.host_len, false, host_char) && cfg.host_len == 0 {
                        cfg.host[..7].copy_from_slice(b"aeterna"); cfg.host_len = 7;
                    }
                }
                2 => { let r = row_of(2); edit_field(24, r, 34, &mut cfg.pass, &mut cfg.pass_len, true, pass_char); }
                3 => { cfg.locale = (cfg.locale + 1) % LOCALES.len(); }
                _ => {
                    if !esp_fits(&d, cfg.esp_mb) { msg = Some("The EFI partition does not fit on this disk."); }
                    else { return Nav::Next; }
                }
            },
            ESC => return Nav::Back,
            CTRL_C | 'q' | 'Q' => return Nav::Quit,
            _ => {}
        }
    }
}

// ── 4. Confirm ───────────────────────────────────────────────────────────────
struct Layout { esp_start: u64, esp_end: u64, root_start: u64, root_end: u64, root_mb: u64 }
fn layout(d: &VDisk, esp_mb: u64) -> Layout {
    let esp_start = 2048;
    let esp_end = esp_start + esp_mb * 2048 - 1;
    let root_start = esp_end + 1;
    let root_end = d.sectors.saturating_sub(34);
    Layout { esp_start, esp_end, root_start, root_end,
             root_mb: (root_end.saturating_sub(root_start) + 1) / 2048 }
}

fn kv(row: u64, k: &str, v: &str, fg: u32) {
    Pen::at(2, row).put(k, FG_DIM).pad(18).put(v, fg);
}

fn page_confirm(disks: &[VDisk], cfg: &Config, img: &Images) -> Nav {
    slog("[INSTALLER] page: confirm\r\n");
    let d = disks[cfg.disk.unwrap_or(0)];
    let l = layout(&d, cfg.esp_mb);
    chrome(3, "Review and confirm", FG_TITLE, "Please check the plan. Nothing has been written yet.",
           &[("Enter", "Install"), ("Esc", "Back")]);

    let model = if d.model.is_empty() { d.bus } else { d.model };
    kv(R_BODY,     "Target disk", &format!("/dev/{}   {}   {}", d.name(), fmt_size(d.size_mb), truncate(model, 30)), FG_TITLE);
    kv(R_BODY + 1, "Partition 1", &format!("EFI System (FAT32)   {:<9}  LBA {}\u{2013}{}", fmt_size(cfg.esp_mb), l.esp_start, l.esp_end), FG);
    kv(R_BODY + 2, "Partition 2", &format!("AETERNA root         {:<9}  LBA {}\u{2013}{}", fmt_size(l.root_mb), l.root_start, l.root_end), FG);
    kv(R_BODY + 3, "Bootloader",  &format!("Limine UEFI \u{2192} /EFI/BOOT/BOOTX64.EFI  ({})", fmt_bytes(img.efi.len() as u64)), FG);
    kv(R_BODY + 4, "Kernel",      &format!("AETERNA {} \u{2192} /boot/KERNEL  ({})", crate::version::VERSION_STR, fmt_bytes(img.kernel.len() as u64)), FG);
    kv(R_BODY + 5, "Hostname",    cfg.hostname(), FG);
    kv(R_BODY + 6, "Locale",      LOCALES[cfg.locale], FG);

    let br = R_BODY + 8;
    draw_box(br, 4, FG_ERR, ERR_BG, "WARNING");
    Pen::at(3, br + 1).on(ERR_BG).put(&format!("ALL DATA ON /dev/{} ({}) WILL BE PERMANENTLY ERASED.", d.name(), fmt_size(d.size_mb)), FG_ERR);
    Pen::at(3, br + 2).on(ERR_BG).put("Existing partitions and files on this disk cannot be recovered.", FG);

    let pr = br + 5;
    Pen::at(2, pr).put("Type ", FG).put("yes", FG_TITLE).put(" and press Enter to install:", FG);
    drain_keys();
    let mut buf = [0u8; 8];
    let mut len = 0usize;
    let mut msg = false;
    loop {
        let mut p = Pen::at(40, pr).on(FIELD_BG);
        p.put(" ", FG);
        for i in 0..len { cell(p.col, pr, buf[i] as char, FG_TITLE, FIELD_BG); p.col += 1; }
        p.put("_", ACCENT).pad(50);
        clear_panel_row(pr + 2);
        if msg { t(2, pr + 2, "Type yes to erase the disk and install, or press Esc to go back.", FG_ERR); }
        match key() {
            '\n' => {
                if &buf[..len] == b"yes" || &buf[..len] == b"YES" || &buf[..len] == b"Yes" {
                    slog("[INSTALLER] confirmed\r\n");
                    return Nav::Next;
                }
                msg = true;
            }
            ESC => return Nav::Back,
            CTRL_C => return Nav::Quit,
            BKSP => { if len > 0 { len -= 1; } }
            c if c.is_ascii_alphabetic() && len < 6 => { buf[len] = c as u8; len += 1; msg = false; }
            _ => {}
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 5. Install — writes everything to disk
// ════════════════════════════════════════════════════════════════════════════
const STEP_LABELS: [&str; 7] = [
    "Creating partition table (GPT)",
    "Formatting EFI partition (FAT32)",
    "Creating directories",
    "Copying bootloader",
    "Copying kernel",
    "Writing boot config + identity",
    "Verifying installation",
];

#[derive(Clone, Copy, PartialEq)]
enum St { Pending, Running, Ok, Warn, Fail }

fn step_draw(i: usize, st: St, detail: &str) {
    let r = R_STEPS + i as u64;
    clear_panel_row(r);
    let (icon, ic, lc, status, sc) = match st {
        St::Pending => ("\u{00B7}", FG_DIM, FG_DIM, "",        FG_DIM),
        St::Running => ("\u{25B6}", ACCENT, FG_TITLE, "\u{2026}", ACCENT),
        St::Ok      => ("\u{2713}", FG_OK,  FG,     "OK",      FG_OK),
        St::Warn    => ("!",        FG_WARN, FG,    "WARN",    FG_WARN),
        St::Fail    => ("\u{2717}", FG_ERR, FG_ERR, "FAILED",  FG_ERR),
    };
    t(2, r, icon, ic);
    t(4, r, STEP_LABELS[i], lc);
    if !detail.is_empty() { t(STEP_BAR_COL, r, detail, if st == St::Fail { FG_ERR } else { FG_DIM }); }
    t(width() - clen(status) - 1, r, status, sc);
    slog("[INSTALLER] step "); slog_dec(i as u64 + 1);
    slog(match st { St::Pending => " pending", St::Running => " running", St::Ok => " ok",
                    St::Warn => " warn", St::Fail => " FAILED" });
    slog("\r\n");
}

/// Start a step; `writes` > 0 shows an inline per-step progress bar.
fn step_begin(i: usize, writes: u64) {
    step_draw(i, St::Running, "");
    S_DONE.store(0, Ordering::Relaxed);
    S_LAST.store(u64::MAX, Ordering::Relaxed);
    S_ROW.store(R_STEPS + i as u64, Ordering::Relaxed);
    S_TOTAL.store(writes, Ordering::Relaxed);
}
fn step_end(i: usize, st: St, detail: &str) {
    S_TOTAL.store(0, Ordering::Relaxed);
    step_draw(i, st, detail);
}

/// Red failure box + wait; the caller returns to the shell afterwards.
fn install_failed(i: usize, why: &str) {
    step_end(i, St::Fail, why);
    footer(&[("Enter", "Return to shell")], "");
    let r = R_CHECKS;
    draw_box(r, 6, FG_ERR, ERR_BG, "Installation failed");
    Pen::at(3, r + 1).on(ERR_BG).put(&format!("Step {} of {}: ", i + 1, STEP_LABELS.len()), FG_DIM).put(why, FG_ERR);
    Pen::at(3, r + 2).on(ERR_BG).put("The disk was only partly written and will not boot.", FG);
    Pen::at(3, r + 3).on(ERR_BG).put("Check the disk / VM settings and run `install` again.", FG);
    Pen::at(3, r + 4).on(ERR_BG).put("Details were logged to the serial console (COM1).", FG_DIM);
    drain_keys();
    loop { if key() == '\n' { break; } }
}

/// Verification results (label, passed).
struct Check { label: &'static str, ok: bool }

fn draw_checks(row: u64, checks: &[Check]) {
    for (i, c) in checks.iter().enumerate() {
        let r = row + (i / 2) as u64;
        let col = if i % 2 == 0 { 4 } else { 40 };
        let mut p = Pen::at(col, r);
        if c.ok { p.put("\u{2713} ", FG_OK); } else { p.put("\u{2717} ", FG_ERR); }
        p.put(c.label, if c.ok { FG } else { FG_ERR });
    }
}

fn do_install(disk: VDisk, cfg: &Config, img: &Images) {
    let esp_size_mb = cfg.esp_mb;
    let hostname = &cfg.host[..cfg.host_len];
    let locale = LOCALES[cfg.locale];
    let (efi_data, efi_size) = (img.efi, img.efi.len());
    let (kernel_data, kernel_size) = (img.kernel, img.kernel.len());

    // ── Layout ────────────────────────────────────────────────────────────
    let Layout { esp_start, esp_end, root_start, root_end, root_mb } = layout(&disk, esp_size_mb);
    let esp_sectors: u64 = esp_size_mb * 2048; // 512-byte sectors

    slog("[INSTALLER] /dev/"); slog(disk.name()); slog("\r\n");
    slog("[INSTALLER] EFI=");   slog_dec(efi_size as u64);    slog("B kernel=");
    slog_dec(kernel_size as u64); slog("B\r\n");

    // ── Screen ────────────────────────────────────────────────────────────
    chrome(4, "Installing AETERNA", FG_TITLE,
           &format!("Writing to /dev/{} \u{2014} do not power off or remove the disk.", disk.name()), &[]);
    footer(&[], "Installing\u{2026} please wait");
    for i in 0..STEP_LABELS.len() { step_draw(i, St::Pending, ""); }
    t(2, R_OVR, "Overall progress", FG_DIM);
    WRITE_ERRS.store(0, Ordering::Relaxed);

    // ── FAT32 geometry (needed up front for the progress estimate) ────────
    //
    // EDK2/Tianocore (VMware UEFI) determines FAT type by cluster count:
    //   CountOfClusters < 65525  →  FAT16  (WRONG for us → "No Media")
    //   CountOfClusters ≥ 65525  →  FAT32  (correct)
    //
    // So we MUST choose SPC (sectors-per-cluster) small enough to push
    // the cluster count above 65525.  For 256 MiB ESP, SPC=8 gives only
    // ~65400 clusters (< 65525) → EDK2 misidentifies as FAT16 → corrupt.
    //
    // We use the Microsoft FAT specification formula for FATSz:
    //   TmpVal1 = DskSize - BPB_RsvdSecCnt
    //   TmpVal2 = 256 * BPB_SecPerClus + BPB_NumFATs
    //   FATSz   = ceil(TmpVal1 / TmpVal2)
    const RSVD: u16 = 32;
    const NFAT: u8  = 2;
    let fat32_total = esp_sectors as u32;

    // Pick SPC so that data_clusters ≥ 65600 (safe margin above 65525)
    let spc: u8 = {
        let mut s: u32 = 8;
        loop {
            let tmp2 = 256 * s + NFAT as u32;
            let fsz  = (fat32_total - RSVD as u32 + tmp2 - 1) / tmp2;
            let drel = RSVD as u32 + fsz * NFAT as u32;
            let dcls = (fat32_total.saturating_sub(drel)) / s;
            if dcls >= 65600 || s == 1 { break; }
            s /= 2;
        }
        s as u8
    };

    let tmp1    = fat32_total - RSVD as u32;
    let tmp2    = 256u32 * spc as u32 + NFAT as u32;
    let fat_sec = (tmp1 + tmp2 - 1) / tmp2;
    let data_rel = RSVD as u32 + fat_sec * NFAT as u32;
    let data_clusters = (fat32_total - data_rel) / spc as u32;

    let cb = spc as usize * 512; // bytes per cluster
    let efi_nc = if efi_size > 0 { ((efi_size + cb - 1) / cb) as u32 } else { 1 };
    let ker_nc = if kernel_size > 0 { ((kernel_size + cb - 1) / cb) as u32 } else { 1 };
    let efi_w = ((efi_size + 511) / 512) as u64 + 2 * efi_nc as u64;
    let ker_w = ((kernel_size + 511) / 512) as u64 + 2 * ker_nc as u64;
    let conf_content = build_limine_conf();

    // Expected sector writes, mirrors the write sequence below
    let total_writes: u64 = 1 + 64 + 2                       // MBR, entries + backup, headers
        + 4 + 2 * fat_sec as u64 + 2                         // VBR/FSInfo + backups, FATs
        + 4 * spc as u64 + 4 + 8                             // dir clusters, dirs, dir chains
        + efi_w + ker_w
        + 2 + ((conf_content.len() as u64 + 511) / 512).max(1)
        + 1;                                                 // identity
    P_DONE.store(0, Ordering::Relaxed);
    P_LAST.store(u64::MAX, Ordering::Relaxed);
    P_TOTAL.store(total_writes, Ordering::Relaxed);
    draw_overall(0);

    macro_rules! die {
        ($i:expr, $msg:expr) => {{ install_failed($i, $msg); return; }}
    }

    // ══════════════════════════════════════════════════════════════════════
    // 1 — Partition table: protective MBR, GPT entries, GPT headers
    step_begin(0, 0);
    slog("[INSTALLER] Step 1: Protective MBR\r\n");
    {
        let mut mbr = [0u8; 512];
        mbr[446]=0; mbr[447]=0; mbr[448]=2; mbr[449]=0; mbr[450]=0xEE;
        mbr[451]=0xFF; mbr[452]=0xFF; mbr[453]=0xFF;
        w32(&mut mbr, 454, 1);
        w32(&mut mbr, 458, (disk.sectors - 1).min(0xFFFF_FFFF) as u32);
        mbr[510]=0x55; mbr[511]=0xAA;
        if !disk_write(disk.index, 0, 1, &mbr) { die!(0, "cannot write the MBR (sector 0)"); }
    }
    slog("[INSTALLER] MBR OK\r\n");

    slog("[INSTALLER] Step 2: GPT partition entries\r\n");
    let disk_guid = make_uuid(disk.index as u64 * 3, 0xFF);
    let esp_guid  = make_uuid(disk.index as u64 * 3, 0);
    let root_guid = make_uuid(disk.index as u64 * 3, 1);
    let mut entries = [0u8; 32 * 512];
    {
        let e = &mut entries[0..128];
        e[0..16].copy_from_slice(&ESP_GUID); e[16..32].copy_from_slice(&esp_guid);
        w64(e,32,esp_start); w64(e,40,esp_end); w64(e,48,0);
        for (i,c) in "EFI System".chars().enumerate() { if 56+i*2+1<128 { w16(e,56+i*2,c as u16); } }
    }
    {
        let e = &mut entries[128..256];
        e[0..16].copy_from_slice(&LINUX_GUID); e[16..32].copy_from_slice(&root_guid);
        w64(e,32,root_start); w64(e,40,root_end); w64(e,48,0);
        for (i,c) in "AETERNA".chars().enumerate() { if 56+i*2+1<128 { w16(e,56+i*2,c as u16); } }
    }
    let entries_crc = crc32(&entries);
    let bak_entries_lba = disk.sectors - 33;
    slog("  ESP: LBA "); slog_dec(esp_start); slog(".."); slog_dec(esp_end); slog("\r\n");
    slog("  ROOT: LBA "); slog_dec(root_start); slog(".."); slog_dec(root_end); slog("\r\n");
    slog("  entries_crc="); slog_hex32(entries_crc); slog("\r\n");
    for s in 0u64..32 {
        let o = (s as usize)*512;
        if !disk_write(disk.index, 2+s, 1, &entries[o..o+512]) { die!(0, "cannot write the GPT partition entries"); }
    }
    let errs_before_backup = WRITE_ERRS.load(Ordering::Relaxed);
    for s in 0u64..32 { let o=(s as usize)*512; disk_write(disk.index,bak_entries_lba+s,1,&entries[o..o+512]); }
    slog("[INSTALLER] GPT entries OK (backup LBA "); slog_dec(bak_entries_lba); slog(")\r\n");

    slog("[INSTALLER] Step 3: GPT headers\r\n");
    {
        let mut hdr = [0u8; 512];
        hdr[0..8].copy_from_slice(b"EFI PART");
        w32(&mut hdr,8,0x00010000); w32(&mut hdr,12,92); w32(&mut hdr,16,0); w32(&mut hdr,20,0);
        w64(&mut hdr,24,1); w64(&mut hdr,32,disk.sectors-1);
        w64(&mut hdr,40,34); w64(&mut hdr,48,disk.sectors-34);
        hdr[56..72].copy_from_slice(&disk_guid);
        w64(&mut hdr,72,2); w32(&mut hdr,80,128); w32(&mut hdr,84,128); w32(&mut hdr,88,entries_crc);
        let hcrc = crc32(&hdr[..92]); w32(&mut hdr,16,hcrc);
        slog("  primary hdr CRC="); slog_hex32(hcrc); slog("\r\n");
        if !disk_write(disk.index,1,1,&hdr) { die!(0, "cannot write the primary GPT header"); }
        // Backup
        w32(&mut hdr,16,0);
        w64(&mut hdr,24,disk.sectors-1); w64(&mut hdr,32,1); w64(&mut hdr,72,bak_entries_lba);
        let bcrc = crc32(&hdr[..92]); w32(&mut hdr,16,bcrc);
        slog("  backup  hdr CRC="); slog_hex32(bcrc); slog("\r\n");
        disk_write(disk.index,disk.sectors-1,1,&hdr);
    }
    // Flush write-cache so the UEFI firmware reads back committed data on boot
    slog("[INSTALLER] Flushing write-cache after GPT...\r\n");
    disk_flush(disk.index);
    let backup_ok = WRITE_ERRS.load(Ordering::Relaxed) == errs_before_backup;
    if backup_ok { step_end(0, St::Ok, "2 partitions"); }
    else { step_end(0, St::Warn, "backup GPT not written"); }

    // ══════════════════════════════════════════════════════════════════════
    // 2 — FAT32 ESP  BPB + FAT tables
    step_begin(1, 4 + 2 * fat_sec as u64 + 2);
    let errs0 = WRITE_ERRS.load(Ordering::Relaxed);

    slog("[INSTALLER] FAT32 geometry:\r\n");
    slog("  total_sectors="); slog_dec(fat32_total as u64);
    slog("  SPC="); slog_dec(spc as u64);
    slog("  RSVD="); slog_dec(RSVD as u64);
    slog("  NFAT="); slog_dec(NFAT as u64); slog("\r\n");
    slog("  fat_sec="); slog_dec(fat_sec as u64);
    slog("  data_rel="); slog_dec(data_rel as u64);
    slog("  data_clusters="); slog_dec(data_clusters as u64);
    if data_clusters >= 65525 { slog(" (FAT32 OK)\r\n"); }
    else { slog(" (< 65525 = EDK2 sees FAT16 = BUG!)\r\n"); }

    {
        let mut vbr = [0u8; 512];
        vbr[0]=0xEB; vbr[1]=0x58; vbr[2]=0x90;
        vbr[3..11].copy_from_slice(b"AETERNA ");
        w16(&mut vbr,11,512); vbr[13]=spc; w16(&mut vbr,14,RSVD);
        vbr[16]=NFAT; w16(&mut vbr,17,0); w16(&mut vbr,19,0); vbr[21]=0xF8;
        w16(&mut vbr,22,0); w16(&mut vbr,24,63); w16(&mut vbr,26,255);
        w32(&mut vbr,28,esp_start as u32); w32(&mut vbr,32,fat32_total);
        w32(&mut vbr,36,fat_sec); w16(&mut vbr,40,0); w16(&mut vbr,42,0);
        w32(&mut vbr,44,2); w16(&mut vbr,48,1); w16(&mut vbr,50,6);
        vbr[64]=0x80; vbr[66]=0x29; w32(&mut vbr,67,0xAE05AE05);
        vbr[71..82].copy_from_slice(b"AETERNA ESP"); vbr[82..90].copy_from_slice(b"FAT32   ");
        vbr[510]=0x55; vbr[511]=0xAA;
        if !disk_write(disk.index,esp_start,1,&vbr) { die!(1, "cannot write the FAT32 boot sector"); }
        slog("[INSTALLER] VBR written at LBA "); slog_dec(esp_start); slog("\r\n");

        let mut fsi = [0u8; 512];
        w32(&mut fsi,0,0x41615252); w32(&mut fsi,484,0x61417272);
        w32(&mut fsi,488,data_clusters.saturating_sub(8)); w32(&mut fsi,492,8);
        fsi[510]=0x55; fsi[511]=0xAA;
        disk_write(disk.index,esp_start+1,1,&fsi);
        disk_write(disk.index,esp_start+6,1,&vbr);  // backup VBR
        disk_write(disk.index,esp_start+7,1,&fsi);  // backup FSInfo
        slog("[INSTALLER] FSInfo + backups written\r\n");
    }
    {
        let zero = [0u8; 512];
        let fat1 = esp_start + RSVD as u64;
        let fat2 = fat1 + fat_sec as u64;
        slog("[INSTALLER] FAT1 LBA="); slog_dec(fat1);
        slog("  FAT2 LBA="); slog_dec(fat2);
        slog("  fat_sec="); slog_dec(fat_sec as u64); slog("\r\n");
        for fc in [fat1, fat2] { for s in 0..fat_sec as u64 { disk_write(disk.index,fc+s,1,&zero); } }
        let mut fat0 = [0u8; 512];
        w32(&mut fat0,0,0x0FFF_FFF8); w32(&mut fat0,4,0x0FFF_FFFF); w32(&mut fat0,8,0x0FFF_FFFF);
        disk_write(disk.index,fat1,1,&fat0); disk_write(disk.index,fat2,1,&fat0);
        slog("[INSTALLER] FAT tables zeroed + FAT[0..2] initialized\r\n");
    }
    if WRITE_ERRS.load(Ordering::Relaxed) != errs0 { die!(1, "write errors while formatting the ESP"); }
    step_end(1, St::Ok, &format!("{}, {} KiB clusters", fmt_size(esp_size_mb), cb / 1024));

    // FAT LBAs — needed in the following steps
    let fat1_lba = esp_start + RSVD as u64;
    let fat2_lba = fat1_lba + fat_sec as u64;

    // ══════════════════════════════════════════════════════════════════════
    // 3 — ESP directory tree (dynamic, non-overlapping cluster allocation)
    step_begin(2, 0);
    let errs0 = WRITE_ERRS.load(Ordering::Relaxed);
    slog("[INSTALLER] Step 5: ESP directory tree\r\n");
    // Helper: sector LBA for cluster N  (cluster 2 = data region start)
    let clba = |c: u32| -> u64 { esp_start + data_rel as u64 + (c as u64 - 2) * spc as u64 };

    // Allocate clusters in order — no overlaps possible
    let mut nc   = 2u32;
    let root_c   = nc; nc += 1;  // 2  root directory
    let efi_dc   = nc; nc += 1;  // 3  /EFI/
    let boot_dc  = nc; nc += 1;  // 4  /EFI/BOOT/
    let sysb_c   = nc; nc += 1;  // 5  /boot/
    let conf_c   = nc; nc += 1;  // 6  /limine.conf

    let efi_c  = nc; nc += efi_nc;
    let ker_c  = nc; // nc += ker_nc; (last allocation)
    let _ = nc;

    // Zero directory clusters
    let zero = [0u8; 512];
    for c in [root_c, efi_dc, boot_dc, sysb_c] {
        let lba = clba(c);
        for s in 0..spc as u64 { disk_write(disk.index, lba+s, 1, &zero); }
    }

    // Root dir /
    {
        let mut d = [0u8; 512];
        d[0..11].copy_from_slice(b"AETERNA ESP"); d[11]=0x08; // volume label
        dir_ent(&mut d, 32, b"EFI        ", 0x10, efi_dc, 0);
        dir_ent(&mut d, 64, b"BOOT       ", 0x10, sysb_c, 0);
        // "limine.conf" — extension .conf is 4 chars, doesn't fit 8.3.
        // Without an LFN entry, FAT shows "LIMINE.CFG" and Limine
        // can't find its config.  We write 1 LFN entry + 8.3 short entry.
        {
            let sn: &[u8; 11] = b"LIMINE~1CON";
            let cksum = lfn_checksum(sn);
            // "limine.conf" in UCS-2LE
            let long_name: [u16; 11] = [
                0x6C, 0x69, 0x6D, 0x69, 0x6E, 0x65,  // l i m i n e
                0x2E,                                  // .
                0x63, 0x6F, 0x6E, 0x66,                // c o n f
            ];
            lfn_entry(&mut d, 96, 0x41, &long_name, cksum); // seq=1|LAST
            dir_ent(&mut d, 128, sn, 0x20, conf_c, conf_content.len() as u32);
        }
        disk_write(disk.index, clba(root_c), 1, &d);
        slog("[INSTALLER] Root dir: LFN entry for limine.conf written\r\n");
    }
    // /EFI/
    {
        let mut d = [0u8; 512];
        dot_ents(&mut d, efi_dc, root_c);
        dir_ent(&mut d, 64, b"BOOT       ", 0x10, boot_dc, 0);
        disk_write(disk.index, clba(efi_dc), 1, &d);
    }
    // /EFI/BOOT/
    {
        let mut d = [0u8; 512];
        dot_ents(&mut d, boot_dc, efi_dc);
        dir_ent(&mut d, 64, b"BOOTX64 EFI", 0x20, efi_c, efi_size as u32);
        disk_write(disk.index, clba(boot_dc), 1, &d);
    }
    // /boot/
    {
        let mut d = [0u8; 512];
        dot_ents(&mut d, sysb_c, root_c);
        dir_ent(&mut d, 64, b"KERNEL     ", 0x20, ker_c, kernel_size as u32);
        disk_write(disk.index, clba(sysb_c), 1, &d);
    }

    // FAT chain entries for all directories — without these, UEFI reads
    // FAT[cluster]=0 ("free") and treats the filesystem as corrupt.
    // root_c=2 is already end-of-chain in fat0; write_chain the rest.
    write_chain(disk.index, fat1_lba, fat2_lba, root_c,  1); // cluster 2
    write_chain(disk.index, fat1_lba, fat2_lba, efi_dc,  1); // cluster 3  /EFI/
    write_chain(disk.index, fat1_lba, fat2_lba, boot_dc, 1); // cluster 4  /EFI/BOOT/
    write_chain(disk.index, fat1_lba, fat2_lba, sysb_c,  1); // cluster 5  /boot/
    slog("[INSTALLER] Dir clusters: root="); slog_dec(root_c as u64);
    slog(" efi_dc="); slog_dec(efi_dc as u64);
    slog(" boot_dc="); slog_dec(boot_dc as u64);
    slog(" sysb="); slog_dec(sysb_c as u64);
    slog(" conf="); slog_dec(conf_c as u64); slog("\r\n");
    slog("  efi_c="); slog_dec(efi_c as u64); slog(" efi_nc="); slog_dec(efi_nc as u64);
    slog("  ker_c="); slog_dec(ker_c as u64); slog(" ker_nc="); slog_dec(ker_nc as u64); slog("\r\n");
    if WRITE_ERRS.load(Ordering::Relaxed) != errs0 { die!(2, "write errors while creating directories"); }
    step_end(2, St::Ok, "/EFI/BOOT  /boot");

    // ══════════════════════════════════════════════════════════════════════
    // 4 — /EFI/BOOT/BOOTX64.EFI
    step_begin(3, efi_w);
    let errs0 = WRITE_ERRS.load(Ordering::Relaxed);
    write_clusters(disk.index, efi_data, efi_size, efi_c, efi_nc, &clba, spc);
    write_chain(disk.index, fat1_lba, fat2_lba, efi_c, efi_nc);
    slog("[INSTALLER] EFI written: clusters "); slog_dec(efi_c as u64);
    slog("..+"); slog_dec(efi_nc as u64);
    slog("  size="); slog_dec(efi_size as u64); slog("\r\n");
    if WRITE_ERRS.load(Ordering::Relaxed) != errs0 { die!(3, "write errors while copying BOOTX64.EFI"); }
    step_end(3, St::Ok, &fmt_bytes(efi_size as u64));

    // ══════════════════════════════════════════════════════════════════════
    // 5 — /boot/KERNEL
    step_begin(4, ker_w);
    let errs0 = WRITE_ERRS.load(Ordering::Relaxed);
    write_clusters(disk.index, kernel_data, kernel_size, ker_c, ker_nc, &clba, spc);
    write_chain(disk.index, fat1_lba, fat2_lba, ker_c, ker_nc);
    slog("[INSTALLER] KERNEL written: clusters "); slog_dec(ker_c as u64);
    slog("..+"); slog_dec(ker_nc as u64);
    slog("  size="); slog_dec(kernel_size as u64); slog("\r\n");
    if WRITE_ERRS.load(Ordering::Relaxed) != errs0 { die!(4, "write errors while copying the kernel"); }
    step_end(4, St::Ok, &fmt_bytes(kernel_size as u64));

    // ══════════════════════════════════════════════════════════════════════
    // 6 — /limine.conf (chain = 1 cluster) + AETERNA identity sector
    step_begin(5, 0);
    let errs0 = WRITE_ERRS.load(Ordering::Relaxed);
    slog("[INSTALLER] Writing /limine.conf at cluster "); slog_dec(conf_c as u64); slog("\r\n");
    write_chain(disk.index, fat1_lba, fat2_lba, conf_c, 1);
    {
        let cb_lba = clba(conf_c);
        let cb_bytes = conf_content.as_bytes();
        let full = cb_bytes.len() / 512;
        for s in 0..full { disk_write(disk.index, cb_lba+s as u64, 1, &cb_bytes[s*512..(s+1)*512]); }
        let partial = cb_bytes.len() % 512;
        if partial > 0 || full == 0 {
            let mut last = [0u8; 512];
            last[..cb_bytes.len()-full*512].copy_from_slice(&cb_bytes[full*512..]);
            disk_write(disk.index, cb_lba+full as u64, 1, &last);
        }
    }

    // Flush after all ESP file writes (EFI + kernel + limine.conf)
    slog("[INSTALLER] Flushing write-cache after ESP files...\r\n");
    disk_flush(disk.index);

    slog("[INSTALLER] Step 8: Identity at LBA "); slog_dec(root_start); slog("\r\n");
    {
        let mut id = [0u8; 512];
        id[0..8].copy_from_slice(b"AETERNA ");
        let ver = crate::version::VERSION_STR.as_bytes();
        id[8..8+ver.len().min(16)].copy_from_slice(&ver[..ver.len().min(16)]);
        let arch = crate::version::ARCH.as_bytes();
        id[24..24+arch.len().min(8)].copy_from_slice(&arch[..arch.len().min(8)]);
        let date = crate::version::BUILD_DATE.as_bytes();
        id[32..32+date.len().min(16)].copy_from_slice(&date[..date.len().min(16)]);
        id[48..48+hostname.len().min(32)].copy_from_slice(&hostname[..hostname.len().min(32)]);
        let loc = locale.as_bytes();
        id[80..80+loc.len().min(16)].copy_from_slice(&loc[..loc.len().min(16)]);
        w64(&mut id, 96, esp_start);
        w64(&mut id, 104, root_start);
        w64(&mut id, 112, disk.size_mb);
        id[510]=0xAE; id[511]=0x05;
        if !disk_write(disk.index, root_start, 1, &id) { die!(5, "cannot write the identity record"); }
    }

    // Final flush: all FAT32 + kernel + identity data committed before readback
    slog("[INSTALLER] Final flush before verification...\r\n");
    disk_flush(disk.index);
    if WRITE_ERRS.load(Ordering::Relaxed) != errs0 { die!(5, "write errors while writing limine.conf"); }
    step_end(5, St::Ok, "/limine.conf");
    P_TOTAL.store(0, Ordering::Relaxed);
    draw_overall(1000);

    // ══════════════════════════════════════════════════════════════════════
    // 7 — Verify
    step_begin(6, 0);
    slog("[INSTALLER] === Verification ===\r\n");
    let mut checks: Vec<Check> = Vec::new();
    {
        let mut buf = [0u8; 512];
        let ok = disk_read(disk.index,0,1,&mut buf) && buf[450]==0xEE;
        checks.push(Check { label: "Protective MBR", ok });
    }
    // ── GPT: signature + header CRC32 + entries CRC32 ────────────────────────
    {
        let mut buf = [0u8; 512];
        let sig = disk_read(disk.index,1,1,&mut buf) && &buf[..8]==b"EFI PART";
        checks.push(Check { label: "GPT header", ok: sig });

        let mut hdr_ok = false;
        let mut ent_ok = false;
        if sig {
            let stored = u32::from_le_bytes([buf[16],buf[17],buf[18],buf[19]]);
            let hdr_ecrc = u32::from_le_bytes([buf[88],buf[89],buf[90],buf[91]]);
            buf[16]=0; buf[17]=0; buf[18]=0; buf[19]=0;   // zero field before check
            let computed = crc32(&buf[..92]);
            hdr_ok = stored == computed;
            if !hdr_ok {
                slog("[VERIFY] GPT header CRC mismatch stored="); slog_hex32(stored);
                slog(" computed="); slog_hex32(computed); slog("\r\n");
            }
            let mut ebuf = alloc::vec![0u8; 32usize * 512];
            let mut read_ok = true;
            for s in 0u64..32 {
                let o = s as usize * 512;
                if !disk_read(disk.index, 2+s, 1, &mut ebuf[o..o+512]) { read_ok=false; break; }
            }
            if read_ok {
                let comp = crc32(&ebuf);
                ent_ok = comp == hdr_ecrc;
                if !ent_ok {
                    slog("[VERIFY] GPT entries CRC mismatch stored="); slog_hex32(hdr_ecrc);
                    slog(" computed="); slog_hex32(comp); slog("\r\n");
                }
            }
        }
        checks.push(Check { label: "GPT header CRC32", ok: hdr_ok });
        checks.push(Check { label: "GPT entries CRC32", ok: ent_ok });
    }
    {
        let mut buf = [0u8; 512];
        let mut ok = disk_read(disk.index,esp_start,1,&mut buf) && buf[510]==0x55 && buf[511]==0xAA;
        if ok {
            // Dump key BPB fields to serial for debugging
            let bpb_spc  = buf[13];
            let bpb_rsvd = u16::from_le_bytes([buf[14], buf[15]]);
            let bpb_nfat = buf[16];
            let bpb_fatsz = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
            let bpb_tot32 = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
            let dr = bpb_rsvd as u32 + bpb_fatsz * bpb_nfat as u32;
            let dc = if bpb_spc > 0 { bpb_tot32.saturating_sub(dr) / bpb_spc as u32 } else { 0 };
            slog("[VERIFY] BPB: SPC="); slog_dec(bpb_spc as u64);
            slog(" RSVD="); slog_dec(bpb_rsvd as u64);
            slog(" NFAT="); slog_dec(bpb_nfat as u64);
            slog(" FATSz="); slog_dec(bpb_fatsz as u64);
            slog(" Tot32="); slog_dec(bpb_tot32 as u64); slog("\r\n");
            slog("[VERIFY] data_rel="); slog_dec(dr as u64);
            slog(" data_clusters="); slog_dec(dc as u64);
            if dc >= 65525 { slog(" -> FAT32 OK\r\n"); }
            else { slog(" -> FAT16 BUG! EDK2 will reject!\r\n"); ok = false; }
        }
        checks.push(Check { label: "FAT32 boot sector", ok });
    }
    // Read-back FAT sector 0 — dump first 8 entries to serial
    {
        let mut fbuf = [0u8; 512];
        if disk_read(disk.index, fat1_lba, 1, &mut fbuf) {
            slog("[VERIFY] FAT1 sector 0 (first 8 entries):\r\n");
            for i in 0..8u32 {
                let off = i as usize * 4;
                let val = u32::from_le_bytes([fbuf[off], fbuf[off+1], fbuf[off+2], fbuf[off+3]]);
                slog("  FAT["); slog_dec(i as u64); slog("]="); slog_hex32(val); slog("\r\n");
            }
        }
    }
    {
        let mut buf = [0u8; 512];
        let ok = disk_read(disk.index, clba(efi_c), 1, &mut buf) && buf[0]==b'M' && buf[1]==b'Z';
        checks.push(Check { label: "BOOTX64.EFI", ok });
    }
    {
        // Compare the whole first cluster of the kernel with the source image
        let mut buf = alloc::vec![0u8; cb];
        let n = cb.min(kernel_size);
        let mut ok = true;
        for s in 0..(n + 511) / 512 {
            if !disk_read(disk.index, clba(ker_c) + s as u64, 1, &mut buf[s*512..s*512+512]) { ok = false; break; }
        }
        ok = ok && buf[..n] == kernel_data[..n];
        checks.push(Check { label: "/boot/KERNEL", ok });
    }
    {
        let mut buf = [0u8; 512];
        let ok = disk_read(disk.index, clba(conf_c), 1, &mut buf)
            && buf[..conf_content.len().min(512)] == conf_content.as_bytes()[..conf_content.len().min(512)];
        checks.push(Check { label: "/limine.conf", ok });
    }
    {
        let mut buf = [0u8; 512];
        let ok = disk_read(disk.index,root_start,1,&mut buf) && &buf[..8]==b"AETERNA " && buf[510]==0xAE && buf[511]==0x05;
        checks.push(Check { label: "Identity record", ok });
    }
    let failed = checks.iter().filter(|c| !c.ok).count();
    let all_ok = failed == 0 && backup_ok;
    if failed == 0 { step_end(6, St::Ok, &format!("{} checks passed", checks.len())); }
    else { step_end(6, St::Fail, &format!("{} of {} checks failed", failed, checks.len())); }
    slog(if all_ok { "[INSTALLER] install complete, all checks OK\r\n" } else { "[INSTALLER] install complete WITH ERRORS\r\n" });

    draw_checks(R_CHECKS, &checks);
    Pen::at(2, R_CHECKS + 6).put("Press Enter to continue.", FG);
    footer(&[("Enter", "Continue")], "");
    drain_keys();
    loop { if key() == '\n' { break; } }

    page_done(&disk, cfg, root_mb, &checks, all_ok, backup_ok);
}

// ── 6. Done ──────────────────────────────────────────────────────────────────
fn page_done(disk: &VDisk, cfg: &Config, root_mb: u64, checks: &[Check], all_ok: bool, backup_ok: bool) {
    slog("[INSTALLER] page: done\r\n");
    let (title, tfg) = if all_ok { ("Installation complete", FG_OK) }
                       else { ("Installation finished with problems", FG_WARN) };
    chrome(5, title, tfg, "AETERNA has been written to the disk.",
           &[("Enter", "Reboot now"), ("Esc", "Back to shell")]);

    let (border, fill) = if all_ok { (FG_OK, OK_BG) } else { (FG_WARN, WARN_BG) };
    draw_box(R_BODY, 4, border, fill, "");
    let mut p = Pen::at(3, R_BODY + 1).on(fill);
    if all_ok { p.put("\u{2713}  ", FG_OK).put("ospab.os is installed on ", FG_TITLE); }
    else { p.put("!  ", FG_WARN).put("Some checks failed on ", FG_TITLE); }
    p.put(&format!("/dev/{}", disk.name()), FG_TITLE);
    Pen::at(6, R_BODY + 2).on(fill).put(&format!("ESP {} FAT32  \u{00B7}  root {}  \u{00B7}  {}  \u{00B7}  {}",
        fmt_size(cfg.esp_mb), fmt_size(root_mb), cfg.hostname(), LOCALES[cfg.locale]), FG_DIM);

    t(2, R_BODY + 5, "Verification", FG_TITLE);
    draw_checks(R_BODY + 6, checks);
    let mut nr = R_BODY + 6 + ((checks.len() + 1) / 2) as u64;
    if !backup_ok { t(4, nr, "! Backup GPT at the end of the disk could not be written.", FG_WARN); nr += 1; }

    let sr = nr + 1;
    t(2, sr, "Next steps", FG_TITLE);
    Pen::at(4, sr + 1).put("1  ", ACCENT).put("Remove the installation media: ", FG).put("eject / disconnect the ISO", FG_TITLE);
    Pen::at(4, sr + 2).put("   ", ACCENT).put("(in VMware/VirtualBox: disconnect the virtual CD/DVD drive).", FG_DIM);
    Pen::at(4, sr + 3).put("2  ", ACCENT).put("Press Enter to reboot. Firmware boots \\EFI\\BOOT\\BOOTX64.EFI", FG);
    Pen::at(4, sr + 4).put("   ", ACCENT).put("from the disk; if not, pick the disk in the boot menu.", FG_DIM);
    Pen::at(4, sr + 5).put("3  ", ACCENT).put("The disk boots in UEFI mode only \u{2014} enable EFI firmware in the VM.", FG);

    drain_keys();
    loop {
        match key() {
            '\n' | 'r' | 'R' => {
                // Commit everything before the reset: drive write-cache first,
                // then any pending live-session filesystem changes.
                fill_cells(0, rows() - 1, cols(), 1, BAR_BG);
                abs_text(2, rows() - 1, "Syncing disks and rebooting\u{2026}", FG_TITLE, BAR_BG);
                disk_flush(disk.index);
                if ospab_os::fs::disk_sync::is_dirty() { ospab_os::fs::disk_sync::sync_filesystem(); }
                slog("[INSTALLER] rebooting\r\n");
                ospab_os::acpi::reboot();
                return;
            }
            ESC | 'q' | 'Q' | CTRL_C => return,
            _ => {}
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// FAT32 helpers
// ════════════════════════════════════════════════════════════════════════════
fn dir_ent(dir: &mut [u8], off: usize, name: &[u8; 11], attr: u8, clust: u32, size: u32) {
    let e = &mut dir[off..off+32];
    e[0..11].copy_from_slice(name); e[11]=attr;
    w16(e,20,(clust>>16) as u16); w16(e,26,(clust&0xFFFF) as u16); w32(e,28,size);
}
fn dot_ents(dir: &mut [u8], my: u32, parent: u32) {
    dir_ent(dir, 0,  b".          ", 0x10, my, 0);
    dir_ent(dir, 32, b"..         ", 0x10, parent, 0);
}
/// 8.3 short-name checksum used by FAT32 Long File Name entries.
fn lfn_checksum(sn: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for i in 0..11 {
        sum = (if sum & 1 != 0 { 0x80u8 } else { 0u8 })
            .wrapping_add(sum >> 1)
            .wrapping_add(sn[i]);
    }
    sum
}
/// Write one LFN directory entry at `dir[off..off+32]`.
/// `seq` = ordinal (1-based, OR 0x40 for last entry).
/// `name` = full long name as UCS-2LE code units.
/// `cksum` = checksum of the corresponding 8.3 short name.
fn lfn_entry(dir: &mut [u8], off: usize, seq: u8, name: &[u16], cksum: u8) {
    let base = (seq & 0x3F) as usize - 1;  // 0-based index
    let start = base * 13;
    let e = &mut dir[off..off+32];
    e[0] = seq;
    // Chars 1-5  (bytes 1..10)
    for i in 0..5usize {
        let ch = if start+i < name.len() { name[start+i] }
                 else if start+i == name.len() { 0x0000 }
                 else { 0xFFFF };
        e[1+i*2]   = ch as u8;
        e[1+i*2+1] = (ch >> 8) as u8;
    }
    e[11] = 0x0F; // LFN attribute
    e[12] = 0x00; // type
    e[13] = cksum;
    // Chars 6-11 (bytes 14..25)
    for i in 0..6usize {
        let ch = if start+5+i < name.len() { name[start+5+i] }
                 else if start+5+i == name.len() { 0x0000 }
                 else { 0xFFFF };
        e[14+i*2]   = ch as u8;
        e[14+i*2+1] = (ch >> 8) as u8;
    }
    e[26] = 0; e[27] = 0; // first cluster = 0
    // Chars 12-13 (bytes 28..31)
    for i in 0..2usize {
        let ch = if start+11+i < name.len() { name[start+11+i] }
                 else if start+11+i == name.len() { 0x0000 }
                 else { 0xFFFF };
        e[28+i*2]   = ch as u8;
        e[28+i*2+1] = (ch >> 8) as u8;
    }
}
fn write_clusters<F>(disk: usize, data: &[u8], size: usize, start: u32, nc: u32, clba: &F, spc: u8)
where F: Fn(u32) -> u64 {
    let cb = spc as usize * 512;
    for ci in 0..nc as usize {
        let off = ci * cb;
        if off >= size { break; }
        let lba = clba(start + ci as u32);
        let rem  = (size - off).min(cb);
        let full = rem / 512;
        for s in 0..full { disk_write(disk, lba+s as u64, 1, &data[off+s*512..off+s*512+512]); }
        let part = rem % 512;
        if part > 0 {
            let mut last = [0u8; 512]; let so = off + full*512;
            last[..part].copy_from_slice(&data[so..so+part]);
            disk_write(disk, lba+full as u64, 1, &last);
        }
    }
}
fn write_chain(disk: usize, fat1: u64, fat2: u64, start: u32, nc: u32) {
    for i in 0..nc {
        let c   = start + i;
        let fao = c * 4;
        let fs  = fao / 512;
        let bo  = (fao % 512) as usize;
        let val: u32 = if i == nc-1 { 0x0FFF_FFFF } else { c+1 };
        for &fb in &[fat1, fat2] {
            let mut sec = [0u8; 512];
            disk_read(disk, fb+fs as u64, 1, &mut sec);
            w32(&mut sec, bo, val);
            disk_write(disk, fb+fs as u64, 1, &sec);
        }
    }
}

// ── limine.conf — matches the live ISO format exactly ────────────────────────
fn build_limine_conf() -> &'static str {
    "timeout: 5\nserial: yes\n\n/AETERNA Microkernel\n\tprotocol: limine\n\tkernel_path: boot():/boot/KERNEL\n"
}
