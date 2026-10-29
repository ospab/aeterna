/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Display modes: the current mode, the list of modes, changing the mode at run
time, and autofit with the VMware window.

  current()       what is on screen now (size, pitch)
  list()          modes that can be set (VMware SVGA II: any size within the
                  device limits and video memory; other machines: only the boot mode)
  set(w, h)       switch; the framebuffer is reconfigured (address and pitch may
                  change), the console is redrawn from its text shadow
  generation()    bumped on every change; the desktop compares it each frame and
                  lays itself out again
  poll()          autofit: answer the host's "Resolution_Set" (see vmrpc.rs)

Settings are kept in /etc/display.conf:
  mode=1920x1080     last mode chosen by hand (applied at boot)
  auto=on|off        follow the VMware window (default on under VMware)
  scale=auto|1|2     console font scale (auto: 2 from 2560 px wide)
*/
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use crate::arch::x86_64::{framebuffer, serial};
use super::{vmrpc, vmware_svga};

const CONF_PATH: &str = "/etc/display.conf";
const MIN_W: u32 = 640;
const MIN_H: u32 = 480;
/// Hard sanity limit for requests from the host.
const MAX_DIM: u32 = 8192;

/// Named sizes, also used by Settings and `display set`.
pub const PRESETS: [(&str, u32, u32); 9] = [
    ("1024x768", 1024, 768),
    ("1280x720", 1280, 720),
    ("1280x800", 1280, 800),
    ("1280x1024", 1280, 1024),
    ("1366x768", 1366, 768),
    ("1600x900", 1600, 900),
    ("1920x1080", 1920, 1080),
    ("2560x1440", 2560, 1440),
    ("3840x2160", 3840, 2160),
];

static GENERATION: AtomicU32 = AtomicU32::new(0);
static DESKTOP_ACTIVE: AtomicBool = AtomicBool::new(false);
/// 0 = not decided, 1 = on, 2 = off
static AUTO: AtomicU8 = AtomicU8::new(0);

/// Changes whenever the mode, pitch or font scale changed.
pub fn generation() -> u32 { GENERATION.load(Ordering::Acquire) }

/// The desktop owns the screen: a mode change must not paint the console.
pub fn set_desktop_active(on: bool) { DESKTOP_ACTIVE.store(on, Ordering::Release); }

/// (width, height, pitch in bytes) now on screen.
pub fn current() -> (u32, u32, u32) {
    match framebuffer::info() {
        Some(f) => (f.width as u32, f.height as u32, f.pitch as u32),
        None => (0, 0, 0),
    }
}

/// True when the mode can be changed (VMware SVGA II present).
pub fn can_set() -> bool { vmware_svga::is_ready() }

/// Autofit with the VMware window is on.
pub fn auto_enabled() -> bool {
    match AUTO.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => vmrpc::available(),
    }
}

pub fn set_auto(on: bool) { AUTO.store(if on { 1 } else { 2 }, Ordering::Relaxed); }

/// Largest mode the device accepts: (width, height, video memory in bytes).
pub fn limits() -> (u32, u32, u32) { vmware_svga::limits() }

fn fits(w: u32, h: u32) -> Result<(), String> {
    if w < MIN_W || h < MIN_H { return Err(format!("{}x{} is below the minimum {}x{}", w, h, MIN_W, MIN_H)); }
    let (mw, mh, vram) = limits();
    if (mw != 0 && w > mw) || (mh != 0 && h > mh) {
        return Err(format!("{}x{} is above the device maximum {}x{} (SVGA_REG_MAX_WIDTH/HEIGHT). {}",
            w, h, mw, mh, suggest(w, h)));
    }
    let need = w as u64 * h as u64 * 4;
    if vram != 0 && need > vram as u64 {
        return Err(format!("{}x{} needs {} bytes ({} KiB) of video memory at 32 bpp, the adapter has {} bytes ({} KiB, SVGA_REG_VRAM_SIZE). {}",
            w, h, need, need >> 10, vram, (vram as u64) >> 10, suggest(w, h)));
    }
    Ok(())
}

/// Largest size with the aspect ratio of `w` x `h` that fits the adapter.
fn largest_same_aspect(w: u32, h: u32) -> (u32, u32) {
    let (mw, mh, vram) = limits();
    let (mut nw, mut nh) = (w, h);
    while nw > MIN_W && ((mw != 0 && (nw > mw || nh > mh)) || (vram != 0 && nw as u64 * nh as u64 * 4 > vram as u64)) {
        nw -= 8;
        nh = (nw as u64 * h as u64 / w as u64) as u32;
    }
    (nw, nh)
}

/// What to do when a mode does not fit: biggest preset, same-aspect size, and the VMware setting.
fn suggest(w: u32, h: u32) -> String {
    let mut best: Option<(u32, u32)> = None;
    for (_, pw, ph) in PRESETS {
        if pw as u64 * ph as u64 > best.map_or(0, |(a, b)| a as u64 * b as u64) && check_fits(pw, ph) { best = Some((pw, ph)); }
    }
    let (sw, sh) = largest_same_aspect(w, h);
    let mut s = String::new();
    if let Some((bw, bh)) = best { s.push_str(&format!("Largest preset that fits: {}x{}. ", bw, bh)); }
    s.push_str(&format!("Same aspect ratio: `display set {}x{}`; any WxH within the limits works. ", sw, sh));
    s.push_str("To get more: VM Settings > Display > Graphics memory 128-256 MB (or Specify monitor settings with a larger maximum resolution), then reboot the VM.");
    s
}

fn check_fits(w: u32, h: u32) -> bool {
    let (mw, mh, vram) = limits();
    !((mw != 0 && w > mw) || (mh != 0 && h > mh) || (vram != 0 && w as u64 * h as u64 * 4 > vram as u64))
}

/// Modes that can be set, smallest first. Without SVGA II: the boot mode only.
pub fn list() -> Vec<(u32, u32)> {
    let (cw, ch, _) = current();
    let mut v: Vec<(u32, u32)> = Vec::new();
    if can_set() {
        for (_, w, h) in PRESETS {
            if fits(w, h).is_ok() { v.push((w, h)); }
        }
    }
    if cw != 0 && !v.contains(&(cw, ch)) { v.push((cw, ch)); }
    v.sort_by_key(|&(w, h)| (w as u64 * h as u64, w));
    v
}

/// "1920x1080", "1920 1080" or a name: hd, fullhd, 2k, 4k (also 720p, 1080p, 1440p, 2160p).
pub fn parse(s: &str) -> Option<(u32, u32)> {
    let s = s.trim();
    let named = match s {
        "hd" | "720p" => Some((1280, 720)),
        "fullhd" | "fhd" | "1080p" => Some((1920, 1080)),
        "2k" | "qhd" | "1440p" => Some((2560, 1440)),
        "4k" | "uhd" | "2160p" => Some((3840, 2160)),
        _ => None,
    };
    if named.is_some() { return named; }
    let mut it = s.split(|c| c == 'x' || c == 'X' || c == ' ' || c == '*');
    let w: u32 = it.next()?.trim().parse().ok()?;
    let h: u32 = it.next()?.trim().parse().ok()?;
    if it.next().is_some() || w == 0 || h == 0 { return None; }
    Some((w, h))
}

/// Short name for a size ("fullhd", "4k" ...), if it has one.
pub fn name_of(w: u32, h: u32) -> Option<&'static str> {
    match (w, h) {
        (1280, 720) => Some("hd"),
        (1920, 1080) => Some("fullhd"),
        (2560, 1440) => Some("2k"),
        (3840, 2160) => Some("4k"),
        _ => None,
    }
}

fn log_mode(prefix: &str, w: u32, h: u32, pitch: u32) {
    serial::write_str("[DISPLAY] ");
    serial::write_str(&format!("{} {}x{} pitch {} scale {}x\r\n", prefix, w, h, pitch, framebuffer::scale()));
}

/// Switch to `w` x `h` (32 bpp). On success returns the mode the device took.
pub fn set(w: u32, h: u32) -> Result<(u32, u32), String> {
    if !can_set() {
        return Err(String::from("this display has a fixed resolution (no VMware SVGA II adapter)"));
    }
    // The adapter wants a width that is a multiple of 8 (otherwise rows shear on screen).
    let w = w & !7;
    fits(w, h)?;
    let (cw, ch, _) = current();
    if (cw, ch) == (w, h) { return Ok((w, h)); }
    if !vmware_svga::set_mode(w, h, 32) {
        return Err(String::from("the adapter refused the mode"));
    }
    vmware_svga::activate();
    let (nw, nh, pitch) = vmware_svga::display_info();
    let Some(fb) = framebuffer::info() else { return Err(String::from("no framebuffer")); };
    let paint = !DESKTOP_ACTIVE.load(Ordering::Acquire);
    unsafe { framebuffer::reconfigure(fb.address, nw as u64, nh as u64, pitch as u64, paint); }
    vmware_svga::flush_screen();
    GENERATION.fetch_add(1, Ordering::AcqRel);
    log_mode("mode set", nw, nh, pitch);
    Ok((nw, nh))
}

/// Set the console font scale: 1, 2, ... or 0 for automatic.
pub fn set_scale(scale: u64) {
    framebuffer::set_scale(scale, !DESKTOP_ACTIVE.load(Ordering::Acquire));
    GENERATION.fetch_add(1, Ordering::AcqRel);
    vmware_svga::flush_screen();
}

// ─── Autofit ────────────────────────────────────────────────────────────────

/// Poll the VMware host channel (call from idle loops; it rate-limits itself).
/// Returns true when the mode changed.
pub fn poll() -> bool {
    if !auto_enabled() { return false; }
    let Some((mut w, mut h)) = vmrpc::poll() else { return false; };
    serial::write_str(&format!("[DISPLAY] host asks for {}x{}\r\n", w, h));
    if w > MAX_DIM || h > MAX_DIM { vmrpc::reply_failed(); return false; }
    if !can_set() {
        serial::write_str("[DISPLAY] no SVGA II adapter: cannot follow the host\r\n");
        vmrpc::reply_failed();
        return false;
    }
    // Does not fit: take the largest size with the same aspect ratio.
    if !check_fits(w, h) {
        let (nw, nh) = largest_same_aspect(w, h);
        serial::write_str(&format!("[DISPLAY] {}x{} does not fit the adapter, using {}x{}\r\n", w, h, nw, nh));
        w = nw;
        h = nh;
    }
    let (cw, ch, _) = current();
    if (cw, ch) == (w, h) { return false; }
    match set(w, h) {
        Ok(_) => true,
        Err(e) => {
            serial::write_str(&format!("[DISPLAY] autofit failed: {}\r\n", e));
            vmrpc::reply_failed();
            false
        }
    }
}

// ─── Settings file ──────────────────────────────────────────────────────────

struct Conf {
    mode: Option<(u32, u32)>,
    auto: Option<bool>,
    scale: Option<u64>,
}

fn read_conf() -> Conf {
    let mut c = Conf { mode: None, auto: None, scale: None };
    let Some(data) = crate::fs::read_file(CONF_PATH) else { return c; };
    for line in String::from_utf8_lossy(&data).lines() {
        let Some((k, v)) = line.split_once('=') else { continue; };
        let v = v.trim();
        match k.trim() {
            "mode" => c.mode = parse(v),
            "auto" => c.auto = Some(matches!(v, "on" | "1" | "yes" | "true")),
            "scale" => c.scale = if v == "auto" { Some(0) } else { v.parse().ok() },
            _ => {}
        }
    }
    c
}

fn write_conf(c: &Conf) {
    let mut s = String::new();
    if let Some((w, h)) = c.mode { s.push_str(&format!("mode={}x{}\n", w, h)); }
    if let Some(a) = c.auto { s.push_str(if a { "auto=on\n" } else { "auto=off\n" }); }
    match c.scale {
        Some(0) => s.push_str("scale=auto\n"),
        Some(n) => s.push_str(&format!("scale={}\n", n)),
        None => {}
    }
    crate::fs::mkdir("/etc");
    crate::fs::write_file(CONF_PATH, s.as_bytes());
}

/// Remember the mode chosen by hand (and turn autofit off: a fixed choice wins).
pub fn save_mode(w: u32, h: u32) {
    let mut c = read_conf();
    c.mode = Some((w, h));
    c.auto = Some(false);
    set_auto(false);
    write_conf(&c);
}

pub fn save_auto(on: bool) {
    let mut c = read_conf();
    c.auto = Some(on);
    set_auto(on);
    write_conf(&c);
}

pub fn save_scale(scale: u64) {
    let mut c = read_conf();
    c.scale = Some(scale);
    write_conf(&c);
}

/// Boot: read /etc/display.conf and apply it. Call after the console started.
pub fn apply_saved() {
    let c = read_conf();
    if let Some(a) = c.auto { set_auto(a); }
    if let Some(s) = c.scale { set_scale(s); }
    if let Some((w, h)) = c.mode {
        if can_set() && (w, h) != (current().0, current().1) {
            match set(w, h) {
                Ok((nw, nh)) => serial::write_str(&format!("[DISPLAY] saved mode {}x{} applied\r\n", nw, nh)),
                Err(e) => serial::write_str(&format!("[DISPLAY] saved mode {}x{} not applied: {}\r\n", w, h, e)),
            }
        }
    }
    let (w, h, p) = current();
    log_mode("boot", w, h, p);
    serial::write_str(&format!("[DISPLAY] autofit {}\r\n",
        if !vmrpc::available() { "unavailable (not VMware)" } else if auto_enabled() { "on" } else { "off" }));
}
