/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
display — screen resolution and console font scale

  display                    current mode, driver, autofit state
  display list               modes that can be set
  display set <mode>         switch now and remember it; <mode> is WxH, hd, fullhd, 2k or 4k
  display auto [on|off]      follow the VMware window size (default: on under VMware)
  display scale <1|2|auto>   console font scale; auto = 2 from 2560 px wide

Settings are kept in /etc/display.conf (see drivers/gpu/display.rs).
*/
use alloc::format;

use crate::drivers::gpu::{display, vmrpc};
use crate::userspace::plum::io;

fn describe(w: u32, h: u32) -> alloc::string::String {
    match display::name_of(w, h) {
        Some(n) => format!("{}x{} ({})", w, h, n),
        None => format!("{}x{}", w, h),
    }
}

pub fn run(args: &str) {
    let mut it = args.split_whitespace();
    match it.next().unwrap_or("") {
        "" | "show" | "info" => show(),
        "list" | "ls" => list(),
        "set" => match it.next() {
            Some(first) => {
                // "display set 1920 1080" is accepted too.
                let mut spec = alloc::string::String::from(first);
                if let Some(second) = it.next() { spec.push(' '); spec.push_str(second); }
                set(&spec);
            }
            None => io::err("usage: display set <WxH|hd|fullhd|2k|4k>\n"),
        },
        "auto" => auto(it.next().unwrap_or("on")),
        "scale" => scale(it.next().unwrap_or("")),
        "-h" | "--help" | "help" => usage(),
        other => {
            // "display 1920x1080" as a shortcut for set.
            if display::parse(other).is_some() { set(other); } else { usage(); }
        }
    }
}

fn usage() {
    io::out("usage: display                  show the current mode\n");
    io::out("       display list             modes that can be set\n");
    io::out("       display set <mode>       WxH, hd, fullhd, 2k or 4k; remembered across reboots\n");
    io::out("       display auto [on|off]    follow the VMware window size\n");
    io::out("       display scale <1|2|auto> console font scale\n");
}

fn show() {
    let (w, h, pitch) = display::current();
    io::out(&format!("mode     {}, pitch {} bytes\n", describe(w, h), pitch));
    let cols = crate::arch::x86_64::framebuffer::screen_cols();
    let rows = crate::arch::x86_64::framebuffer::screen_rows();
    io::out(&format!("console  {}x{} characters, font scale {}x{}\n", cols, rows,
        crate::arch::x86_64::framebuffer::scale(),
        if crate::arch::x86_64::framebuffer::scale_is_auto() { " (auto)" } else { "" }));
    if display::can_set() {
        let (mw, mh, vram) = display::limits();
        io::out(&format!("driver   VMware SVGA II, up to {}x{}, {} MiB video memory\n", mw, mh, vram >> 20));
    } else {
        io::out("driver   boot framebuffer (fixed resolution)\n");
    }
    let auto = if !vmrpc::available() { "unavailable (not running under VMware)" }
        else if !display::auto_enabled() { "off" }
        else if vmrpc::connected() { "on, host channel open" }
        else { "on, waiting for the host channel" };
    io::out(&format!("autofit  {}\n", auto));
    if vmrpc::available() { io::out(&format!("guestrpc {}\n", vmrpc::status())); }
}

fn list() {
    let (cw, ch, _) = display::current();
    if display::can_set() {
        let (mw, mh, vram) = display::limits();
        io::out(&format!("device limits: max {}x{}, video memory {} KiB ({} bytes); 32 bpp needs W*H*4 bytes\n", mw, mh, vram >> 10, vram));
        io::out("any WxH within the limits works: display set 1712x912\n");
    }
    for (w, h) in display::list() {
        let mark = if (w, h) == (cw, ch) { " *" } else { "" };
        io::out(&format!("{:>5}x{:<5} {}{}\n", w, h, display::name_of(w, h).unwrap_or(""), mark));
    }
    if !display::can_set() {
        io::out("(this display has a fixed resolution)\n");
    }
}

fn set(spec: &str) {
    let Some((w, h)) = display::parse(spec) else {
        io::err("display: expected WxH, hd, fullhd, 2k or 4k\n");
        return;
    };
    match display::set(w, h) {
        Ok((nw, nh)) => {
            display::save_mode(nw, nh);
            io::out(&format!("display: {} set; autofit off, mode saved to /etc/display.conf\n", describe(nw, nh)));
        }
        Err(e) => io::err(&format!("display: {}\n", e)),
    }
}

fn auto(arg: &str) {
    match arg {
        "off" | "0" | "no" => {
            display::save_auto(false);
            io::out("display: autofit off\n");
        }
        _ => {
            if !vmrpc::available() {
                io::err("display: autofit needs VMware (no VMware backdoor here); use display set\n");
                return;
            }
            display::save_auto(true);
            io::out("display: autofit on (VMware: View > Autofit Guest must be enabled)\n");
            // Try the host channel now and report what happened.
            vmrpc::kick();
            let t0 = crate::arch::x86_64::tsc::tsc_us();
            let mut changed = false;
            while crate::arch::x86_64::tsc::tsc_us() - t0 < 600_000 {
                if display::poll() { changed = true; }
            }
            io::out(&format!("guestrpc {}\n", vmrpc::status()));
            if changed { io::out("display: the host asked for a new size and it was applied\n"); }
            io::out("details are in the serial log, lines tagged [DISPLAY]\n");
        }
    }
}

fn scale(arg: &str) {
    let n = match arg {
        "auto" => 0,
        "1" => 1,
        "2" => 2,
        "3" => 3,
        _ => { io::err("usage: display scale <1|2|auto>\n"); return; }
    };
    display::set_scale(n);
    display::save_scale(n);
    io::out(&format!("display: console font scale {}\n", arg));
}
