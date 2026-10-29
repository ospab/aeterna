// SPDX-License-Identifier: AGPL-3.0-only
//! beeb: BBC Micro Model B emulator for ospab.os. Front end only: arguments, files, keyboard,
//! screen and pacing; the machine is in the `beeb-core` crate. See docs/en/beeb.md.
//!
//!   beeb [-mos os12.rom] [disc.ssd]
//!
//! Defaults come from /etc/beeb.conf (`mos=PATH`, `disc=PATH`, `scale=N`). The MOS ROM and the
//! disc image are not part of the system; the user supplies them.
#![no_std]
#![no_main]

extern crate alloc;

mod keymap;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use beeb_core::machine::{Beeb, SCREEN_H, SCREEN_W};
use liboos::screen;
use liboos::{print, println};

liboos::entry!(main);

const CONF: &str = "/etc/beeb.conf";
const DEFAULT_MOS: &str = "/usr/share/beeb/os12.rom";
const FRAME_NS: u64 = 20_000_000;
const AUDIO_RATE: u32 = 48_000;
/// Frames queued above which a frame's audio is dropped (100 ms).
const AUDIO_MAX_QUEUE: usize = 4800;
const SC_F11: u8 = 0x57;
const SC_F12: u8 = 0x58;

fn read_file(path: &str) -> Result<Vec<u8>, i64> {
    let fd = liboos::open(path, 0);
    if fd < 0 {
        return Err(fd);
    }
    let fd = fd as u64;
    let mut data = Vec::new();
    let mut buf = vec![0u8; 16384];
    loop {
        let n = liboos::read(fd, &mut buf);
        if n < 0 {
            liboos::close(fd);
            return Err(n);
        }
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n as usize]);
    }
    liboos::close(fd);
    Ok(data)
}

struct Config {
    mos: Option<String>,
    disc: Option<String>,
    scale: u32,
    /// Extra sideways ROMs: (slot, path). `basic=` is slot 15.
    roms: Vec<(usize, String)>,
    sound: bool,
}

fn load_conf(c: &mut Config) {
    let Ok(raw) = read_file(CONF) else { return };
    let text = String::from_utf8_lossy(&raw);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let (k, v) = (k.trim(), v.trim());
            match k {
                "mos" => c.mos = Some(String::from(v)),
                "disc" => c.disc = Some(String::from(v)),
                "scale" => c.scale = v.parse().unwrap_or(0),
                "sound" => c.sound = !matches!(v, "0" | "off" | "no"),
                "basic" => c.roms.push((15, String::from(v))),
                _ if k.starts_with("rom") => {
                    if let Ok(slot) = k[3..].parse::<usize>() {
                        c.roms.push((slot, String::from(v)));
                    }
                }
                _ => {}
            }
        }
    }
}

fn usage() {
    println!("usage: beeb [-mos os12.rom] [-basic basic.rom] [-rom SLOT file.rom] [-scale N] [-nosound] [disc.ssd]");
    println!("  -mos PATH    BBC MOS 1.20 ROM, 16384 bytes (default: mos= in {} or {})", CONF, DEFAULT_MOS);
    println!("  -basic PATH  a BBC BASIC ROM (16384 bytes) in sideways slot 15; Elite's loader needs it");
    println!("  -rom N PATH  any sideways ROM in slot N (0..13; slot 14 is the built-in disc system)");
    println!("  -nosound     do not open the sound device");
    println!("  -scale N     horizontal pixel scale (default: largest that fits)");
    println!("  disc.ssd     single-sided DFS disc image, booted like SHIFT+BREAK");
    println!("keys: Esc = ESCAPE, F11 = reset, F12 = quit, Ctrl+C = kill; see docs/en/beeb.md");
}

fn missing_mos(path: &str, err: i64) {
    println!("beeb: cannot read the MOS ROM '{}' (error {}).", path, err);
    println!("The BBC MOS 1.20 ROM (os12.rom, 16384 bytes) is not part of ospab.os.");
    println!("Put your own copy at {} or pass it with -mos PATH,", DEFAULT_MOS);
    println!("or set mos=PATH in {}.", CONF);
}

/// Where the picture goes on the framebuffer: integer scale, centred.
struct Layout {
    sx: usize,
    sy: usize,
    ox: usize,
    oy: usize,
}

fn layout(fb: &screen::Framebuffer, want: u32) -> Layout {
    let (w, h) = (fb.width as usize, fb.height as usize);
    // The BBC picture is 640x256 shown on a 4:3 monitor: a pixel is about twice as high as wide.
    let mut sx = (w / SCREEN_W).min(h / (SCREEN_H * 2)).max(1);
    if want > 0 {
        sx = want as usize;
    }
    let mut sy = sx * 2;
    if SCREEN_H * sy > h {
        sy = (h / SCREEN_H).max(1);
    }
    let (pw, ph) = ((SCREEN_W * sx).min(w), (SCREEN_H * sy).min(h));
    Layout { sx, sy, ox: (w - pw) / 2, oy: (h - ph) / 2 }
}

/// Convert 0x00RRGGBB to the framebuffer's channel order.
#[inline]
fn native(fb: &screen::Framebuffer, rgb: u32) -> u32 {
    if fb.red_shift == 16 && fb.green_shift == 8 && fb.blue_shift == 0 {
        return rgb;
    }
    (((rgb >> 16) & 0xFF) << fb.red_shift) | (((rgb >> 8) & 0xFF) << fb.green_shift) | ((rgb & 0xFF) << fb.blue_shift)
}

/// Draw the lines of `src` that changed since `prev` (all of them when `force`).
fn blit(fb: &screen::Framebuffer, lay: &Layout, src: &[u32], prev: &mut [u32], force: bool) {
    let px = unsafe { fb.pixels() };
    let stride = fb.stride();
    let maxw = (fb.width as usize - lay.ox).min(SCREEN_W * lay.sx);
    for y in 0..SCREEN_H {
        let line = &src[y * SCREEN_W..(y + 1) * SCREEN_W];
        let old = &mut prev[y * SCREEN_W..(y + 1) * SCREEN_W];
        if !force && line == &*old {
            continue;
        }
        old.copy_from_slice(line);
        let y0 = lay.oy + y * lay.sy;
        if y0 >= fb.height as usize {
            break;
        }
        let start = y0 * stride + lay.ox;
        let row = &mut px[start..start + maxw];
        if lay.sx == 1 {
            for (d, s) in row.iter_mut().zip(line.iter()) {
                *d = native(fb, *s);
            }
        } else {
            for (i, d) in row.iter_mut().enumerate() {
                *d = native(fb, line[i / lay.sx]);
            }
        }
        for k in 1..lay.sy {
            if y0 + k >= fb.height as usize {
                break;
            }
            px.copy_within(start..start + maxw, (y0 + k) * stride + lay.ox);
        }
    }
}

fn main(args: liboos::Args) -> i32 {
    let mut conf = Config { mos: None, disc: None, scale: 0, roms: Vec::new(), sound: true };
    load_conf(&mut conf);
    let mut i = 1;
    while i < args.len() {
        let a = args.get(i).unwrap_or("");
        match a {
            "-h" | "-help" | "--help" => {
                usage();
                return 0;
            }
            "-mos" => {
                i += 1;
                match args.get(i) {
                    Some(p) => conf.mos = Some(String::from(p)),
                    None => {
                        usage();
                        return 2;
                    }
                }
            }
            "-basic" => {
                i += 1;
                match args.get(i) {
                    Some(p) => conf.roms.push((15, String::from(p))),
                    None => {
                        usage();
                        return 2;
                    }
                }
            }
            "-rom" => {
                let slot = args.get(i + 1).and_then(|s| s.parse::<usize>().ok());
                let path = args.get(i + 2);
                i += 2;
                match (slot, path) {
                    (Some(n), Some(p)) if n < 16 && n != 14 => conf.roms.push((n, String::from(p))),
                    _ => {
                        usage();
                        return 2;
                    }
                }
            }
            "-nosound" => conf.sound = false,
            "-scale" => {
                i += 1;
                conf.scale = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            s if s.starts_with('-') => {
                println!("beeb: unknown option {}", s);
                usage();
                return 2;
            }
            s => conf.disc = Some(String::from(s)),
        }
        i += 1;
    }

    let mos_path = conf.mos.clone().unwrap_or_else(|| String::from(DEFAULT_MOS));
    let mos = match read_file(&mos_path) {
        Ok(m) => m,
        Err(e) => {
            missing_mos(&mos_path, e);
            return 1;
        }
    };
    if mos.len() != 16384 {
        println!("beeb: '{}' is {} bytes; the MOS ROM must be exactly 16384 bytes.", mos_path, mos.len());
        return 1;
    }
    let disc = match &conf.disc {
        Some(p) => match read_file(p) {
            Ok(d) => Some(d),
            Err(e) => {
                println!("beeb: cannot read the disc image '{}' (error {})", p, e);
                return 1;
            }
        },
        None => None,
    };

    let mut beeb = Beeb::new(&mos);
    for (slot, path) in conf.roms.iter() {
        match read_file(path) {
            Ok(r) => beeb.insert_rom(*slot, &r),
            Err(e) => {
                println!("beeb: cannot read the ROM '{}' (error {})", path, e);
                return 1;
            }
        }
    }
    let boot = disc.is_some();
    if let Some(d) = disc {
        beeb.insert_disc(d);
    }
    beeb.reset(boot);

    let fb = match screen::acquire() {
        Ok(f) => f,
        Err(e) => {
            println!("beeb: cannot get the screen (error {}); run it on the console", e);
            return 1;
        }
    };
    if screen::kbd_raw(true) < 0 {
        screen::release();
        println!("beeb: cannot switch the keyboard to raw mode (another program owns it)");
        return 1;
    }
    let black = native(&fb, 0);
    unsafe {
        for p in fb.pixels().iter_mut() {
            *p = black;
        }
    }
    // Sound: mono, 48 kHz. No sound card (or -nosound): run silently.
    let audio = if conf.sound { liboos::audio::Audio::open(AUDIO_RATE, 1).ok() } else { None };
    if let Some(a) = &audio {
        beeb.set_audio_rate(AUDIO_RATE);
        // prime about 60 ms of silence so the first frames do not underrun
        a.write(&[0i16; 2880]);
    }
    let lay = layout(&fb, conf.scale);
    let mut prev = vec![0u32; SCREEN_W * SCREEN_H];
    let mut force = true;
    let mut frames: u64 = 0;
    let mut next = screen::clock_ns();
    let mut late = 0u32;

    'run: loop {
        while let Some(ev) = screen::key_event() {
            if !ev.extended && ev.pressed {
                if ev.code == SC_F12 {
                    break 'run;
                }
                if ev.code == SC_F11 {
                    beeb.reset(boot);
                    continue;
                }
            }
            if let Some(key) = keymap::map(ev.code, ev.extended) {
                beeb.key(key, ev.pressed);
            }
        }
        beeb.run_frame();
        let samples = beeb.audio();
        if let Some(a) = &audio {
            // keep 60..100 ms queued: when more than 100 ms is waiting, drop this frame's samples
            if a.queued() <= AUDIO_MAX_QUEUE {
                a.write(samples);
            }
        }
        blit(&fb, &lay, beeb.screen(), &mut prev, force);
        force = false;
        screen::flush();
        frames += 1;

        next += FRAME_NS;
        let now = screen::clock_ns();
        if now > next + 5 * FRAME_NS {
            // far behind (slow machine): do not try to catch up
            next = now;
            late += 1;
        }
        loop {
            let now = screen::clock_ns();
            if now >= next {
                break;
            }
            if next - now > 12_000_000 {
                screen::sleep_ms((next - now) / 1_000_000 - 10);
            } else {
                core::hint::spin_loop();
            }
        }
    }

    screen::kbd_raw(false);
    screen::release();
    print!("beeb: {} frames", frames);
    if late > 0 {
        print!(", fell behind {} times", late);
    }
    println!();
    0
}
