// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! drift front end (ring 3): maps the framebuffer, turns raw scancodes into game actions, paces
//! frames, and stores commanders and settings in files. All game logic is in `drift-core`.
#![no_std]
#![no_main]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use drift_core::commander::{SAVE_SIZE, SAVE_SLOTS};
use drift_core::game::{Act, Game, Io};
use drift_core::gfx::Canvas;
use liboos::println;
use liboos::screen::{self, Framebuffer};

liboos::entry!(main);

/// Memory the game needs on top of the output canvas (planet and sky textures, scene buffers,
/// meshes). The liboos heap must be large enough for this plus `w * h * 4` bytes.
const BASE_HEAP: usize = 12 * 1024 * 1024;
const FRAME_NS: u64 = 16_666_667;
const DIRS: [&str; 3] = ["/home", "/tmp", ""];

fn map_key(code: u8, ext: bool) -> Option<Act> {
    Some(match (code, ext) {
        (0x01, _) => Act::Back,
        (0x02, _) => Act::N1,
        (0x03, _) => Act::N2,
        (0x04, _) => Act::N3,
        (0x05, _) => Act::N4,
        (0x06, _) => Act::N5,
        (0x0F, _) => Act::Help,
        (0x1C, _) => Act::Enter,
        (0x2A, _) | (0x36, _) => Act::Shift,
        (0x39, _) => Act::Fire,
        (0x1E, _) => Act::Faster,
        (0x2C, _) => Act::Slower,
        (0x32, _) => Act::Missile,
        (0x14, _) => Act::Target,
        (0x15, _) => Act::Untarget,
        (0x2E, _) => Act::Chaff,
        (0x24, _) => Act::Jump,
        (0x23, _) => Act::Hyper,
        (0x22, _) => Act::GalDrive,
        (0x20, _) => Act::Dock,
        (0x19, _) => Act::Pause,
        (0x30, _) => Act::Buy,
        (0x1F, _) => Act::Sell,
        (0x12, _) => Act::Eject,
        (0x3B, _) => Act::F1,
        (0x3C, _) => Act::F2,
        (0x3D, _) => Act::F3,
        (0x3E, _) => Act::F4,
        (0x3F, _) => Act::F5,
        (0x40, _) => Act::F6,
        (0x41, _) => Act::F7,
        (0x42, _) => Act::F8,
        (0x43, _) => Act::F9,
        (0x44, _) => Act::F10,
        (0x57, _) => Act::F11,
        (0x58, _) => Act::F12,
        (0x48, _) => Act::Up,
        (0x50, _) => Act::Down,
        (0x4B, _) => Act::Left,
        (0x4D, _) => Act::Right,
        (0x47, true) => Act::Home,
        (0x53, true) => Act::Del,
        _ => return None,
    })
}

fn slot_name(dir: &str, slot: usize) -> String {
    alloc::format!("{}/drift-slot{}.sav", dir, slot + 1)
}

fn read_file(path: &str, max: usize) -> Option<Vec<u8>> {
    let fd = liboos::open(path, 0);
    if fd < 3 {
        return None;
    }
    let mut buf = alloc::vec![0u8; max];
    let n = liboos::read(fd as u64, &mut buf);
    liboos::close(fd as u64);
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

fn write_file(path: &str, data: &[u8]) -> bool {
    let fd = liboos::open(path, 1);
    if fd < 3 {
        return false;
    }
    let n = liboos::write(fd as u64, data);
    liboos::close(fd as u64);
    n == data.len() as i64
}

fn load_state(game: &mut Game) {
    for slot in 0..SAVE_SLOTS {
        for d in DIRS {
            if let Some(b) = read_file(&slot_name(d, slot), SAVE_SIZE) {
                game.provide_slot(slot, Some(&b));
                break;
            }
        }
    }
    for d in DIRS {
        if let Some(b) = read_file(&alloc::format!("{}/drift.cfg", d), 16) {
            game.provide_settings(&b);
            break;
        }
    }
}

fn store(io: Vec<Io>) {
    for req in io {
        match req {
            Io::WriteSlot { slot, data } => {
                let ok = DIRS.iter().any(|d| write_file(&slot_name(d, slot), &data));
                if !ok {
                    println!("drift: cannot write save slot {}", slot + 1);
                }
            }
            Io::WriteSettings(data) => {
                let _ = DIRS.iter().any(|d| write_file(&alloc::format!("{}/drift.cfg", d), &data));
            }
        }
    }
}

/// Copy the finished canvas into the framebuffer, centred, scaled by an integer factor.
fn present(fb: &Framebuffer, px: &mut [u32], out: &Canvas, scale: usize, xmap: &[usize]) {
    let (ow, oh) = (out.w, out.h);
    let fw = fb.width as usize;
    let stride = fb.stride();
    let x0 = (fw - ow * scale) / 2;
    let y0 = (fb.height as usize - oh * scale) / 2;
    let direct = fb.red_shift == 16 && fb.green_shift == 8 && fb.blue_shift == 0;
    let (rs, gs, bs) = (fb.red_shift as u32, fb.green_shift as u32, fb.blue_shift as u32);
    for y in 0..oh {
        let src = &out.px[y * ow..(y + 1) * ow];
        let base = (y0 + y * scale) * stride + x0;
        if scale == 1 && direct {
            px[base..base + ow].copy_from_slice(src);
        } else {
            let row = &mut px[base..base + ow * scale];
            for (i, d) in row.iter_mut().enumerate() {
                let c = src[xmap[i]];
                *d = if direct { c } else { ((c >> 16) & 255) << rs | ((c >> 8) & 255) << gs | (c & 255) << bs };
            }
        }
        for k in 1..scale {
            let (a, b) = (base, base + k * stride);
            px.copy_within(a..a + ow * scale, b);
        }
    }
}

fn parse_div(args: &liboos::Args) -> Option<usize> {
    let mut i = 1;
    while i + 1 < args.len() {
        if args.get(i) == Some("-r") {
            return args.get(i + 1).and_then(|s| s.parse::<usize>().ok()).filter(|d| (1..=4).contains(d));
        }
        i += 1;
    }
    None
}

fn main(args: liboos::Args) -> i32 {
    if args.get(1) == Some("-h") || args.get(1) == Some("--help") {
        println!("usage: drift [-r N]\n  -r N   render the interface at 1/N of the screen size (default: native)\nF1..F12 screens, Tab key map, Esc pause. See docs/en/drift.md.");
        return 0;
    }
    let fb = match screen::acquire() {
        Ok(f) => f,
        Err(e) => {
            println!("drift: cannot get the screen (error {})", e);
            return 1;
        }
    };
    // pick the interface size: native if the heap can hold it, else smaller
    let mut div = parse_div(&args).unwrap_or(1);
    let (ow, oh) = loop {
        let (w, h) = ((fb.width as usize / div) & !3, fb.height as usize / div);
        let mut probe: Vec<u8> = Vec::new();
        if probe.try_reserve_exact(BASE_HEAP + w * h * 4).is_ok() {
            drop(probe);
            break (w, h);
        }
        if div >= 4 {
            screen::release();
            println!("drift: not enough heap memory (needs about {} MiB, see docs/en/drift.md)", (BASE_HEAP + w * h * 4) >> 20);
            return 1;
        }
        div += 1;
    };
    let mut out = Canvas::new(ow, oh);
    let scale = core::cmp::max(1, core::cmp::min(fb.width as usize / ow, fb.height as usize / oh));
    let xmap: Vec<usize> = (0..ow * scale).map(|x| x / scale).collect();
    if screen::kbd_raw(true) < 0 {
        screen::release();
        println!("drift: cannot switch the keyboard to raw mode");
        return 1;
    }
    let px = unsafe { fb.pixels() };
    for p in px.iter_mut() {
        *p = 0;
    }
    let mut game = Game::new(screen::clock_ns() ^ 0xD1F7);
    load_state(&mut game);
    let mut last = screen::clock_ns();
    let mut ema_ms = 16.0f32;
    let mut frames = 0u64;
    let start = last;
    while !game.quit {
        let frame_start = screen::clock_ns();
        let dt = ((frame_start - last) as f32) * 1e-9;
        last = frame_start;
        let mut ext = false;
        while let Some(ev) = screen::key_event() {
            ext = ev.extended;
            if let Some(a) = map_key(ev.code, ev.extended) {
                game.input.key(a, ev.pressed);
            }
        }
        let _ = ext;
        game.update(dt);
        store(game.take_io());
        game.render(&mut out);
        present(&fb, px, &out, scale, &xmap);
        screen::flush();
        frames += 1;
        let spent = screen::clock_ns() - frame_start;
        ema_ms = ema_ms * 0.9 + (spent as f32 * 1e-6) * 0.1;
        // slow machine: lower the 3D resolution for this run (the saved setting is untouched)
        if frames % 90 == 0 && ema_ms > 38.0 && game.settings.quality > 0 {
            game.settings.quality -= 1;
        }
        let target = frame_start + FRAME_NS;
        while screen::clock_ns() < target {
            if target - screen::clock_ns() > 12_000_000 {
                liboos::yield_now();
            } else {
                core::hint::spin_loop();
            }
        }
    }
    screen::kbd_raw(false);
    screen::release();
    let secs = (screen::clock_ns() - start) / 1_000_000_000;
    println!("drift: {} frames in {} s, average work {:.1} ms per frame, interface {}x{}", frames, secs, ema_ms, ow, oh);
    0
}
