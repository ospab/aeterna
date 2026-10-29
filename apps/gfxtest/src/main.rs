// SPDX-License-Identifier: AGPL-3.0-only
//! gfxtest: proves the ring-3 screen, raw keyboard and clock calls. Draws a rotating
//! wireframe square on a black screen. Esc or q quits (so does Ctrl+C); it also stops by itself
//! after `gfxtest N` seconds (default 10). `gfxtest -n` leaves the keyboard in line mode. Prints the event and frame counts at the end.
#![no_std]
#![no_main]

use liboos::screen::{self, Framebuffer};
use liboos::println;

liboos::entry!(main);

// Fixed-point sine table, 256 steps per turn, scale 1024.
fn sin256(a: u32) -> i32 {
    // Bhaskara-style parabola approximation, good enough for a demo.
    let a = (a & 255) as i32;
    let (x, sign) = if a < 128 { (a, 1) } else { (a - 128, -1) };
    // sin(pi * x / 128) ~ 4x(128-x) / (16384/... ) ; peak at x=64: 4*64*64 = 16384 -> 1024
    sign * (4 * x * (128 - x) / 16)
}

fn line(fb: &Framebuffer, px: &mut [u32], x0: i32, y0: i32, x1: i32, y1: i32, c: u32) {
    let stride = fb.stride() as i32;
    let (mut x, mut y) = (x0, y0);
    let dx = (x1 - x0).abs();
    let dy = -(y1 - y0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;
    loop {
        if x >= 0 && y >= 0 && x < fb.width as i32 && y < fb.height as i32 {
            px[(y * stride + x) as usize] = c;
        }
        if x == x1 && y == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x += sx;
        }
        if e2 <= dx {
            err += dx;
            y += sy;
        }
    }
}

fn main(args: liboos::Args) -> i32 {
    let mut seconds = 10u64;
    let mut raw = true;
    if args.len() > 1 {
        if let Some(a) = args.get(1) {
            if a == "-n" {
                raw = false;
                seconds = 60;
            }
            let mut n = 0u64;
            for b in a.bytes() {
                if b.is_ascii_digit() {
                    n = n * 10 + (b - b'0') as u64;
                }
            }
            if n > 0 {
                seconds = n;
            }
        }
    }
    let fb = match screen::acquire() {
        Ok(f) => f,
        Err(e) => {
            println!("gfxtest: cannot get the screen (error {})", e);
            return 1;
        }
    };
    if raw && screen::kbd_raw(true) < 0 {
        screen::release();
        println!("gfxtest: cannot switch the keyboard to raw mode");
        return 1;
    }
    let px = unsafe { fb.pixels() };
    let black = fb.rgb(0, 0, 0);
    let green = fb.rgb(80, 255, 120);
    let white = fb.rgb(255, 255, 255);
    for p in px.iter_mut() {
        *p = black;
    }
    let (cx, cy) = (fb.width as i32 / 2, fb.height as i32 / 2);
    let r = (fb.height.min(fb.width) as i32) / 4;
    let t0 = screen::clock_ns();
    let mut frames = 0u32;
    let mut events = 0u32;
    let mut last: Option<screen::KeyEvent> = None;
    let mut quit = false;
    while !quit && screen::clock_ns() - t0 < seconds * 1_000_000_000 {
        let frame_start = screen::clock_ns();
        while let Some(ev) = screen::key_event() {
            events += 1;
            last = Some(ev);
            // Esc = 0x01, Q = 0x10
            if ev.pressed && (ev.code == 0x01 || ev.code == 0x10) {
                quit = true;
            }
        }
        // erase the previous frame's bounding box
        let b = r * 3 / 2 + 2;
        for y in (cy - b).max(0)..(cy + b).min(fb.height as i32) {
            let row = y as usize * fb.stride();
            for x in (cx - b).max(0)..(cx + b).min(fb.width as i32) {
                px[row + x as usize] = black;
            }
        }
        let ang = (frames % 256) as u32;
        let (s, c) = (sin256(ang), sin256(ang + 64));
        let mut pts = [(0i32, 0i32); 4];
        let corners = [(-1, -1), (1, -1), (1, 1), (-1, 1)];
        for (i, (kx, ky)) in corners.iter().enumerate() {
            let (x, y) = (kx * r, ky * r);
            pts[i] = (cx + (x * c - y * s) / 1024, cy + (x * s + y * c) / 1024);
        }
        for i in 0..4 {
            let (a, b2) = (pts[i], pts[(i + 1) % 4]);
            line(&fb, px, a.0, a.1, b2.0, b2.1, green);
        }
        // key indicator: a small white box while any key was pressed last
        if let Some(ev) = last {
            if ev.pressed {
                for y in 8..24 {
                    for x in 8..24 {
                        px[y * fb.stride() + x] = white;
                    }
                }
            } else {
                for y in 8..24 {
                    for x in 8..24 {
                        px[y * fb.stride() + x] = black;
                    }
                }
            }
        }
        screen::flush();
        frames += 1;
        // 50 frames per second
        let target = frame_start + 20_000_000;
        while screen::clock_ns() < target {
            if target - screen::clock_ns() > 12_000_000 {
                screen::sleep_ms((target - screen::clock_ns()) / 1_000_000 - 10);
            } else {
                core::hint::spin_loop();
            }
        }
    }
    let elapsed_ms = (screen::clock_ns() - t0) / 1_000_000;
    screen::kbd_raw(false);
    screen::release();
    println!("gfxtest: {} frames in {} ms, {} key events", frames, elapsed_ms, events);
    0
}
