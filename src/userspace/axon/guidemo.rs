/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

guidemo — the oos-ui reference desktop on the real framebuffer.

Renders the same desktop as gui/mockups/desktop.png (oos-ui crate, software
rendering), moves the pointer with the mouse (PS/2, USB, VMMouse), lets you
click buttons/toggles, drag windows and type into text fields.  Esc restores
the console screen.  Frame times are printed on exit (and to serial).

  guidemo           run the demo
  guidemo bench     render a few full frames, print timings, return
*/

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use oos_ui::demo::Demo;
use oos_ui::event::{Event, Key, Modifiers, MouseButton};
use oos_ui::geom::Rect;
use oos_ui::theme::DARK;

use crate::arch::x86_64::{framebuffer, keyboard, mouse, serial, tsc};
use crate::userspace::plum::io;

struct Fb {
    base: *mut u32,
    width: i32,
    height: i32,
    stride: usize,
    native: bool,
    shifts: (u8, u8, u8),
}

impl Fb {
    /// Copy damaged rectangles of the back buffer to the screen.
    fn present(&self, back: &oos_ui::Surface, rects: &[Rect]) {
        for r in rects {
            let r = r.intersect(&Rect::new(0, 0, self.width.min(back.width), self.height.min(back.height)));
            if r.is_empty() { continue; }
            for y in r.y..r.bottom() {
                let src = &back.data[y as usize * back.stride + r.x as usize..][..r.w as usize];
                unsafe {
                    let dst = self.base.add(y as usize * self.stride + r.x as usize);
                    if self.native {
                        core::ptr::copy_nonoverlapping(src.as_ptr(), dst, r.w as usize);
                    } else {
                        let (rs, gs, bs) = self.shifts;
                        for (i, &p) in src.iter().enumerate() {
                            let v = ((p >> 16) & 0xFF) << rs | ((p >> 8) & 0xFF) << gs | (p & 0xFF) << bs;
                            *dst.add(i) = v;
                        }
                    }
                }
            }
        }
        // VMware SVGA II in FIFO mode needs an explicit update (no-op otherwise).
        if !rects.is_empty() { crate::drivers::gpu::flush_screen(); }
    }
}

fn clock_text() -> String {
    const WD: [&str; 7] = ["Чт", "Пт", "Сб", "Вс", "Пн", "Вт", "Ср"];
    const MON: [&str; 12] = ["янв.", "февр.", "мар.", "апр.", "мая", "июн.", "июл.", "авг.", "сент.", "окт.", "нояб.", "дек."];
    let ns = crate::time::now();
    let t = crate::time::to_civil(ns);
    let days = crate::time::to_unix_secs(ns).div_euclid(86_400);
    format!("{} {} {}  {:02}:{:02}", WD[days.rem_euclid(7) as usize], t.day, MON[(t.month as usize).clamp(1, 12) - 1], t.hour, t.minute)
}

fn key_event(c: char) -> Option<Event> {
    let none = Modifiers::NONE;
    let (key, text, mods) = match c {
        '\n' | '\r' => (Key::Enter, None, none),
        '\x08' => (Key::Backspace, None, none),
        '\t' => (Key::Tab, None, none),
        '\x01' => (Key::Char('a'), None, Modifiers::CTRL),
        keyboard::KEY_LEFT => (Key::Left, None, none),
        keyboard::KEY_RIGHT => (Key::Right, None, none),
        keyboard::KEY_UP => (Key::Up, None, none),
        keyboard::KEY_DOWN => (Key::Down, None, none),
        keyboard::KEY_HOME => (Key::Home, None, none),
        keyboard::KEY_END => (Key::End, None, none),
        keyboard::KEY_PGUP => (Key::PageUp, None, none),
        keyboard::KEY_PGDN => (Key::PageDown, None, none),
        keyboard::KEY_DELETE => (Key::Delete, None, none),
        c if !c.is_control() && (c as u32) < 0x80 => (Key::Char(c), Some(c), none),
        _ => return None,
    };
    Some(Event::KeyDown { key, mods, text })
}

#[derive(Default)]
struct Stats {
    frames: u64,
    total_us: u64,
    max_us: u64,
    min_us: u64,
    pixels: u64,
}

impl Stats {
    fn add(&mut self, us: u64, rects: &[Rect]) {
        if self.frames == 0 || us < self.min_us { self.min_us = us; }
        self.frames += 1;
        self.total_us += us;
        self.max_us = self.max_us.max(us);
        self.pixels += rects.iter().map(|r| r.area() as u64).sum::<u64>();
    }
    fn line(&self, name: &str) -> String {
        if self.frames == 0 { return format!("  {:<18} -\n", name); }
        format!("  {:<18} {:>5} frames  avg {:>6} us  min {:>6} us  max {:>6} us  avg area {} px\n",
            name, self.frames, self.total_us / self.frames, self.min_us, self.max_us, self.pixels / self.frames)
    }
}

pub fn run(args: &str) {
    let info = match framebuffer::info() {
        Some(i) if i.bpp == 32 => i,
        _ => { io::err("guidemo: no 32-bpp framebuffer\n"); return; }
    };
    let fb = Fb {
        base: info.address,
        width: info.width as i32,
        height: info.height as i32,
        stride: (info.pitch / 4) as usize,
        native: info.red_shift == 16 && info.green_shift == 8 && info.blue_shift == 0,
        shifts: (info.red_shift, info.green_shift, info.blue_shift),
    };
    let bench = args.trim() == "bench";

    // Save the console so Esc can restore it exactly.
    let saved_len = fb.stride * fb.height as usize;
    let mut saved: Vec<u32> = Vec::with_capacity(saved_len);
    unsafe {
        core::ptr::copy_nonoverlapping(fb.base, saved.as_mut_ptr(), saved_len);
        saved.set_len(saved_len);
    }
    let cursor = framebuffer::cursor_pos();

    let theme = DARK;
    let t0 = tsc::tsc_us();
    let mut text = oos_ui::fonts::default_text_engine();
    let t_fonts = tsc::tsc_us() - t0;
    let t1 = tsc::tsc_us();
    let mut demo = Demo::new(fb.width, fb.height, &mut text, &theme);
    demo.desktop.set_clock(&clock_text(), &theme);
    let t_build = tsc::tsc_us() - t1;

    // Frame 1: everything cold (layout, glyph rasterisation, shadow masks).
    let start = tsc::tsc_us();
    let f = tsc::tsc_us();
    let rects = demo.frame(0, &mut text, &theme);
    let t_render1 = tsc::tsc_us() - f;
    let p = tsc::tsc_us();
    fb.present(&demo.desktop.back, &rects);
    let t_present_full = tsc::tsc_us() - p;
    // Frame 2: full redraw with warm caches.
    demo.desktop.invalidate_all();
    for w in demo.desktop.windows.iter_mut() { w.invalidate_all(); }
    let f = tsc::tsc_us();
    let rects = demo.frame(0, &mut text, &theme);
    let t_render2 = tsc::tsc_us() - f;
    fb.present(&demo.desktop.back, &rects);
    // Frame 3: recomposite only (window surfaces unchanged).
    demo.desktop.invalidate_all();
    let f = tsc::tsc_us();
    let rects = demo.frame(0, &mut text, &theme);
    let t_compose = tsc::tsc_us() - f;
    fb.present(&demo.desktop.back, &rects);

    let mut st_pointer = Stats::default();
    let mut st_other = Stats::default();
    let mut last_clock = 0u64;

    if !bench {
        while keyboard::try_read_key().is_some() {}
        let _ = mouse::poll();
        let mut buttons = 0u8;
        let mut abs_seen = false;
        'main: loop {
            let mut pointer_moved = false;
            let mut any = false;
            // Keyboard.
            while let Some(c) = keyboard::try_read_key() {
                if c == '\x1b' { break 'main; }
                if let Some(ev) = key_event(c) { demo.handle(&ev, &mut text, &theme); any = true; }
            }
            // Mouse: relative PS/2 / USB deltas, or VMMouse absolute.
            let (dx, dy, b) = mouse::poll();
            let mut nb = b;
            let (cx, cy) = (demo.desktop.cursor.x, demo.desktop.cursor.y);
            let (mut nx, mut ny) = (cx + dx, cy - dy);
            if crate::drivers::gpu::is_absolute() {
                if let Some(ev) = crate::drivers::gpu::mouse_poll() {
                    nx = (ev.x as i64 * fb.width as i64 / 65536) as i32;
                    ny = (ev.y as i64 * fb.height as i64 / 65536) as i32;
                    nb = ev.buttons;
                    abs_seen = true;
                    if ev.scroll != 0 {
                        demo.handle(&Event::Wheel { x: nx, y: ny, dy: -(ev.scroll as i32) }, &mut text, &theme);
                    }
                } else if abs_seen {
                    nb = buttons;
                }
            }
            let (nx, ny) = (nx.clamp(0, fb.width - 1), ny.clamp(0, fb.height - 1));
            if nx != cx || ny != cy {
                demo.handle(&Event::PointerMove { x: nx, y: ny }, &mut text, &theme);
                pointer_moved = true;
            }
            for (bit, btn) in [(1u8, MouseButton::Left), (2, MouseButton::Right), (4, MouseButton::Middle)] {
                if nb & bit != buttons & bit {
                    let ev = if nb & bit != 0 { Event::PointerDown { x: nx, y: ny, button: btn } } else { Event::PointerUp { x: nx, y: ny, button: btn } };
                    demo.handle(&ev, &mut text, &theme);
                    any = true;
                }
            }
            buttons = nb;

            let now = tsc::tsc_us();
            let now_ms = (now - start) / 1000;
            if now_ms / 1000 != last_clock {
                last_clock = now_ms / 1000;
                demo.desktop.set_clock(&clock_text(), &theme);
            }
            let f = tsc::tsc_us();
            let rects = demo.frame(now_ms, &mut text, &theme);
            if !rects.is_empty() {
                fb.present(&demo.desktop.back, &rects);
                let us = tsc::tsc_us() - f;
                if pointer_moved && !any { st_pointer.add(us, &rects); } else { st_other.add(us, &rects); }
            } else if !pointer_moved && !any {
                unsafe { core::arch::asm!("hlt"); }
            }
        }
    }

    // Restore the console.
    unsafe { core::ptr::copy_nonoverlapping(saved.as_ptr(), fb.base, saved_len); }
    crate::drivers::gpu::flush_screen();
    framebuffer::set_cursor_pos(cursor.0, cursor.1);
    drop(saved);

    let mut s = format!("guidemo: {}x{}, oos-ui software renderer, TSC {} MHz\n", fb.width, fb.height, tsc::mhz());
    s += &format!("  fonts parsed       {:>6} us\n  desktop built      {:>6} us\n", t_fonts, t_build);
    s += &format!("  first frame        {:>6} us  (cold: layout, glyphs, shadows)\n", t_render1);
    s += &format!("  full redraw        {:>6} us  (warm caches, all windows repainted)\n", t_render2);
    s += &format!("  recomposite        {:>6} us  (window surfaces reused)\n", t_compose);
    s += &format!("  present full       {:>6} us  (back buffer -> framebuffer)\n", t_present_full);
    s += &st_pointer.line("pointer-only");
    s += &st_other.line("input/animation");
    io::out(&s);
    for line in s.lines() { serial::write_str("[GUIDEMO] "); serial::write_str(line); serial::write_str("\r\n"); }
}
