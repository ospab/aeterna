// SPDX-License-Identifier: AGPL-3.0-only
//! 6845 CRTC + video ULA + SAA5050-style teletext, rendered one scan line (128 CPU cycles) at a
//! time so register writes made mid-frame by interrupts show up on the right line.
//!
//! The 640x256 output has its origin at the first displayed line / column of the standard modes;
//! other CRTC settings move the picture relative to that (R2/R3 horizontal, R7/R3 vertical).
//! Teletext glyphs reuse the 8x8 font of the user-supplied MOS ROM (chars 0x20..0x7F at the start
//! of the ROM image), so no font data is embedded here.

use crate::machine::{SCREEN_H, SCREEN_W};
use alloc::vec;
use alloc::vec::Vec;

const RGB: [u32; 8] = [0x000000, 0xFF0000, 0x00FF00, 0xFFFF00, 0x0000FF, 0xFF00FF, 0x00FFFF, 0xFFFFFF];
const STD_TOP: i32 = 38;
const TT_TOP: i32 = 27;
const STD_LEFT_PX: i32 = 176;

pub struct LineEvents {
    pub vsync_start: bool,
    pub vsync_end: bool,
}

pub struct Video {
    pub crtc: [u8; 18],
    pub crtc_sel: u8,
    pub ula: u8,
    pub pal: [u8; 16],
    pub fb: Vec<u32>,
    pub frame_done: bool,
    pub frame: u64,
    row: u32,
    ra: u32,
    adjust: u32,
    in_adjust: bool,
    ma_row: u16,
    start: u16,
    vsync_left: u32,
    vs_seen: bool,
    tvline: i32,
    odd: bool,
    tt_last_dh: bool,
    tt_bottom: bool,
}

impl Video {
    pub fn new() -> Self {
        Video {
            crtc: [0; 18], crtc_sel: 0, ula: 0, pal: [0; 16], fb: vec![0; SCREEN_W * SCREEN_H],
            frame_done: false, frame: 0, row: 0, ra: 0, adjust: 0, in_adjust: false, ma_row: 0,
            start: 0, vsync_left: 0, vs_seen: false, tvline: 0, odd: false, tt_last_dh: false,
            tt_bottom: false,
        }
    }

    pub fn crtc_read(&self) -> u8 {
        match self.crtc_sel { 14..=17 => self.crtc[self.crtc_sel as usize], _ => 0 }
    }

    pub fn crtc_write(&mut self, v: u8) {
        let s = self.crtc_sel as usize;
        if s < 18 { self.crtc[s] = v; }
    }

    pub fn palette_write(&mut self, v: u8) { self.pal[(v >> 4) as usize] = v & 15; }

    pub fn tvline(&self) -> i32 { self.tvline }

    fn rows_per_char(&self) -> u32 {
        let r9 = self.crtc[9] as u32;
        if self.crtc[8] & 3 == 3 { (r9 >> 1) + 1 } else { r9 + 1 }
    }

    fn new_frame(&mut self) {
        self.row = 0;
        self.ra = 0;
        self.in_adjust = false;
        self.start = (((self.crtc[12] as u16) << 8) | self.crtc[13] as u16) & 0x3FFF;
        self.ma_row = self.start;
        self.vs_seen = false;
        self.odd = !self.odd;
        self.tt_last_dh = false;
    }

    pub fn line(&mut self, ram: &[u8], wrap: u32, mos: &[u8]) -> LineEvents {
        let rpr = self.rows_per_char();
        let displayed = !self.in_adjust && self.row < self.crtc[6] as u32 && self.ra < rpr;
        let tele = self.ula & 2 != 0;
        let y = self.tvline - if tele { TT_TOP } else { STD_TOP };
        if displayed && y >= 0 && (y as usize) < SCREEN_H {
            if tele { self.render_tele(y as usize, ram, mos) } else { self.render_bitmap(y as usize, ram, wrap) }
        }
        if self.in_adjust {
            self.adjust -= 1;
            if self.adjust == 0 { self.new_frame(); }
        } else {
            self.ra += 1;
            if self.ra >= rpr {
                self.ra = 0;
                if self.row >= self.crtc[4] as u32 {
                    let adj = self.crtc[5] as u32;
                    if adj > 0 { self.in_adjust = true; self.adjust = adj; } else { self.new_frame(); }
                } else {
                    self.row += 1;
                    self.ma_row = self.ma_row.wrapping_add(self.crtc[1] as u16) & 0x3FFF;
                }
            }
        }
        let mut ev = LineEvents { vsync_start: false, vsync_end: false };
        if self.vsync_left > 0 {
            self.vsync_left -= 1;
            if self.vsync_left == 0 { ev.vsync_end = true; }
        } else if !self.in_adjust && !self.vs_seen && self.ra == 0 && self.row == self.crtc[7] as u32 {
            let w = (self.crtc[3] >> 4) as u32;
            self.vsync_left = if w == 0 { 16 } else { w };
            self.vs_seen = true;
            ev.vsync_start = true;
            self.frame_done = true;
            self.frame += 1;
        }
        if ev.vsync_end {
            self.tvline = 0;
            for p in self.fb.iter_mut() { *p = 0; }
        } else {
            self.tvline += 1;
        }
        ev
    }

    fn x_origin(&self, charpx: i32) -> i32 {
        let r = &self.crtc;
        let sw = if r[3] & 15 == 0 { 16 } else { (r[3] & 15) as i32 };
        let border = r[0] as i32 + 1 - (r[2] as i32 + sw);
        border * charpx - STD_LEFT_PX
    }

    fn render_bitmap(&mut self, y: usize, ram: &[u8], wrap: u32) {
        if self.ra >= 8 { return; }
        let two = self.ula & 0x10 != 0;
        let charpx: i32 = if two { 8 } else { 16 };
        let pixclk: u32 = 2 << ((self.ula >> 2) & 3);
        let ppb = (pixclk / if two { 2 } else { 1 }).clamp(1, 8);
        let opp = (charpx as u32 / ppb).max(1) as usize;
        let flash = self.ula & 1 != 0;
        let mut rgb = [0u32; 16];
        for i in 0..16 {
            let d = self.pal[i];
            let mut c = (d & 7) ^ 7;
            if d & 8 != 0 && flash { c ^= 7; }
            rgb[i] = RGB[c as usize];
        }
        let x0 = self.x_origin(charpx);
        let cols = (self.crtc[1] as usize).min(128);
        let line = &mut self.fb[y * SCREEN_W..(y + 1) * SCREEN_W];
        for c in 0..cols {
            let ma = (self.ma_row as u32 + c as u32) & 0x3FFF;
            let mut a = (ma << 3) | self.ra;
            if a >= 0x8000 { a = a.wrapping_sub(wrap); }
            let v = ram[(a & 0x7FFF) as usize] as u32;
            for p in 0..ppb {
                let s = v << p;
                let idx = ((s >> 4) & 8) | ((s >> 3) & 4) | ((s >> 2) & 2) | ((s >> 1) & 1);
                let col = rgb[idx as usize];
                let xs = x0 + c as i32 * charpx + (p as usize * opp) as i32;
                for k in 0..opp as i32 {
                    let x = xs + k;
                    if x >= 0 && (x as usize) < SCREEN_W { line[x as usize] = col; }
                }
            }
        }
    }

    fn render_tele(&mut self, y: usize, ram: &[u8], mos: &[u8]) {
        let ra = self.ra as usize;
        let cols = (self.crtc[1] as usize).min(40);
        let base = self.ma_row as usize;
        let code_at = |c: usize| ram[0x7C00 + ((base + c) & 0x3FF)] & 0x7F;
        if self.ra == 0 {
            self.tt_bottom = self.tt_last_dh;
            let mut has = false;
            for c in 0..cols { if code_at(c) == 0x0D { has = true; } }
            self.tt_last_dh = has && !self.tt_bottom;
        }
        let bottom = self.tt_bottom;
        let flash_off = (self.frame / 25) & 1 == 1;
        let (mut fg, mut bg) = (7u8, 0u8);
        let (mut gfx, mut sep, mut flash, mut dh, mut hold, mut conceal) = (false, false, false, false, false, false);
        let mut held = 0x20u8;
        let line = &mut self.fb[y * SCREEN_W..(y + 1) * SCREEN_W];
        for c in 0..cols {
            let code = code_at(c);
            let ctrl = code < 0x20;
            if ctrl {
                match code {
                    0x09 => flash = false,
                    0x0C => dh = false,
                    0x18 => conceal = true,
                    0x19 => sep = false,
                    0x1A => sep = true,
                    0x1C => bg = 0,
                    0x1D => bg = fg,
                    0x1E => hold = true,
                    _ => {}
                }
            }
            let (glyph, g_gfx, g_sep) = if ctrl {
                if hold && gfx { (held, true, sep) } else { (0x20, false, false) }
            } else {
                (code, gfx && !(0x40..0x60).contains(&code), sep)
            };
            if !ctrl && g_gfx { held = code; }
            let sl = if dh { if bottom { 5 + ra / 2 } else { ra / 2 } } else { ra };
            let hidden = (flash && flash_off) || conceal;
            let (fgc, bgc) = (RGB[fg as usize], RGB[bg as usize]);
            for x in 0..16usize {
                let on = if hidden || (glyph == 0x20 && !g_gfx) {
                    false
                } else if g_gfx {
                    let band = if sl < 3 { 0 } else if sl < 7 { 1 } else { 2 };
                    let right = x >= 8;
                    let bit = match (band, right) {
                        (0, false) => 1, (0, true) => 2, (1, false) => 4, (1, true) => 8,
                        (2, false) => 0x10, _ => 0x40,
                    };
                    let gap = g_sep && ((x & 7) == 0 || (x & 7) == 7 || sl == 2 || sl == 6 || sl == 9);
                    glyph & bit != 0 && !gap
                } else if sl < 8 && (0x20..0x80).contains(&(glyph as usize)) {
                    let fo = (glyph as usize - 0x20) * 8 + sl;
                    let b = if fo < mos.len() { mos[fo] } else { 0 };
                    b & (0x80 >> (x / 2)) != 0
                } else {
                    false
                };
                line[c * 16 + x] = if on { fgc } else { bgc };
            }
            if ctrl {
                match code {
                    1..=7 => { fg = code; gfx = false; conceal = false; held = 0x20; }
                    0x08 => flash = true,
                    0x0D => dh = true,
                    0x11..=0x17 => { fg = code & 7; gfx = true; conceal = false; }
                    0x1F => hold = false,
                    _ => {}
                }
            }
        }
        for x in cols * 16..SCREEN_W { line[x] = 0; }
    }
}
