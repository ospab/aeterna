// SPDX-License-Identifier: AGPL-3.0-only
//! Procedural line icons (16-px grid, 1.5-px strokes), drawn with canvas
//! primitives so they stay sharp at any size and need no image assets.

use crate::canvas::Canvas;
use crate::color::Color;
use crate::geom::Rect;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Folder,
    File,
    FileCode,
    FileImage,
    FileArchive,
    Terminal,
    Settings,
    Search,
    ChevronLeft,
    ChevronRight,
    ChevronDown,
    Close,
    Minimize,
    Check,
    Plus,
    Wifi,
    Volume,
    Power,
    Grid,
    Logo,
    Display,
    Network,
    Keyboard,
    Lock,
    Info,
    Sound,
}

/// Draw `icon` centred in `r` (designed for 16x16; scales with min(w, h)).
pub fn draw(c: &mut Canvas, icon: Icon, r: Rect, color: Color) {
    let s = r.w.min(r.h) as f32 / 16.0;
    let ox = r.x as f32 + (r.w as f32 - 16.0 * s) / 2.0;
    let oy = r.y as f32 + (r.h as f32 - 16.0 * s) / 2.0;
    let p = |x: f32, y: f32| (ox + x * s, oy + y * s);
    let lw = 1.5 * s;
    let line = |c: &mut Canvas, a: (f32, f32), b: (f32, f32)| {
        let (a, b) = (p(a.0, a.1), p(b.0, b.1));
        c.line(a.0, a.1, b.0, b.1, lw, color)
    };
    let rr = |c: &mut Canvas, x: f32, y: f32, w: f32, h: f32, rad: f32, fill: bool| {
        let (x0, y0) = p(x, y);
        let rect = Rect::new(x0 as i32, y0 as i32, (w * s + 0.5) as i32, (h * s + 0.5) as i32);
        if fill { c.fill_round_rect(rect, (rad * s) as i32, color) } else { c.stroke_round_rect(rect, (rad * s + 0.5) as i32, ((1.5 * s) as i32).max(1), color) }
    };
    match icon {
        Icon::Folder => {
            rr(c, 1.0, 3.0, 6.5, 3.0, 1.5, true);
            rr(c, 1.0, 4.5, 14.0, 9.5, 2.0, true);
        }
        Icon::File | Icon::FileCode | Icon::FileImage | Icon::FileArchive => {
            rr(c, 3.0, 1.0, 10.0, 14.0, 2.0, false);
            match icon {
                Icon::FileCode => {
                    line(c, (7.0, 6.5), (5.5, 8.5));
                    line(c, (5.5, 8.5), (7.0, 10.5));
                    line(c, (9.0, 6.5), (10.5, 8.5));
                    line(c, (10.5, 8.5), (9.0, 10.5));
                }
                Icon::FileImage => {
                    let (cx, cy) = p(10.0, 5.5);
                    c.fill_circle(cx, cy, 1.2 * s, color);
                    line(c, (5.0, 12.0), (7.5, 8.5));
                    line(c, (7.5, 8.5), (9.5, 11.0));
                    line(c, (9.5, 11.0), (11.0, 9.5));
                }
                Icon::FileArchive => {
                    for i in 0..4 {
                        let y = 3.0 + i as f32 * 2.0;
                        rr(c, if i % 2 == 0 { 7.0 } else { 8.0 }, y, 1.5, 1.5, 0.0, true);
                    }
                    rr(c, 6.5, 11.0, 3.0, 2.0, 0.5, true);
                }
                _ => {
                    line(c, (6.0, 6.0), (10.0, 6.0));
                    line(c, (6.0, 9.0), (10.0, 9.0));
                    line(c, (6.0, 12.0), (8.5, 12.0));
                }
            }
        }
        Icon::Terminal => {
            rr(c, 1.0, 2.0, 14.0, 12.0, 2.5, false);
            line(c, (4.5, 6.0), (7.0, 8.0));
            line(c, (7.0, 8.0), (4.5, 10.0));
            line(c, (8.5, 10.5), (11.5, 10.5));
        }
        Icon::Settings => {
            let (cx, cy) = p(8.0, 8.0);
            for i in 0..8 {
                let a = i as f32 * core::f32::consts::PI / 4.0;
                let (sn, cs) = (libm::sinf(a), libm::cosf(a));
                c.line(cx + cs * 5.0 * s, cy + sn * 5.0 * s, cx + cs * 7.0 * s, cy + sn * 7.0 * s, 2.2 * s, color);
            }
            c.stroke_circle(cx, cy, 5.2 * s, lw, color);
            c.stroke_circle(cx, cy, 2.2 * s, lw, color);
        }
        Icon::Search => {
            let (cx, cy) = p(7.0, 7.0);
            c.stroke_circle(cx, cy, 4.75 * s, lw, color);
            line(c, (10.5, 10.5), (14.0, 14.0));
        }
        Icon::ChevronLeft => { line(c, (10.0, 3.5), (5.5, 8.0)); line(c, (5.5, 8.0), (10.0, 12.5)); }
        Icon::ChevronRight => { line(c, (6.0, 3.5), (10.5, 8.0)); line(c, (10.5, 8.0), (6.0, 12.5)); }
        Icon::ChevronDown => { line(c, (3.5, 6.0), (8.0, 10.5)); line(c, (8.0, 10.5), (12.5, 6.0)); }
        Icon::Close => { line(c, (4.0, 4.0), (12.0, 12.0)); line(c, (12.0, 4.0), (4.0, 12.0)); }
        Icon::Minimize => { line(c, (4.0, 8.0), (12.0, 8.0)); }
        Icon::Check => { line(c, (3.5, 8.5), (6.5, 11.5)); line(c, (6.5, 11.5), (12.5, 4.5)); }
        Icon::Plus => { line(c, (8.0, 3.0), (8.0, 13.0)); line(c, (3.0, 8.0), (13.0, 8.0)); }
        Icon::Wifi => {
            let (cx, cy) = p(8.0, 13.0);
            let saved = c.save();
            let (_, top) = p(0.0, 0.0);
            c.clip_to(Rect::new(r.x, top as i32, r.w, (cy - top - 1.5 * s) as i32));
            for rad in [4.0f32, 7.5, 11.0] {
                c.stroke_circle(cx, cy, rad * s, lw, color);
            }
            c.restore(saved);
            c.fill_circle(cx, cy - 0.5 * s, 1.3 * s, color);
        }
        Icon::Volume | Icon::Sound => {
            rr(c, 1.5, 6.0, 3.0, 4.0, 0.5, true);
            line(c, (4.5, 6.0), (8.0, 3.0));
            line(c, (8.0, 3.0), (8.0, 13.0));
            line(c, (8.0, 13.0), (4.5, 10.0));
            let (cx, cy) = p(8.0, 8.0);
            let saved = c.save();
            let (lx, _) = p(10.0, 0.0);
            c.clip_to(Rect::new(lx as i32, r.y, r.w, r.h));
            c.stroke_circle(cx, cy, 3.5 * s, lw, color);
            c.stroke_circle(cx, cy, 6.5 * s, lw, color);
            c.restore(saved);
        }
        Icon::Power => {
            let (cx, cy) = p(8.0, 8.5);
            let gap = 2.6 * s;
            // Ring with a gap at the top: draw it through three clips.
            for clip in [
                Rect::new(r.x, r.y, (cx - gap) as i32 - r.x, r.h),
                Rect::new((cx + gap) as i32 + 1, r.y, r.right() - (cx + gap) as i32 - 1, r.h),
                Rect::new(r.x, (cy - 2.0 * s) as i32, r.w, r.bottom() - (cy - 2.0 * s) as i32),
            ] {
                let saved = c.save();
                c.clip_to(clip);
                c.stroke_circle(cx, cy, 5.5 * s, lw, color);
                c.restore(saved);
            }
            line(c, (8.0, 1.5), (8.0, 7.5));
        }
        Icon::Grid => {
            for (x, y) in [(2.0, 2.0), (9.0, 2.0), (2.0, 9.0), (9.0, 9.0)] {
                rr(c, x, y, 5.0, 5.0, 1.5, true);
            }
        }
        Icon::Logo => {
            let (cx, cy) = p(8.0, 8.0);
            c.stroke_circle(cx, cy, 6.5 * s, 1.75 * s, color);
            let (dx, dy) = p(12.6, 3.4);
            c.fill_circle(dx, dy, 2.0 * s, color);
        }
        Icon::Display => {
            rr(c, 1.0, 2.0, 14.0, 9.5, 2.0, false);
            line(c, (5.5, 14.0), (10.5, 14.0));
            line(c, (8.0, 11.5), (8.0, 14.0));
        }
        Icon::Network => {
            let (cx, cy) = p(8.0, 8.0);
            c.stroke_circle(cx, cy, 6.5 * s, lw, color);
            line(c, (1.5, 8.0), (14.5, 8.0));
            line(c, (8.0, 1.5), (6.0, 8.0));
            line(c, (6.0, 8.0), (8.0, 14.5));
            line(c, (8.0, 1.5), (10.0, 8.0));
            line(c, (10.0, 8.0), (8.0, 14.5));
        }
        Icon::Keyboard => {
            rr(c, 1.0, 3.5, 14.0, 9.0, 2.0, false);
            for (x, y) in [(4.0, 6.5), (6.5, 6.5), (9.0, 6.5), (11.5, 6.5)] {
                let (a, b) = p(x, y);
                c.fill_circle(a + 0.5 * s, b, 0.8 * s, color);
            }
            line(c, (5.0, 9.5), (11.0, 9.5));
        }
        Icon::Lock => {
            rr(c, 3.0, 7.0, 10.0, 7.5, 2.0, true);
            let (cx, cy) = p(8.0, 6.5);
            let saved = c.save();
            c.clip_to(Rect::new(r.x, r.y, r.w, (cy - r.y as f32) as i32 + 1));
            c.stroke_circle(cx, cy, 3.25 * s, lw, color);
            c.restore(saved);
            line(c, (4.75, 6.5), (4.75, 7.5));
            line(c, (11.25, 6.5), (11.25, 7.5));
        }
        Icon::Info => {
            let (cx, cy) = p(8.0, 8.0);
            c.stroke_circle(cx, cy, 6.5 * s, lw, color);
            line(c, (8.0, 7.5), (8.0, 11.5));
            let (dx, dy) = p(8.0, 5.0);
            c.fill_circle(dx, dy, 1.0 * s, color);
        }
    }
}
