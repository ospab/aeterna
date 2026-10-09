// SPDX-License-Identifier: AGPL-3.0-only
//! Cheap soft shadows.
//!
//! A shadow of a rounded rectangle is drawn as a nine-patch cut from one small
//! blurred alpha mask per (radius, blur) pair.  The mask is rasterised once,
//! blurred with three box-blur passes (a good Gaussian approximation) and
//! cached; drawing is then just mask rows for the corners and constant spans
//! for the edges, regardless of the window size.  The centre, which is
//! normally hidden under the opaque window, can be skipped via `occluder`.

use alloc::vec;
use alloc::vec::Vec;

use crate::canvas::Canvas;
use crate::color::Color;
use crate::geom::Rect;
use crate::math;

/// Shadow parameters (all in px).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shadow {
    pub dx: i32,
    pub dy: i32,
    pub blur: i32,
    /// Grow (+) or shrink (-) the shadow shape relative to the caster.
    pub spread: i32,
    pub color: Color,
}

struct Mask {
    radius: i32,
    blur: i32,
    size: i32,
    corner: i32,
    data: Vec<u8>,
}

/// Cache of blurred nine-patch masks.
#[derive(Default)]
pub struct ShadowCache {
    masks: Vec<Mask>,
}

impl ShadowCache {
    pub fn new() -> Self { ShadowCache { masks: Vec::new() } }

    fn mask(&mut self, radius: i32, blur: i32) -> &Mask {
        if let Some(i) = self.masks.iter().position(|m| m.radius == radius && m.blur == blur) {
            return &self.masks[i];
        }
        let m = build_mask(radius, blur);
        self.masks.push(m);
        self.masks.last().unwrap()
    }

    /// Draw the shadow cast by a rounded rect `caster` (local coords).
    /// `occluder` (local coords) marks an opaque area drawn on top later, whose
    /// interior may be skipped.
    pub fn draw(&mut self, c: &mut Canvas, caster: Rect, radius: i32, s: &Shadow, occluder: Option<Rect>) {
        if s.color.a() == 0 { return; }
        let shape = caster.offset(s.dx, s.dy).outset(s.spread);
        let radius = (radius + s.spread).max(0);
        let blur = s.blur.max(1);
        let m = self.mask(radius, blur);
        let pad = blur;
        let out = shape.outset(pad);
        if !out.intersects(&c.clip()) { return; }
        let (w, h) = (out.w, out.h);
        let cl = m.corner.min(w / 2);
        let cr = m.corner.min(w - cl);
        let ct = m.corner.min(h / 2);
        let cb = m.corner.min(h - ct);
        let mid = m.size / 2;
        let clip = c.clip();
        let y0 = out.y.max(clip.y);
        let y1 = out.bottom().min(clip.bottom());
        for y in y0..y1 {
            let ly = y - out.y;
            let sy = if ly < ct { ly } else if ly >= h - cb { m.size - (h - ly) } else { mid };
            let row = &m.data[(sy * m.size) as usize..((sy + 1) * m.size) as usize];
            // Left and right corner/edge slices.
            if cl > 0 { c.draw_mask(out.x, y, &row[..cl as usize], cl, 1, s.color); }
            if cr > 0 { c.draw_mask(out.right() - cr, y, &row[(m.size - cr) as usize..], cr, 1, s.color); }
            // Middle span: constant coverage.
            let span = Rect::new(out.x + cl, y, w - cl - cr, 1);
            if span.w > 0 {
                let v = row[mid as usize];
                if v == 0 { continue; }
                if let Some(o) = occluder {
                    if o.contains_rect(&span) { continue; }
                }
                c.fill_rect(span, s.color.fade(v));
            }
        }
        let _ = (m.radius, m.blur);
    }
}

fn build_mask(radius: i32, blur: i32) -> Mask {
    let pad = blur;
    let core = 2 * radius + 2 * blur + 2;
    let size = core + 2 * pad;
    let mut a = vec![0u8; (size * size) as usize];
    // Rasterise the rounded rect (pad, pad, core, core).
    let r = radius as f32;
    for y in 0..core {
        for x in 0..core {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let cx = if fx < r { r } else if fx > core as f32 - r { core as f32 - r } else { fx };
            let cy = if fy < r { r } else if fy > core as f32 - r { core as f32 - r } else { fy };
            let d = math::sqrt((fx - cx) * (fx - cx) + (fy - cy) * (fy - cy));
            let cov = if r > 0.0 { math::clamp01(r - d + 0.5) } else { 1.0 };
            a[((y + pad) * size + x + pad) as usize] = (cov * 255.0 + 0.5) as u8;
        }
    }
    // Three box passes, each of radius ~blur/3, horizontal then vertical.
    let br = (blur / 3).max(1);
    let mut tmp = vec![0u8; a.len()];
    for _ in 0..3 {
        box_pass(&a, &mut tmp, size, br, true);
        box_pass(&tmp, &mut a, size, br, false);
    }
    Mask { radius, blur, size, corner: pad + radius + blur, data: a }
}

fn box_pass(src: &[u8], dst: &mut [u8], size: i32, r: i32, horizontal: bool) {
    let n = size as usize;
    let win = (2 * r + 1) as u32;
    for line in 0..n {
        let at = |i: i32| -> u32 {
            if i < 0 || i >= size { return 0; }
            let i = i as usize;
            if horizontal { src[line * n + i] as u32 } else { src[i * n + line] as u32 }
        };
        let mut acc: u32 = 0;
        for i in -r..=r { acc += at(i); }
        for i in 0..size {
            let v = ((acc + win / 2) / win) as u8;
            let idx = if horizontal { line * n + i as usize } else { i as usize * n + line };
            dst[idx] = v;
            acc += at(i + r + 1);
            acc -= at(i - r);
        }
    }
}
