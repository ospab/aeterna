// SPDX-License-Identifier: AGPL-3.0-only
//! Canvas: 2D drawing on a [`PixelsMut`] with clipping and translation.
//!
//! Coordinates are integer pixels; a pixel (x, y) covers [x, x+1) x [y, y+1),
//! so 1-px hairlines drawn with [`Canvas::hline`]/[`Canvas::vline`]/
//! [`Canvas::stroke_rect`] are always crisp.  Curved shapes (rounded rects,
//! circles, lines) are anti-aliased with a one-sample signed-distance
//! coverage estimate, evaluated only on the edge pixels; interiors are filled
//! as plain spans.

use crate::blend;
use crate::color::Color;
use crate::geom::Rect;
use crate::math;
use crate::surface::{Pixels, PixelsMut};

/// Image sampling filter for scaled blits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    Nearest,
    Bilinear,
}

/// Saved clip/translation state (see [`Canvas::save`]).
#[derive(Clone, Copy, Debug)]
pub struct State {
    clip: Rect,
    ox: i32,
    oy: i32,
}

pub struct Canvas<'a> {
    px: PixelsMut<'a>,
    /// Clip in device coordinates (always inside the surface).
    clip: Rect,
    ox: i32,
    oy: i32,
}

impl<'a> Canvas<'a> {
    pub fn new(px: PixelsMut<'a>) -> Canvas<'a> {
        let clip = px.rect();
        Canvas { px, clip, ox: 0, oy: 0 }
    }

    pub fn width(&self) -> i32 { self.px.width }
    pub fn height(&self) -> i32 { self.px.height }

    // ── State ────────────────────────────────────────────────────────────

    pub fn save(&self) -> State { State { clip: self.clip, ox: self.ox, oy: self.oy } }
    pub fn restore(&mut self, s: State) { self.clip = s.clip; self.ox = s.ox; self.oy = s.oy; }

    /// Intersect the clip with `r` (local coordinates).
    pub fn clip_to(&mut self, r: Rect) {
        self.clip = self.clip.intersect(&r.offset(self.ox, self.oy));
    }

    /// Replace the clip (local coordinates), still bounded by the surface.
    pub fn set_clip(&mut self, r: Rect) {
        self.clip = self.px.rect().intersect(&r.offset(self.ox, self.oy));
    }

    /// Current clip in local coordinates.
    pub fn clip(&self) -> Rect { self.clip.offset(-self.ox, -self.oy) }

    pub fn translate(&mut self, dx: i32, dy: i32) { self.ox += dx; self.oy += dy; }

    #[inline]
    fn dev(&self, r: Rect) -> Rect { r.offset(self.ox, self.oy).intersect(&self.clip) }

    #[inline]
    fn row(&mut self, y: i32, x0: i32, x1: i32) -> &mut [u32] {
        let s = y as usize * self.px.stride;
        &mut self.px.data[s + x0 as usize..s + x1 as usize]
    }

    // ── Rectangles and hairlines ─────────────────────────────────────────

    /// Fill (or blend, if translucent) a rectangle.
    pub fn fill_rect(&mut self, r: Rect, color: Color) {
        let d = self.dev(r);
        if d.is_empty() || color.a() == 0 { return; }
        let p = color.premul();
        for y in d.y..d.bottom() {
            blend::fill_span(self.row(y, d.x, d.right()), p);
        }
    }

    /// Clear a rectangle to an exact premultiplied value (no blending).
    pub fn clear_rect(&mut self, r: Rect, premul: u32) {
        let d = self.dev(r);
        for y in d.y..d.bottom() {
            for p in self.row(y, d.x, d.right()) { *p = premul; }
        }
    }

    pub fn hline(&mut self, x0: i32, x1: i32, y: i32, color: Color) {
        self.fill_rect(Rect::new(x0, y, x1 - x0, 1), color);
    }

    pub fn vline(&mut self, x: i32, y0: i32, y1: i32, color: Color) {
        self.fill_rect(Rect::new(x, y0, 1, y1 - y0), color);
    }

    /// Crisp rectangle outline, `width` px inside `r`.
    pub fn stroke_rect(&mut self, r: Rect, width: i32, color: Color) {
        let w = width.max(1);
        self.fill_rect(Rect::new(r.x, r.y, r.w, w), color);
        self.fill_rect(Rect::new(r.x, r.bottom() - w, r.w, w), color);
        self.fill_rect(Rect::new(r.x, r.y + w, w, r.h - 2 * w), color);
        self.fill_rect(Rect::new(r.right() - w, r.y + w, w, r.h - 2 * w), color);
    }

    // ── Anti-aliased shapes ──────────────────────────────────────────────

    /// Blend one pixel (device coords, already clipped) with coverage 0..1.
    #[inline]
    fn plot_dev(&mut self, x: i32, y: i32, premul: u32, cov: f32) {
        if cov <= 0.0 { return; }
        let c = if cov >= 1.0 { 255 } else { (cov * 255.0 + 0.5) as u32 };
        let i = y as usize * self.px.stride + x as usize;
        self.px.data[i] = blend::over_cov(self.px.data[i], premul, c);
    }

    /// Filled rounded rectangle with radius `radius` (clamped to half the
    /// smaller side). Corners are anti-aliased; the rest is solid spans.
    pub fn fill_round_rect(&mut self, r: Rect, radius: i32, color: Color) {
        let rad = radius.min(r.w / 2).min(r.h / 2).max(0);
        if rad == 0 { return self.fill_rect(r, color); }
        // Middle band (full width), then top/bottom bands with inset spans.
        self.fill_rect(Rect::new(r.x, r.y + rad, r.w, r.h - 2 * rad), color);
        self.fill_rect(Rect::new(r.x + rad, r.y, r.w - 2 * rad, rad), color);
        self.fill_rect(Rect::new(r.x + rad, r.bottom() - rad, r.w - 2 * rad, rad), color);
        self.round_corners(r, rad as f32, None, color);
    }

    /// Rounded-rectangle outline of `width` px drawn inside `r`.
    pub fn stroke_round_rect(&mut self, r: Rect, radius: i32, width: i32, color: Color) {
        let rad = radius.min(r.w / 2).min(r.h / 2).max(0);
        let w = width.max(1);
        if rad == 0 { return self.stroke_rect(r, w, color); }
        // Straight edges between the corners.
        self.fill_rect(Rect::new(r.x + rad, r.y, r.w - 2 * rad, w), color);
        self.fill_rect(Rect::new(r.x + rad, r.bottom() - w, r.w - 2 * rad, w), color);
        self.fill_rect(Rect::new(r.x, r.y + rad, w, r.h - 2 * rad), color);
        self.fill_rect(Rect::new(r.right() - w, r.y + rad, w, r.h - 2 * rad), color);
        self.round_corners(r, rad as f32, Some(w as f32), color);
    }

    /// Draw the four `rad`×`rad` corner squares of `r`: filled when `ring` is
    /// None, otherwise a ring of that width.
    fn round_corners(&mut self, r: Rect, rad: f32, ring: Option<f32>, color: Color) {
        let p = color.premul();
        let n = rad as i32;
        let corners = [
            (r.x, r.y, r.x as f32 + rad, r.y as f32 + rad),
            (r.right() - n, r.y, r.right() as f32 - rad, r.y as f32 + rad),
            (r.x, r.bottom() - n, r.x as f32 + rad, r.bottom() as f32 - rad),
            (r.right() - n, r.bottom() - n, r.right() as f32 - rad, r.bottom() as f32 - rad),
        ];
        for &(sx, sy, cx, cy) in corners.iter() {
            let sq = self.dev(Rect::new(sx, sy, n, n));
            if sq.is_empty() { continue; }
            let (cx, cy) = (cx + self.ox as f32, cy + self.oy as f32);
            for y in sq.y..sq.bottom() {
                let dy = y as f32 + 0.5 - cy;
                for x in sq.x..sq.right() {
                    let dx = x as f32 + 0.5 - cx;
                    let d = math::sqrt(dx * dx + dy * dy);
                    let outer = math::clamp01(rad - d + 0.5);
                    let cov = match ring {
                        None => outer,
                        Some(w) => outer - math::clamp01(rad - w - d + 0.5),
                    };
                    self.plot_dev(x, y, p, cov);
                }
            }
        }
    }

    /// Filled anti-aliased circle (centre and radius in pixels, may be fractional).
    pub fn fill_circle(&mut self, cx: f32, cy: f32, radius: f32, color: Color) {
        self.circle_impl(cx, cy, radius, None, color);
    }

    /// Anti-aliased circle outline of the given width (inside the radius).
    pub fn stroke_circle(&mut self, cx: f32, cy: f32, radius: f32, width: f32, color: Color) {
        self.circle_impl(cx, cy, radius, Some(width), color);
    }

    fn circle_impl(&mut self, cx: f32, cy: f32, rad: f32, ring: Option<f32>, color: Color) {
        let bx = math::floor(cx - rad - 1.0) as i32;
        let by = math::floor(cy - rad - 1.0) as i32;
        let n = (2.0 * rad + 3.0) as i32;
        let d = self.dev(Rect::new(bx, by, n, n));
        if d.is_empty() { return; }
        let p = color.premul();
        let (cx, cy) = (cx + self.ox as f32, cy + self.oy as f32);
        let inner_solid = ring.map_or(rad - 1.0, |_| -1.0);
        for y in d.y..d.bottom() {
            let dy = y as f32 + 0.5 - cy;
            for x in d.x..d.right() {
                let dx = x as f32 + 0.5 - cx;
                let dist2 = dx * dx + dy * dy;
                if inner_solid > 0.0 && dist2 < inner_solid * inner_solid {
                    let i = y as usize * self.px.stride + x as usize;
                    self.px.data[i] = blend::over(self.px.data[i], p);
                    continue;
                }
                let dist = math::sqrt(dist2);
                let outer = math::clamp01(rad - dist + 0.5);
                let cov = match ring {
                    None => outer,
                    Some(w) => outer - math::clamp01(rad - w - dist + 0.5),
                };
                self.plot_dev(x, y, p, cov);
            }
        }
    }

    /// Anti-aliased line segment with round caps.
    pub fn line(&mut self, x0: f32, y0: f32, x1: f32, y1: f32, width: f32, color: Color) {
        let hw = width * 0.5;
        let bx0 = math::floor(x0.min(x1) - hw - 1.0) as i32;
        let by0 = math::floor(y0.min(y1) - hw - 1.0) as i32;
        let bx1 = (x0.max(x1) + hw + 2.0) as i32;
        let by1 = (y0.max(y1) + hw + 2.0) as i32;
        let d = self.dev(Rect::from_ltrb(bx0, by0, bx1, by1));
        if d.is_empty() { return; }
        let p = color.premul();
        let (ox, oy) = (self.ox as f32, self.oy as f32);
        let (ax, ay, bx, by) = (x0 + ox, y0 + oy, x1 + ox, y1 + oy);
        let (vx, vy) = (bx - ax, by - ay);
        let len2 = (vx * vx + vy * vy).max(1e-6);
        for y in d.y..d.bottom() {
            let py = y as f32 + 0.5;
            for x in d.x..d.right() {
                let px = x as f32 + 0.5;
                let t = math::clamp01(((px - ax) * vx + (py - ay) * vy) / len2);
                let (qx, qy) = (ax + vx * t - px, ay + vy * t - py);
                let dist = math::sqrt(qx * qx + qy * qy);
                self.plot_dev(x, y, p, math::clamp01(hw - dist + 0.5));
            }
        }
    }

    /// Polyline helper (e.g. check marks, chevrons).
    pub fn polyline(&mut self, pts: &[(f32, f32)], width: f32, color: Color) {
        for w in pts.windows(2) {
            self.line(w[0].0, w[0].1, w[1].0, w[1].1, width, color);
        }
    }

    // ── Masks and images ─────────────────────────────────────────────────

    /// Paint `color` through an 8-bit coverage mask placed at (x, y).
    pub fn draw_mask(&mut self, x: i32, y: i32, mask: &[u8], mw: i32, mh: i32, color: Color) {
        let d = self.dev(Rect::new(x, y, mw, mh));
        if d.is_empty() { return; }
        let p = color.premul();
        let (mx0, my0) = (d.x - (x + self.ox), d.y - (y + self.oy));
        for row in 0..d.h {
            let m0 = ((my0 + row) * mw + mx0) as usize;
            let mrow = &mask[m0..m0 + d.w as usize];
            let dst = self.row(d.y + row, d.x, d.right());
            blend::mask_row(dst, mrow, p);
        }
    }

    /// Composite a premultiplied image (or a sub-rectangle of it) at (x, y).
    pub fn blit(&mut self, src: &Pixels, src_rect: Rect, x: i32, y: i32) {
        self.blit_impl(src, src_rect, x, y, 255, false);
    }

    /// Copy pixels without blending (the source is treated as opaque).
    pub fn blit_opaque(&mut self, src: &Pixels, src_rect: Rect, x: i32, y: i32) {
        self.blit_impl(src, src_rect, x, y, 255, true);
    }

    /// Composite with a global opacity (0..=255).
    pub fn blit_alpha(&mut self, src: &Pixels, src_rect: Rect, x: i32, y: i32, alpha: u8) {
        self.blit_impl(src, src_rect, x, y, alpha as u32, false);
    }

    fn blit_impl(&mut self, src: &Pixels, src_rect: Rect, x: i32, y: i32, alpha: u32, copy: bool) {
        let sr = src_rect.intersect(&src.rect());
        let target = Rect::new(x + (sr.x - src_rect.x), y + (sr.y - src_rect.y), sr.w, sr.h);
        let d = self.dev(target);
        if d.is_empty() || alpha == 0 { return; }
        let sx = sr.x + (d.x - (target.x + self.ox));
        let sy = sr.y + (d.y - (target.y + self.oy));
        for row in 0..d.h {
            let s0 = (sy + row) as usize * src.stride + sx as usize;
            let srow = &src.data[s0..s0 + d.w as usize];
            let dst = self.row(d.y + row, d.x, d.right());
            if copy {
                dst.copy_from_slice(srow);
            } else {
                blend::blend_row_alpha(dst, srow, alpha);
            }
        }
    }

    /// Scale `src_rect` of `src` into `dst` (local coords).
    pub fn blit_scaled(&mut self, src: &Pixels, src_rect: Rect, dst: Rect, filter: Filter) {
        let sr = src_rect.intersect(&src.rect());
        if sr.is_empty() || dst.is_empty() { return; }
        let d = self.dev(dst);
        if d.is_empty() { return; }
        // 16.16 fixed-point source step per destination pixel.
        let step_x = ((sr.w as i64) << 16) / dst.w as i64;
        let step_y = ((sr.h as i64) << 16) / dst.h as i64;
        let (dx0, dy0) = (dst.x + self.ox, dst.y + self.oy);
        let max_x = (sr.right() - 1) as i64;
        let max_y = (sr.bottom() - 1) as i64;
        for y in d.y..d.bottom() {
            let s = y as usize * self.px.stride;
            match filter {
                Filter::Nearest => {
                    let fy = ((y - dy0) as i64 * step_y + step_y / 2) >> 16;
                    let srow = (sr.y as i64 + fy).min(max_y) as usize * src.stride;
                    for x in d.x..d.right() {
                        let fx = ((x - dx0) as i64 * step_x + step_x / 2) >> 16;
                        let sp = src.data[srow + (sr.x as i64 + fx).min(max_x) as usize];
                        let i = s + x as usize;
                        self.px.data[i] = blend::over(self.px.data[i], sp);
                    }
                }
                Filter::Bilinear => {
                    // Sample at pixel centres: src = (dst + 0.5) * step - 0.5.
                    let fy = (y - dy0) as i64 * step_y + step_y / 2 - 32768;
                    let fy = fy.max(0);
                    let y0 = (sr.y as i64 + (fy >> 16)).min(max_y);
                    let y1 = (y0 + 1).min(max_y);
                    let wy = ((fy >> 8) & 0xFF) as u32;
                    for x in d.x..d.right() {
                        let fx = ((x - dx0) as i64 * step_x + step_x / 2 - 32768).max(0);
                        let x0 = (sr.x as i64 + (fx >> 16)).min(max_x);
                        let x1 = (x0 + 1).min(max_x);
                        let wx = ((fx >> 8) & 0xFF) as u32;
                        let r0 = y0 as usize * src.stride;
                        let r1 = y1 as usize * src.stride;
                        let top = lerp_px(src.data[r0 + x0 as usize], src.data[r0 + x1 as usize], wx);
                        let bot = lerp_px(src.data[r1 + x0 as usize], src.data[r1 + x1 as usize], wx);
                        let sp = lerp_px(top, bot, wy);
                        let i = s + x as usize;
                        self.px.data[i] = blend::over(self.px.data[i], sp);
                    }
                }
            }
        }
    }
}

/// Per-channel interpolation a + (b - a) * t / 256 on premultiplied pixels.
#[inline(always)]
fn lerp_px(a: u32, b: u32, t: u32) -> u32 {
    if t == 0 { return a; }
    let it = 256 - t;
    let rb = ((a & 0x00FF_00FF) * it + (b & 0x00FF_00FF) * t) >> 8;
    let ag = ((a >> 8) & 0x00FF_00FF) * it + ((b >> 8) & 0x00FF_00FF) * t;
    (rb & 0x00FF_00FF) | (ag & 0xFF00_FF00)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::Surface;

    #[test]
    fn hairline_is_crisp() {
        let mut s = Surface::new(10, 10);
        {
            let mut c = Canvas::new(s.view_mut());
            c.hline(1, 9, 4, Color::WHITE);
        }
        for x in 0..10 {
            let v = s.pixel(x, 4);
            assert_eq!(v, if (1..9).contains(&x) { 0xFFFF_FFFF } else { 0 });
            assert_eq!(s.pixel(x, 3), 0);
            assert_eq!(s.pixel(x, 5), 0);
        }
    }

    #[test]
    fn round_rect_symmetric_and_clipped() {
        let mut s = Surface::new(40, 30);
        {
            let mut c = Canvas::new(s.view_mut());
            c.set_clip(Rect::new(0, 0, 20, 30));
            c.fill_round_rect(Rect::new(4, 4, 32, 22), 8, Color::WHITE);
        }
        assert_eq!(s.pixel(4, 4) >> 24, 0); // outside the corner arc
        assert_eq!(s.pixel(12, 4) >> 24, 255);
        assert_eq!(s.pixel(25, 10), 0); // clipped away
    }
}
