// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Software 3D: z-buffered triangle rasterizer with flat and Gouraud shading, near-plane
//! clipping, additive sprites and beams, and a cheap bloom pass.
use crate::gfx::*;
use crate::math::*;
use alloc::vec;
use alloc::vec::Vec;

pub const NEAR: f32 = 6.0;
/// Cool fill light from the side facing away from the star (planet shine).
const FILL: [f32; 3] = [0.10, 0.13, 0.20];

pub struct Camera {
    pub pos: V3,
    pub o: Orient,
    /// Focal length in scene pixels.
    pub focal: f32,
}

pub struct Scene {
    pub w: usize,
    pub h: usize,
    pub col: Vec<u32>,
    /// 1/z of the nearest opaque surface; 0 = nothing (sky).
    pub iz: Vec<f32>,
    small: Vec<[i32; 3]>,
    small2: Vec<[i32; 3]>,
}

#[derive(Clone, Copy)]
pub struct Light {
    /// Unit vector towards the light.
    pub dir: V3,
    pub col: [f32; 3],
    pub amb: [f32; 3],
}

impl Scene {
    pub fn new(w: usize, h: usize) -> Scene {
        let mut s = Scene { w: 0, h: 0, col: Vec::new(), iz: Vec::new(), small: Vec::new(), small2: Vec::new() };
        s.resize(w, h);
        s
    }
    pub fn resize(&mut self, w: usize, h: usize) {
        self.w = w;
        self.h = h;
        self.col = vec![0; w * h];
        self.iz = vec![0.0; w * h];
        let (sw, sh) = (w / 4 + 2, h / 4 + 2);
        self.small = vec![[0; 3]; sw * sh];
        self.small2 = vec![[0; 3]; sw * sh];
    }
    pub fn clear_depth(&mut self) {
        for z in self.iz.iter_mut() {
            *z = 0.0;
        }
    }
    #[inline]
    pub fn project(&self, cam: &Camera, p: V3) -> V3 {
        // returns camera-space coordinates
        cam.o.to_local(p - cam.pos)
    }
    #[inline]
    pub fn to_screen(&self, c: V3, focal: f32) -> (f32, f32) {
        let k = focal / c.z;
        (self.w as f32 * 0.5 + c.x * k, self.h as f32 * 0.5 - c.y * k)
    }

    /// Additive soft sprite of world radius `rad`, depth-tested at its centre against opaque geometry.
    pub fn glow(&mut self, cam: &Camera, p: V3, rad: f32, color: u32, intensity: f32, min_px: f32) {
        let c = cam.o.to_local(p - cam.pos);
        if c.z < NEAR {
            return;
        }
        let (sx, sy) = self.to_screen(c, cam.focal);
        let mut r = rad * cam.focal / c.z;
        if r < min_px {
            r = min_px;
        }
        if r < 0.5 || r > 4000.0 {
            return;
        }
        let iz = 1.0 / c.z;
        let (x0, x1) = (floor(sx - r).max(0.0) as i32, (sx + r + 1.0).min(self.w as f32) as i32);
        let (y0, y1) = (floor(sy - r).max(0.0) as i32, (sy + r + 1.0).min(self.h as f32) as i32);
        let inv = 1.0 / (r * r);
        for y in y0..y1 {
            let dy = y as f32 + 0.5 - sy;
            let row = y as usize * self.w;
            for x in x0..x1 {
                let dx = x as f32 + 0.5 - sx;
                let d2 = (dx * dx + dy * dy) * inv;
                if d2 >= 1.0 {
                    continue;
                }
                let i = row + x as usize;
                if self.iz[i] > iz {
                    continue;
                }
                let f = (1.0 - d2) * (1.0 - d2);
                let k = (f * intensity * 255.0) as u32;
                self.col[i] = add_px(self.col[i], color, k);
            }
        }
    }

    /// Additive glowing beam between two world points, with a bright core.
    pub fn beam(&mut self, cam: &Camera, a: V3, b: V3, color: u32, width_px: f32, intensity: f32) {
        let mut ca = cam.o.to_local(a - cam.pos);
        let mut cb = cam.o.to_local(b - cam.pos);
        if ca.z < NEAR && cb.z < NEAR {
            return;
        }
        if ca.z < NEAR {
            let t = (NEAR - ca.z) / (cb.z - ca.z);
            ca = ca.lerp(cb, t);
        } else if cb.z < NEAR {
            let t = (NEAR - cb.z) / (ca.z - cb.z);
            cb = cb.lerp(ca, t);
        }
        let (x0, y0) = self.to_screen(ca, cam.focal);
        let (x1, y1) = self.to_screen(cb, cam.focal);
        if !(x0.is_finite() && x1.is_finite() && y0.is_finite() && y1.is_finite()) {
            return;
        }
        let pad = width_px * 2.0 + 2.0;
        let (bx0, bx1) = (floor(min(x0, x1) - pad).max(0.0) as i32, (max(x0, x1) + pad).min(self.w as f32) as i32);
        let (by0, by1) = (floor(min(y0, y1) - pad).max(0.0) as i32, (max(y0, y1) + pad).min(self.h as f32) as i32);
        let (dx, dy) = (x1 - x0, y1 - y0);
        let l2 = dx * dx + dy * dy;
        let core = scale_col(0xFFFFFF, 1.0);
        for y in by0..by1 {
            for x in bx0..bx1 {
                let (px, py) = (x as f32 + 0.5 - x0, y as f32 + 0.5 - y0);
                let t = if l2 < 1e-6 { 0.0 } else { clamp((px * dx + py * dy) / l2, 0.0, 1.0) };
                let (qx, qy) = (px - dx * t, py - dy * t);
                let d = sqrt(qx * qx + qy * qy) / width_px;
                if d < 2.0 {
                    let halo = exp_neg(d * d * 1.2) * intensity;
                    let i = y as usize * self.w + x as usize;
                    self.col[i] = add_px(self.col[i], color, (halo * 255.0) as u32);
                    if d < 0.6 {
                        self.col[i] = add_px(self.col[i], core, (intensity * (1.0 - d / 0.6) * 255.0) as u32);
                    }
                }
            }
        }
    }

    /// Single bright point with a tiny halo (stars, distant ships).
    pub fn point(&mut self, cam: &Camera, p: V3, color: u32, k: u32) {
        let c = cam.o.to_local(p - cam.pos);
        if c.z < NEAR {
            return;
        }
        let (sx, sy) = self.to_screen(c, cam.focal);
        let (x, y) = (sx as i32, sy as i32);
        if x < 0 || y < 0 || x >= self.w as i32 || y >= self.h as i32 {
            return;
        }
        let i = y as usize * self.w + x as usize;
        if self.iz[i] > 1.0 / c.z {
            return;
        }
        self.col[i] = add_px(self.col[i], color, k);
    }

    /// Bright-pass bloom: blur the bright parts at quarter resolution and add them back.
    pub fn bloom(&mut self, threshold: i32, gain: i32) {
        let (sw, sh) = (self.w / 4 + 1, self.h / 4 + 1);
        if sw * sh > self.small.len() {
            return;
        }
        for v in self.small.iter_mut() {
            *v = [0; 3];
        }
        for y in 0..self.h {
            let sy = y / 4;
            let row = y * self.w;
            for x in 0..self.w {
                let c = self.col[row + x];
                if c & 0x808080 == 0 && threshold >= 128 {
                    continue;
                }
                let (r, g, b) = chan(c);
                let (r, g, b) = (r as i32 - threshold, g as i32 - threshold, b as i32 - threshold);
                if r > 0 || g > 0 || b > 0 {
                    let s = &mut self.small[sy * sw + x / 4];
                    s[0] += r.max(0);
                    s[1] += g.max(0);
                    s[2] += b.max(0);
                }
            }
        }
        // 16 pixels were summed per cell; blur horizontally then vertically (radius 3).
        for y in 0..sh {
            for x in 0..sw {
                let mut acc = [0i32; 3];
                for k in -3i32..=3 {
                    let xx = (x as i32 + k).clamp(0, sw as i32 - 1) as usize;
                    let w = 4 - k.abs();
                    let s = self.small[y * sw + xx];
                    acc[0] += s[0] * w;
                    acc[1] += s[1] * w;
                    acc[2] += s[2] * w;
                }
                self.small2[y * sw + x] = acc;
            }
        }
        for y in 0..sh {
            for x in 0..sw {
                let mut acc = [0i32; 3];
                for k in -3i32..=3 {
                    let yy = (y as i32 + k).clamp(0, sh as i32 - 1) as usize;
                    let w = 4 - k.abs();
                    let s = self.small2[yy * sw + x];
                    acc[0] += s[0] * w;
                    acc[1] += s[1] * w;
                    acc[2] += s[2] * w;
                }
                self.small[y * sw + x] = acc;
            }
        }
        // average = cell sum / 16 pixels / 256 (blur weights); gain is in 1/256 units. The blurred
        // buffer is smooth, so each 4x4 block gets one constant value, added with saturation.
        for sy in 0..sh {
            for sx in 0..sw {
                let s = self.small[sy * sw + sx];
                let add = [(s[0] * gain) >> 20, (s[1] * gain) >> 20, (s[2] * gain) >> 20];
                if add[0] <= 0 && add[1] <= 0 && add[2] <= 0 {
                    continue;
                }
                let (ar, ag, ab) = (add[0].clamp(0, 255) as u32, add[1].clamp(0, 255) as u32, add[2].clamp(0, 255) as u32);
                for dy in 0..4 {
                    let y = sy * 4 + dy;
                    if y >= self.h {
                        break;
                    }
                    let x0 = sx * 4;
                    let x1 = (x0 + 4).min(self.w);
                    for px in &mut self.col[y * self.w + x0..y * self.w + x1] {
                        let v = *px;
                        let r = ((v >> 16) & 255) + ar;
                        let g = ((v >> 8) & 255) + ag;
                        let b = (v & 255) + ab;
                        *px = (r.min(255) << 16) | (g.min(255) << 8) | b.min(255);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------- meshes

#[derive(Clone)]
pub struct Tri {
    pub a: u16,
    pub b: u16,
    pub c: u16,
    pub col: u32,
    /// 0..1 self-illumination (engine glow, lamps).
    pub glow: f32,
    pub n: V3,
    pub vn: [V3; 3],
}

#[derive(Clone)]
pub struct Mesh {
    pub v: Vec<V3>,
    pub t: Vec<Tri>,
    pub radius: f32,
    /// Engine exhaust points (model space) and size.
    pub engines: Vec<(V3, f32)>,
}

pub struct MeshBuilder {
    pub v: Vec<V3>,
    pub t: Vec<Tri>,
    pub engines: Vec<(V3, f32)>,
}

impl MeshBuilder {
    pub fn new() -> MeshBuilder {
        MeshBuilder { v: Vec::new(), t: Vec::new(), engines: Vec::new() }
    }
    /// Add a convex part; triangle windings are fixed so normals point away from the centroid.
    pub fn part(&mut self, verts: &[V3], faces: &[[u8; 3]], col: u32, glow: f32) {
        let base = self.v.len() as u16;
        let mut cen = V3::ZERO;
        for p in verts {
            cen += *p;
        }
        cen = cen * (1.0 / verts.len() as f32);
        for p in verts {
            self.v.push(*p);
        }
        for f in faces {
            let (mut a, mut b, mut c) = (f[0] as usize, f[1] as usize, f[2] as usize);
            let n = (verts[b] - verts[a]).cross(verts[c] - verts[a]);
            let fc = (verts[a] + verts[b] + verts[c]) * (1.0 / 3.0);
            let mut n = n.norm();
            if n.dot(fc - cen) < 0.0 {
                core::mem::swap(&mut b, &mut c);
                n = -n;
            }
            let _ = &mut a;
            self.t.push(Tri { a: base + a as u16, b: base + b as u16, c: base + c as u16, col, glow, n, vn: [n, n, n] });
        }
    }
    /// Convex box part from min/max corner.
    pub fn cuboid(&mut self, lo: V3, hi: V3, col: u32, glow: f32) {
        self.prism8(
            [
                v3(lo.x, lo.y, lo.z),
                v3(hi.x, lo.y, lo.z),
                v3(hi.x, hi.y, lo.z),
                v3(lo.x, hi.y, lo.z),
                v3(lo.x, lo.y, hi.z),
                v3(hi.x, lo.y, hi.z),
                v3(hi.x, hi.y, hi.z),
                v3(lo.x, hi.y, hi.z),
            ],
            col,
            glow,
        );
    }
    /// Hexahedron from 8 corners (4 back then 4 front, same order).
    pub fn prism8(&mut self, p: [V3; 8], col: u32, glow: f32) {
        let f: [[u8; 3]; 12] = [
            [0, 1, 2],
            [0, 2, 3],
            [4, 6, 5],
            [4, 7, 6],
            [0, 4, 5],
            [0, 5, 1],
            [3, 2, 6],
            [3, 6, 7],
            [0, 3, 7],
            [0, 7, 4],
            [1, 5, 6],
            [1, 6, 2],
        ];
        self.part(&p, &f, col, glow);
    }
    /// Make corner normals smooth (averaged over triangles sharing a position) for all triangles.
    pub fn smooth(&mut self) {
        let n = self.v.len();
        let mut acc = vec![V3::ZERO; n];
        for t in &self.t {
            for &i in &[t.a, t.b, t.c] {
                acc[i as usize] += t.n;
            }
        }
        // weld by position
        let mut wel = acc.clone();
        for i in 0..n {
            for j in 0..n {
                if (self.v[i] - self.v[j]).len2() < 1e-4 && i != j {
                    wel[i] += acc[j];
                }
            }
        }
        for t in self.t.iter_mut() {
            t.vn = [wel[t.a as usize].norm(), wel[t.b as usize].norm(), wel[t.c as usize].norm()];
        }
    }
    pub fn finish(self) -> Mesh {
        let mut r = 1.0f32;
        for p in &self.v {
            r = max(r, p.len());
        }
        Mesh { v: self.v, t: self.t, radius: r, engines: self.engines }
    }
}

#[derive(Clone, Copy)]
struct CV {
    p: V3,
    c: [f32; 3],
}

/// Draw a mesh instance. `flash` (0..1) adds a white-blue shield flash.
pub fn draw_mesh(sc: &mut Scene, cam: &Camera, m: &Mesh, pos: V3, o: &Orient, scale: f32, light: &Light, flash: f32, tmp: &mut Vec<V3>) {
    let rel = pos - cam.pos;
    let cz = cam.o.to_local(rel);
    let rad = m.radius * scale;
    if cz.z + rad < NEAR {
        return;
    }
    let half_w = sc.w as f32 * 0.5 / cam.focal;
    let half_h = sc.h as f32 * 0.5 / cam.focal;
    // reject if entirely outside the view (conservative)
    if cz.z > 0.0 {
        if abs(cz.x) - rad > cz.z * half_w || abs(cz.y) - rad > cz.z * half_h {
            return;
        }
    }
    // tiny: draw a point
    if cz.z > 0.0 && rad * cam.focal / cz.z < 1.2 {
        let (sx, sy) = sc.to_screen(cz, cam.focal);
        let (x, y) = (sx as i32, sy as i32);
        if x >= 0 && y >= 0 && x < sc.w as i32 && y < sc.h as i32 {
            let i = y as usize * sc.w + x as usize;
            let iz = 1.0 / cz.z;
            if iz > sc.iz[i] {
                sc.iz[i] = iz;
                sc.col[i] = m.t[0].col;
            }
        }
        return;
    }
    tmp.clear();
    for p in &m.v {
        let w = o.to_world(*p * scale);
        tmp.push(cam.o.to_local(rel + w));
    }
    let eye_local = o.to_local(cam.pos - pos); // camera in model space (unscaled units)
    let fl = flash;
    for t in &m.t {
        // back-face culling in model space
        let a = m.v[t.a as usize];
        if t.n.dot(eye_local * (1.0 / scale) - a) <= 0.0 {
            continue;
        }
        let base = {
            let (r, g, b) = chan(t.col);
            [r as f32, g as f32, b as f32]
        };
        let mut cv = [CV { p: V3::ZERO, c: [0.0; 3] }; 3];
        let idx = [t.a, t.b, t.c];
        for k in 0..3 {
            let nw = o.to_world(t.vn[k]);
            let nd = nw.dot(light.dir);
            let d = max(0.0, nd);
            let back = max(0.0, -nd);
            let mut c = [0.0; 3];
            for ch in 0..3 {
                let lit = light.amb[ch] + light.col[ch] * d + back * FILL[ch];
                c[ch] = base[ch] * (lit + t.glow) + fl * 150.0;
            }
            cv[k] = CV { p: tmp[idx[k] as usize], c };
        }
        draw_tri(sc, cam.focal, &cv);
    }
}

fn lerp_cv(a: CV, b: CV, t: f32) -> CV {
    CV { p: a.p.lerp(b.p, t), c: [lerp(a.c[0], b.c[0], t), lerp(a.c[1], b.c[1], t), lerp(a.c[2], b.c[2], t)] }
}

fn draw_tri(sc: &mut Scene, focal: f32, v: &[CV; 3]) {
    // near clip
    let mut poly = [v[0]; 4];
    let mut n = 0;
    for i in 0..3 {
        let a = v[i];
        let b = v[(i + 1) % 3];
        let ain = a.p.z >= NEAR;
        let bin = b.p.z >= NEAR;
        if ain {
            poly[n] = a;
            n += 1;
        }
        if ain != bin {
            let t = (NEAR - a.p.z) / (b.p.z - a.p.z);
            let mut q = lerp_cv(a, b, t);
            q.p.z = NEAR;
            poly[n] = q;
            n += 1;
        }
    }
    if n < 3 {
        return;
    }
    raster_tri(sc, focal, &poly[0], &poly[1], &poly[2]);
    if n == 4 {
        raster_tri(sc, focal, &poly[0], &poly[2], &poly[3]);
    }
}

fn raster_tri(sc: &mut Scene, focal: f32, a: &CV, b: &CV, c: &CV) {
    let (hw, hh) = (sc.w as f32 * 0.5, sc.h as f32 * 0.5);
    let pr = |q: &CV| -> (f32, f32, f32) {
        let k = focal / q.p.z;
        (hw + q.p.x * k, hh - q.p.y * k, 1.0 / q.p.z)
    };
    let (mut p0, mut p1, mut p2) = (pr(a), pr(b), pr(c));
    let (mut c0, mut c1, mut c2) = (a.c, b.c, c.c);
    // sort by y
    if p0.1 > p1.1 {
        core::mem::swap(&mut p0, &mut p1);
        core::mem::swap(&mut c0, &mut c1);
    }
    if p1.1 > p2.1 {
        core::mem::swap(&mut p1, &mut p2);
        core::mem::swap(&mut c1, &mut c2);
    }
    if p0.1 > p1.1 {
        core::mem::swap(&mut p0, &mut p1);
        core::mem::swap(&mut c0, &mut c1);
    }
    if !(p0.0.is_finite() && p1.0.is_finite() && p2.0.is_finite() && p0.1.is_finite() && p2.1.is_finite()) {
        return;
    }
    let big = 1.0e5;
    if abs(p0.0) > big || abs(p1.0) > big || abs(p2.0) > big || abs(p0.1) > big || abs(p2.1) > big {
        return;
    }
    let det = (p1.0 - p0.0) * (p2.1 - p0.1) - (p2.0 - p0.0) * (p1.1 - p0.1);
    if abs(det) < 1e-4 {
        return;
    }
    let idet = 1.0 / det;
    let grad = |a0: f32, a1: f32, a2: f32| -> (f32, f32) {
        let dx = ((a1 - a0) * (p2.1 - p0.1) - (a2 - a0) * (p1.1 - p0.1)) * idet;
        let dy = ((a2 - a0) * (p1.0 - p0.0) - (a1 - a0) * (p2.0 - p0.0)) * idet;
        (dx, dy)
    };
    let (zx, zy) = grad(p0.2, p1.2, p2.2);
    let (rx, ry) = grad(c0[0], c1[0], c2[0]);
    let (gx, gy) = grad(c0[1], c1[1], c2[1]);
    let (bx, by) = grad(c0[2], c1[2], c2[2]);
    let y_start = ceil_i(p0.1 - 0.5).max(0);
    let y_end = ceil_i(p2.1 - 0.5).min(sc.h as i32);
    let w = sc.w as i32;
    let long_dx = if p2.1 - p0.1 > 1e-6 { (p2.0 - p0.0) / (p2.1 - p0.1) } else { 0.0 };
    let top_dx = if p1.1 - p0.1 > 1e-6 { (p1.0 - p0.0) / (p1.1 - p0.1) } else { 0.0 };
    let bot_dx = if p2.1 - p1.1 > 1e-6 { (p2.0 - p1.0) / (p2.1 - p1.1) } else { 0.0 };
    for y in y_start..y_end {
        let yc = y as f32 + 0.5;
        let xl_long = p0.0 + (yc - p0.1) * long_dx;
        let xs = if yc < p1.1 { p0.0 + (yc - p0.1) * top_dx } else { p1.0 + (yc - p1.1) * bot_dx };
        let (xa, xb) = if xl_long < xs { (xl_long, xs) } else { (xs, xl_long) };
        let x0 = ceil_i(xa - 0.5).max(0);
        let x1 = ceil_i(xb - 0.5).min(w);
        if x1 <= x0 {
            continue;
        }
        let dx0 = x0 as f32 + 0.5 - p0.0;
        let dy0 = yc - p0.1;
        let mut z = p0.2 + zx * dx0 + zy * dy0;
        let mut r = c0[0] + rx * dx0 + ry * dy0;
        let mut g = c0[1] + gx * dx0 + gy * dy0;
        let mut bl = c0[2] + bx * dx0 + by * dy0;
        let row = y as usize * sc.w;
        for x in x0..x1 {
            let i = row + x as usize;
            if z > sc.iz[i] {
                sc.iz[i] = z;
                let ri = if r < 0.0 { 0 } else if r > 255.0 { 255 } else { r as u32 };
                let gi = if g < 0.0 { 0 } else if g > 255.0 { 255 } else { g as u32 };
                let bi = if bl < 0.0 { 0 } else if bl > 255.0 { 255 } else { bl as u32 };
                sc.col[i] = (ri << 16) | (gi << 8) | bi;
            }
            z += zx;
            r += rx;
            g += gx;
            bl += bx;
        }
    }
}

#[inline]
fn ceil_i(x: f32) -> i32 {
    let i = x as i32;
    if (i as f32) < x {
        i + 1
    } else {
        i
    }
}

impl Scene {
    /// Plain additive line in screen space (retro mode, tunnel streaks).
    pub fn line_px(&mut self, x0: f32, y0: f32, x1: f32, y1: f32, color: u32, k: u32) {
        if !(x0.is_finite() && y0.is_finite() && x1.is_finite() && y1.is_finite()) {
            return;
        }
        let (dx, dy) = (x1 - x0, y1 - y0);
        let n = (max(abs(dx), abs(dy)) as i32).min(4000);
        if n == 0 {
            return;
        }
        let (sx, sy) = (dx / n as f32, dy / n as f32);
        let (mut x, mut y) = (x0, y0);
        for _ in 0..=n {
            let (xi, yi) = (x as i32, y as i32);
            if xi >= 0 && yi >= 0 && xi < self.w as i32 && yi < self.h as i32 {
                let i = yi as usize * self.w + xi as usize;
                self.col[i] = add_px(self.col[i], color, k);
            }
            x += sx;
            y += sy;
        }
    }
}

/// Retro mode: wireframe of the front-facing triangles.
pub fn draw_mesh_wire(sc: &mut Scene, cam: &Camera, m: &Mesh, pos: V3, o: &Orient, scale: f32, color: u32, tmp: &mut Vec<V3>) {
    let rel = pos - cam.pos;
    tmp.clear();
    for p in &m.v {
        tmp.push(cam.o.to_local(rel + o.to_world(*p * scale)));
    }
    let eye = o.to_local(cam.pos - pos);
    for t in &m.t {
        if t.n.dot(eye * (1.0 / scale) - m.v[t.a as usize]) <= 0.0 {
            continue;
        }
        let idx = [t.a as usize, t.b as usize, t.c as usize];
        for k in 0..3 {
            let (mut a, mut b) = (tmp[idx[k]], tmp[idx[(k + 1) % 3]]);
            if a.z < NEAR && b.z < NEAR {
                continue;
            }
            if a.z < NEAR {
                a = a.lerp(b, (NEAR - a.z) / (b.z - a.z));
            } else if b.z < NEAR {
                b = b.lerp(a, (NEAR - b.z) / (a.z - b.z));
            }
            let (x0, y0) = sc.to_screen(a, cam.focal);
            let (x1, y1) = sc.to_screen(b, cam.focal);
            sc.line_px(x0, y0, x1, y1, color, 200);
        }
    }
}
