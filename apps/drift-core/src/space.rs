// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Backdrops: procedural planets (cube-map textures, ray-cast spheres with day/night terminator and
//! atmosphere), stars with corona, nebula sky and star field.
use crate::gfx::*;
use crate::math::*;
use crate::raster::*;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PlanetKind {
    Ocean,
    Arid,
    Frozen,
    Volcanic,
    Barren,
    Jungle,
}

pub fn face_dir(face: usize, u: f32, v: f32) -> V3 {
    match face {
        0 => v3(1.0, -v, -u),
        1 => v3(-1.0, -v, u),
        2 => v3(u, 1.0, v),
        3 => v3(u, -1.0, -v),
        4 => v3(u, -v, 1.0),
        _ => v3(-u, -v, -1.0),
    }
}

/// Returns (face, u, v) with u, v in -1..1.
pub fn dir_face(d: V3) -> (usize, f32, f32) {
    let (ax, ay, az) = (abs(d.x), abs(d.y), abs(d.z));
    if ax >= ay && ax >= az {
        let i = 1.0 / ax;
        if d.x > 0.0 {
            (0, -d.z * i, -d.y * i)
        } else {
            (1, d.z * i, -d.y * i)
        }
    } else if ay >= az {
        let i = 1.0 / ay;
        if d.y > 0.0 {
            (2, d.x * i, d.z * i)
        } else {
            (3, d.x * i, -d.z * i)
        }
    } else {
        let i = 1.0 / az;
        if d.z > 0.0 {
            (4, d.x * i, -d.y * i)
        } else {
            (5, -d.x * i, -d.y * i)
        }
    }
}

pub struct PlanetTex {
    pub n: usize,
    pub alb: Vec<u32>,
    pub cloud: Vec<u8>,
    /// bit 7 water, low 7 bits night-light intensity
    pub aux: Vec<u8>,
    pub kind: PlanetKind,
    pub atmo: [f32; 3],
    pub atmo_k: f32,
}

fn mixc(a: [f32; 3], b: [f32; 3], t: f32) -> [f32; 3] {
    [lerp(a[0], b[0], t), lerp(a[1], b[1], t), lerp(a[2], b[2], t)]
}

impl PlanetTex {
    /// `lights` 0..1: how many city lights on the night side.
    pub fn generate(seed: u64, kind: PlanetKind, n: usize, lights: f32) -> PlanetTex {
        let mut rng = Rng::new(seed);
        let s1 = rng.next_u32();
        let s2 = rng.next_u32();
        let s3 = rng.next_u32();
        let off = v3(rng.fr(-50.0, 50.0), rng.fr(-50.0, 50.0), rng.fr(-50.0, 50.0));
        let sea = rng.fr(0.44, 0.56);
        let hue = rng.f();
        let mut alb = vec![0u32; 6 * n * n];
        let mut cloud = vec![0u8; 6 * n * n];
        let mut aux = vec![0u8; 6 * n * n];
        let (atmo, atmo_k, cloud_amt) = match kind {
            PlanetKind::Ocean => ([0.35, 0.55, 1.0], 1.0, 1.0),
            PlanetKind::Jungle => ([0.4, 0.8, 0.7], 0.9, 1.0),
            PlanetKind::Arid => ([1.0, 0.7, 0.4], 0.7, 0.35),
            PlanetKind::Frozen => ([0.6, 0.8, 1.0], 0.8, 0.5),
            PlanetKind::Volcanic => ([1.0, 0.4, 0.25], 0.8, 0.8),
            PlanetKind::Barren => ([0.7, 0.7, 0.75], 0.15, 0.0),
        };
        for face in 0..6 {
            for j in 0..n {
                for i in 0..n {
                    let u = (i as f32 + 0.5) / n as f32 * 2.0 - 1.0;
                    let v = (j as f32 + 0.5) / n as f32 * 2.0 - 1.0;
                    let d = face_dir(face, u, v).norm();
                    let p = d * 2.2 + off;
                    let h = fbm3(p, 5, s1);
                    let detail = noise3(d * 40.0 + off, s3);
                    let lat = abs(d.y);
                    let mut c;
                    let mut water = false;
                    let mut glowv = 0.0f32;
                    match kind {
                        PlanetKind::Ocean | PlanetKind::Jungle => {
                            let jung = kind == PlanetKind::Jungle;
                            if h < sea {
                                let depth = clamp((sea - h) * 7.0, 0.0, 1.0);
                                c = mixc([0.10, 0.38, 0.55], [0.01, 0.07, 0.25], depth);
                                if jung {
                                    c = mixc([0.05, 0.30, 0.38], [0.01, 0.08, 0.15], depth);
                                }
                                water = true;
                            } else {
                                let e = clamp((h - sea) * 6.0, 0.0, 1.0);
                                let green = if jung { [0.04, 0.35, 0.10] } else { [0.18, 0.42, 0.14] };
                                let dry = if jung { [0.12, 0.30, 0.08] } else { [0.50, 0.42, 0.24] };
                                let dryness = smoothstep(0.35, 0.8, noise3(p * 0.7, s2) + lat * 0.4 - (if jung { 0.35 } else { 0.0 }));
                                c = mixc(green, dry, dryness);
                                c = mixc(c, [0.45, 0.43, 0.40], smoothstep(0.55, 1.0, e));
                                c = mixc(c, [0.95, 0.96, 1.0], smoothstep(0.85, 1.0, e));
                                if lights > 0.0 && noise3(d * 18.0 + off, s2 ^ 77) > 0.62 && lat < 0.8 {
                                    glowv = lights * (0.4 + 0.6 * detail);
                                }
                            }
                            if lat + (noise3(p * 3.0, s3) - 0.5) * 0.15 > 0.88 {
                                c = mixc(c, [0.93, 0.95, 1.0], 0.95);
                                water = false;
                                glowv = 0.0;
                            }
                        }
                        PlanetKind::Arid => {
                            let band = noise3(v3(p.x * 0.5, p.y * 3.0, p.z * 0.5), s2);
                            let base = mixc([0.62, 0.40, 0.20], [0.80, 0.62, 0.38], band);
                            c = mixc(base, [0.36, 0.22, 0.14], smoothstep(0.55, 0.8, h));
                            c = mixc(c, [0.9, 0.85, 0.75], smoothstep(0.9, 0.97, lat));
                            if lights > 0.0 && h < 0.42 && noise3(d * 20.0 + off, s2 ^ 5) > 0.6 {
                                glowv = lights * 0.8;
                            }
                        }
                        PlanetKind::Frozen => {
                            let crack = abs(noise3(p * 4.0, s2) - 0.5);
                            c = mixc([0.80, 0.88, 0.96], [0.55, 0.70, 0.88], h);
                            if crack < 0.015 {
                                c = mixc(c, [0.20, 0.30, 0.45], 0.8);
                            }
                            c = mixc(c, [0.35, 0.42, 0.52], smoothstep(0.62, 0.8, h) * 0.6);
                            if lights > 0.0 && noise3(d * 16.0 + off, s2 ^ 9) > 0.68 {
                                glowv = lights * 0.7;
                            }
                        }
                        PlanetKind::Volcanic => {
                            let vein = abs(noise3(p * 3.0, s2) - 0.5);
                            c = mixc([0.10, 0.08, 0.07], [0.27, 0.19, 0.15], h);
                            if vein < 0.03 + 0.04 * smoothstep(0.5, 0.75, h) {
                                c = [0.9, 0.35, 0.05];
                                glowv = 1.0;
                            }
                        }
                        PlanetKind::Barren => {
                            let base = mixc([0.34 + hue * 0.1, 0.32, 0.30], [0.62, 0.58, 0.54], h);
                            let crater = noise3(d * 14.0 + off, s2);
                            c = mixc(base, [0.18, 0.17, 0.17], smoothstep(0.7, 0.8, crater) * 0.7);
                            c = mixc(c, [0.7, 0.68, 0.64], smoothstep(0.55, 0.62, crater) * smoothstep(0.7, 0.62, crater) * 0.5);
                        }
                    }
                    let k = 0.9 + 0.2 * detail;
                    let idx = face * n * n + j * n + i;
                    alb[idx] = pack((c[0] * k * 255.0) as u32, (c[1] * k * 255.0) as u32, (c[2] * k * 255.0) as u32);
                    if cloud_amt > 0.0 {
                        let cl = fbm3(d * 3.2 + off * 0.3, 5, s3 ^ 0x55);
                        // bands for stretched look
                        let band = noise3(v3(d.x * 2.0, d.y * 9.0, d.z * 2.0) + off, s1 ^ 3);
                        let cv = smoothstep(0.52, 0.72, cl * 0.75 + band * 0.25) * cloud_amt;
                        cloud[idx] = (cv * 235.0) as u8;
                    }
                    aux[idx] = (if water { 128 } else { 0 }) | ((glowv.min(1.0) * 127.0) as u8);
                }
            }
        }
        PlanetTex { n, alb, cloud, aux, kind, atmo, atmo_k }
    }

    fn sample(&self, d: V3) -> ([f32; 3], f32, u8) {
        let (face, u, v) = dir_face(d);
        let n = self.n;
        let tx = (u * 0.5 + 0.5) * n as f32 - 0.5;
        let ty = (v * 0.5 + 0.5) * n as f32 - 0.5;
        let fx = floor(tx);
        let fy = floor(ty);
        let wx = tx - fx;
        let wy = ty - fy;
        let lim = n as i32 - 1;
        let x0 = (fx as i32).clamp(0, lim) as usize;
        let y0 = (fy as i32).clamp(0, lim) as usize;
        let x1 = (fx as i32 + 1).clamp(0, lim) as usize;
        let y1 = (fy as i32 + 1).clamp(0, lim) as usize;
        let base = face * n * n;
        let i00 = base + y0 * n + x0;
        let i10 = base + y0 * n + x1;
        let i01 = base + y1 * n + x0;
        let i11 = base + y1 * n + x1;
        let w00 = (1.0 - wx) * (1.0 - wy);
        let w10 = wx * (1.0 - wy);
        let w01 = (1.0 - wx) * wy;
        let w11 = wx * wy;
        let mut c = [0.0f32; 3];
        for (i, w) in [(i00, w00), (i10, w10), (i01, w01), (i11, w11)] {
            let (r, g, b) = chan(self.alb[i]);
            c[0] += r as f32 * w;
            c[1] += g as f32 * w;
            c[2] += b as f32 * w;
        }
        let cl = (self.cloud[i00] as f32 * w00 + self.cloud[i10] as f32 * w10 + self.cloud[i01] as f32 * w01 + self.cloud[i11] as f32 * w11)
            * (1.0 / 255.0);
        let nearest = if wx < 0.5 { if wy < 0.5 { i00 } else { i01 } } else if wy < 0.5 { i10 } else { i11 };
        (c, cl, self.aux[nearest])
    }
}

/// Draw a textured, lit planet by ray-casting a sphere per pixel.
pub fn draw_planet(sc: &mut Scene, cam: &Camera, tex: &PlanetTex, center: V3, radius: f32, spin: &Orient, light_dir: V3, light_col: [f32; 3]) {
    let cc = cam.o.to_local(center - cam.pos);
    let dist2 = cc.len2();
    if cc.z + radius < NEAR {
        return;
    }
    let (hw, hh) = (sc.w as f32 * 0.5, sc.h as f32 * 0.5);
    let inv_f = 1.0 / cam.focal;
    let shell = radius * 1.07;
    let c2r = dist2 - radius * radius;
    let c2s = dist2 - shell * shell;
    // bounding box of the shell
    let (x0, x1, y0, y1);
    if cc.z > shell * 1.2 {
        let k = cam.focal / cc.z;
        let rp = shell * k * 1.2 + 2.0;
        let (sx, sy) = (hw + cc.x * k, hh - cc.y * k);
        x0 = floor(sx - rp).max(0.0) as i32;
        x1 = (sx + rp).min(sc.w as f32) as i32;
        y0 = floor(sy - rp).max(0.0) as i32;
        y1 = (sy + rp).min(sc.h as f32) as i32;
    } else {
        x0 = 0;
        x1 = sc.w as i32;
        y0 = 0;
        y1 = sc.h as i32;
    }
    // light and view vectors in camera space for speed
    let ld_cam = cam.o.to_local(light_dir);
    let _ = ld_cam;
    for y in y0..y1 {
        let dy = -(y as f32 + 0.5 - hh) * inv_f;
        let row = y as usize * sc.w;
        for x in x0..x1 {
            let dx = (x as f32 + 0.5 - hw) * inv_f;
            let a = dx * dx + dy * dy + 1.0;
            let b = dx * cc.x + dy * cc.y + cc.z;
            let disc = b * b - a * c2r;
            let i = row + x as usize;
            if disc > 0.0 && b > 0.0 {
                let t = (b - sqrt(disc)) / a;
                if t <= NEAR * 0.5 {
                    continue;
                }
                let iz = 1.0 / t;
                if iz <= sc.iz[i] {
                    continue;
                }
                // surface normal in camera space, then world, then planet frame
                let ncam = v3(dx * t - cc.x, dy * t - cc.y, t - cc.z) * (1.0 / radius);
                let nw = cam.o.to_world(ncam);
                let npl = spin.to_local(nw);
                let (alb, cloud, aux) = tex.sample(npl);
                let ndl = nw.dot(light_dir);
                let diff = smoothstep(-0.06, 0.3, ndl);
                let vdir = cam.o.to_world(v3(dx, dy, 1.0).norm()); // from camera to point
                let facing = max(0.0, -nw.dot(vdir));
                let water = aux & 128 != 0;
                let mut out = [0.0f32; 3];
                let amb = 0.035;
                for k in 0..3 {
                    let surf = alb[k] * (1.0 - cloud * 0.0);
                    let lit = (amb + diff * light_col[k]) * 1.0;
                    let cl = 235.0 * (amb * 1.5 + diff * light_col[k]);
                    out[k] = lerp(surf * lit, cl, cloud);
                }
                if water && cloud < 0.6 {
                    let hv = (light_dir - vdir).norm();
                    let s = max(0.0, nw.dot(hv));
                    let sp = powi(s, 48) * diff * (1.0 - cloud) * 0.9;
                    for o in out.iter_mut() {
                        *o += 255.0 * sp;
                    }
                }
                let glowv = (aux & 127) as f32 / 127.0;
                if glowv > 0.0 {
                    let night = 1.0 - smoothstep(-0.12, 0.08, ndl);
                    let g = glowv * night * (1.0 - cloud * 0.7);
                    if tex.kind == PlanetKind::Volcanic {
                        out[0] += 255.0 * g;
                        out[1] += 110.0 * g;
                        out[2] += 20.0 * g;
                    } else {
                        out[0] += 255.0 * g;
                        out[1] += 200.0 * g;
                        out[2] += 120.0 * g;
                    }
                }
                let fres = powi(1.0 - facing, 3);
                let rim = fres * (0.15 + 0.85 * smoothstep(-0.25, 0.5, ndl)) * tex.atmo_k;
                for k in 0..3 {
                    out[k] += 255.0 * tex.atmo[k] * rim * 0.9;
                }
                sc.iz[i] = iz;
                sc.col[i] = pack(out[0].max(0.0) as u32, out[1].max(0.0) as u32, out[2].max(0.0) as u32);
            } else if tex.atmo_k > 0.2 && b > 0.0 {
                // atmosphere halo just outside the limb
                let h2 = dist2 - b * b / a;
                let _ = c2s;
                if h2 < shell * shell {
                    let h = sqrt(max(h2, 0.0));
                    if h < radius {
                        continue;
                    }
                    let tc = b / a;
                    let iz = 1.0 / tc;
                    if iz <= sc.iz[i] {
                        continue;
                    }
                    let f = (shell - h) / (shell - radius);
                    let pc = v3(dx * tc - cc.x, dy * tc - cc.y, tc - cc.z) * (1.0 / h);
                    let nw = cam.o.to_world(pc);
                    let lit = smoothstep(-0.35, 0.4, nw.dot(light_dir));
                    let k = f * f * f * lit * tex.atmo_k;
                    sc.col[i] = add_px(sc.col[i], pack((tex.atmo[0] * 255.0) as u32, (tex.atmo[1] * 255.0) as u32, (tex.atmo[2] * 255.0) as u32), (k * 255.0) as u32);
                }
            }
        }
    }
}

/// Draw a star: limb-darkened disc with granulation, and a corona sprite.
pub fn draw_sun(sc: &mut Scene, cam: &Camera, pos: V3, radius: f32, color: [f32; 3], time: f32) {
    let c = cam.o.to_local(pos - cam.pos);
    if c.z < NEAR {
        return;
    }
    let k = cam.focal / c.z;
    let rp = radius * k;
    let (sx, sy) = (sc.w as f32 * 0.5 + c.x * k, sc.h as f32 * 0.5 - c.y * k);
    if sx < -rp * 6.0 - 50.0 || sx > sc.w as f32 + rp * 6.0 + 50.0 || sy < -rp * 6.0 - 50.0 || sy > sc.h as f32 + rp * 6.0 + 50.0 {
        return;
    }
    let col = pack((color[0] * 255.0) as u32, (color[1] * 255.0) as u32, (color[2] * 255.0) as u32);
    // corona first (additive), then the disc over it
    let iz = 1.0 / c.z;
    let reach = rp * 4.5 + 6.0;
    let (x0, x1) = (floor(sx - reach).max(0.0) as i32, (sx + reach).min(sc.w as f32) as i32);
    let (y0, y1) = (floor(sy - reach).max(0.0) as i32, (sy + reach).min(sc.h as f32) as i32);
    let irp = 1.0 / max(rp, 0.5);
    let ang_k = 7.0;
    for y in y0..y1 {
        let dy = y as f32 + 0.5 - sy;
        let row = y as usize * sc.w;
        for x in x0..x1 {
            let dx = x as f32 + 0.5 - sx;
            let d = sqrt(dx * dx + dy * dy) * irp;
            let i = row + x as usize;
            if sc.iz[i] > iz {
                continue;
            }
            if d < 1.0 {
                let mu = sqrt(1.0 - d * d);
                let limb = 0.45 + 0.55 * mu;
                let gran = 0.92 + 0.08 * sin(dx * irp * 17.0 + time * 0.3) * sin(dy * irp * 13.0 - time * 0.2);
                let l = limb * gran;
                let hot = powi(mu, 3) * 0.55;
                let r = (color[0] * l + hot) * 255.0 * 1.15;
                let g = (color[1] * l + hot) * 255.0 * 1.15;
                let b = (color[2] * l + hot) * 255.0 * 1.15;
                sc.col[i] = pack(r.max(0.0) as u32, g.max(0.0) as u32, b.max(0.0) as u32);
            } else {
                let fall = 1.0 / (1.0 + (d - 1.0) * ang_k * 0.5 * (d - 1.0) * 6.0 + (d - 1.0) * 3.0);
                let kk = fall * 0.85;
                sc.col[i] = add_px(sc.col[i], col, (kk * 255.0) as u32);
            }
        }
    }
}

/// Linear interpolation of packed 0x00RRGGBB colours, t in 0..=256.
#[inline]
pub fn lerp_swar(a: u32, b: u32, t: u32) -> u32 {
    let rb = (((a & 0xFF00FF) * (256 - t) + (b & 0xFF00FF) * t) >> 8) & 0xFF00FF;
    let g = (((a & 0x00FF00) * (256 - t) + (b & 0x00FF00) * t) >> 8) & 0x00FF00;
    rb | g
}

pub struct Star {
    pub dir: V3,
    pub b: u8,
    pub col: u32,
}

pub struct Sky {
    pub stars: Vec<Star>,
    cube: Vec<u32>,
    cube_n: usize,
    low: Vec<u32>,
}

impl Sky {
    pub fn generate(seed: u64) -> Sky {
        let mut rng = Rng::new(seed ^ 0x5151);
        let n = 64;
        let s1 = rng.next_u32();
        let s2 = rng.next_u32();
        let hue_a = [rng.fr(0.1, 1.0), rng.fr(0.05, 0.6), rng.fr(0.2, 1.0)];
        let hue_b = [rng.fr(0.1, 0.9), rng.fr(0.2, 0.9), rng.fr(0.1, 1.0)];
        let amount = rng.fr(0.45, 1.0);
        let band = rng.unit();
        let mut cube = vec![0u32; 6 * n * n];
        for face in 0..6 {
            for j in 0..n {
                for i in 0..n {
                    let u = (i as f32 + 0.5) / n as f32 * 2.0 - 1.0;
                    let v = (j as f32 + 0.5) / n as f32 * 2.0 - 1.0;
                    let d = face_dir(face, u, v).norm();
                    let f = fbm3(d * 1.7, 5, s1);
                    let f2 = fbm3(d * 3.1 + v3(7.0, 3.0, 1.0), 4, s2);
                    let dens = smoothstep(0.42, 0.78, f) * amount;
                    let bd = abs(d.dot(band));
                    let gal = exp_neg(bd * bd * 14.0) * (0.35 + 0.65 * f2);
                    let mixv = f2;
                    let mut r = 0.0;
                    let mut g = 0.0;
                    let mut b = 0.0;
                    for (k, out) in [&mut r, &mut g, &mut b].into_iter().enumerate() {
                        *out = (hue_a[k] * (1.0 - mixv) + hue_b[k] * mixv) * dens * 70.0 + gal * [34.0, 32.0, 40.0][k];
                    }
                    cube[face * n * n + j * n + i] = pack(r as u32, g as u32, b as u32);
                }
            }
        }
        let mut stars = Vec::new();
        for _ in 0..1800 {
            let dir = rng.unit();
            let m = rng.f();
            let b = (40.0 + 215.0 * m * m * m) as u8;
            let tint = rng.f();
            let col = if tint < 0.15 {
                rgb(255, 200, 160)
            } else if tint < 0.3 {
                rgb(170, 200, 255)
            } else {
                rgb(255, 255, 255)
            };
            stars.push(Star { dir, b, col });
        }
        Sky { stars, cube, cube_n: n, low: Vec::new() }
    }

    pub fn draw(&mut self, sc: &mut Scene, cam: &Camera) {
        let (w, h) = (sc.w, sc.h);
        let (sw, sh) = (w / 4 + 2, h / 4 + 2);
        if self.low.len() != sw * sh {
            self.low = vec![0; sw * sh];
        }
        let inv_f = 1.0 / cam.focal;
        let n = self.cube_n;
        for j in 0..sh {
            let dy = -((j * 4) as f32 + 2.0 - h as f32 * 0.5) * inv_f;
            for i in 0..sw {
                let dx = ((i * 4) as f32 + 2.0 - w as f32 * 0.5) * inv_f;
                let d = cam.o.r * dx + cam.o.u * dy + cam.o.f;
                let (face, u, v) = dir_face(d);
                let tx = (u * 0.5 + 0.5) * n as f32 - 0.5;
                let ty = (v * 0.5 + 0.5) * n as f32 - 0.5;
                let (fx, fy) = (floor(tx), floor(ty));
                let (wx, wy) = (((tx - fx) * 256.0) as u32, ((ty - fy) * 256.0) as u32);
                let lim = n as i32 - 1;
                let x0 = (fx as i32).clamp(0, lim) as usize;
                let y0 = (fy as i32).clamp(0, lim) as usize;
                let x1 = (fx as i32 + 1).clamp(0, lim) as usize;
                let y1 = (fy as i32 + 1).clamp(0, lim) as usize;
                let base = face * n * n;
                let c00 = self.cube[base + y0 * n + x0];
                let c10 = self.cube[base + y0 * n + x1];
                let c01 = self.cube[base + y1 * n + x0];
                let c11 = self.cube[base + y1 * n + x1];
                self.low[j * sw + i] = lerp_swar(lerp_swar(c00, c10, wx), lerp_swar(c01, c11, wx), wy);
            }
        }
        let mut rowbuf = vec![0u32; sw];
        for y in 0..h {
            let sy0 = y / 4;
            let wy = ((y % 4) as u32 * 2 + 1) * 32;
            for i in 0..sw {
                rowbuf[i] = lerp_swar(self.low[sy0 * sw + i], self.low[(sy0 + 1) * sw + i], wy);
            }
            let row = y * w;
            for sx0 in 0..(w / 4 + 1) {
                let (a, b) = (rowbuf[sx0], rowbuf[sx0 + 1]);
                for k in 0..4usize {
                    let x = sx0 * 4 + k;
                    if x < w {
                        sc.col[row + x] = lerp_swar(a, b, (k as u32 * 2 + 1) * 32);
                    }
                }
            }
        }
        for z in sc.iz.iter_mut() {
            *z = 0.0;
        }
        for s in &self.stars {
            let c = cam.o.to_local(s.dir);
            if c.z < 0.05 {
                continue;
            }
            let k = cam.focal / c.z;
            let (px, py) = (w as f32 * 0.5 + c.x * k, h as f32 * 0.5 - c.y * k);
            let (x, y) = (px as i32, py as i32);
            if px < 1.0 || py < 1.0 || x >= w as i32 - 1 || y >= h as i32 - 1 {
                continue;
            }
            let i = y as usize * w + x as usize;
            sc.col[i] = add_px(sc.col[i], s.col, s.b as u32);
            if s.b > 170 {
                for off in [1usize, w] {
                    sc.col[i + off] = add_px(sc.col[i + off], s.col, s.b as u32 / 3);
                    sc.col[i - off] = add_px(sc.col[i - off], s.col, s.b as u32 / 3);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cube_mapping_roundtrip() {
        let mut rng = Rng::new(3);
        for _ in 0..500 {
            let d = rng.unit();
            let (f, u, v) = dir_face(d);
            let back = face_dir(f, u, v).norm();
            assert!((back - d).len() < 1e-4);
        }
    }
}
