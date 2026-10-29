// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Low-poly solid ship, rock and station meshes, defined in code.
use crate::gfx::rgb;
use crate::math::*;
use crate::raster::*;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum M {
    Tern,
    Gull,
    Pelican,
    Jackal,
    Hyena,
    Warden,
    Hound,
    Needle,
    Husk,
    Brood,
    Rock0,
    Rock1,
    Rock2,
    Canister,
    Capsule,
    Missile,
    Station,
    Debris,
}

pub const NUM_MESHES: usize = 18;

pub const STATION_HALF_LEN: f32 = 380.0;
pub const STATION_RADIUS: f32 = 520.0;
pub const SLOT_HX: f32 = 130.0;
pub const SLOT_HY: f32 = 42.0;

fn p(x: f32, y: f32, z: f32) -> V3 {
    v3(x, y, z)
}

/// Triangular prism with thickness along y.
fn tri_prism(b: &mut MeshBuilder, a: V3, c: V3, d: V3, half: f32, col: u32, glow: f32) {
    let up = |q: V3, s: f32| v3(q.x, q.y + s, q.z);
    let verts = [up(a, half), up(c, half), up(d, half), up(a, -half), up(c, -half), up(d, -half)];
    let f: [[u8; 3]; 8] = [[0, 1, 2], [3, 5, 4], [0, 1, 4], [0, 4, 3], [1, 2, 5], [1, 5, 4], [2, 0, 3], [2, 3, 5]];
    b.part(&verts, &f, col, glow);
}

/// Pyramid over four base points to an apex.
fn pyramid(b: &mut MeshBuilder, base: [V3; 4], apex: V3, col: u32, glow: f32) {
    let verts = [base[0], base[1], base[2], base[3], apex];
    let f: [[u8; 3]; 6] = [[0, 1, 2], [0, 2, 3], [0, 1, 4], [1, 2, 4], [2, 3, 4], [3, 0, 4]];
    b.part(&verts, &f, col, glow);
}

/// Dart hull: nose, left/right rear, top and bottom rear.
fn dart(b: &mut MeshBuilder, nose: V3, half_w: f32, rear_z: f32, top: f32, bot: f32, col: u32) {
    let v = [nose, p(-half_w, 0.0, rear_z), p(half_w, 0.0, rear_z), p(0.0, top, rear_z + 6.0), p(0.0, -bot, rear_z + 6.0)];
    let f: [[u8; 3]; 6] = [[0, 1, 3], [0, 3, 2], [0, 2, 4], [0, 4, 1], [1, 4, 3], [2, 3, 4]];
    b.part(&v, &f, col, 0.0);
}

fn engine_glow(b: &mut MeshBuilder, x: f32, y: f32, z: f32, s: f32) {
    b.cuboid(p(x - s, y - s, z - 2.0), p(x + s, y + s, z), rgb(255, 150, 70), 1.6);
    b.engines.push((p(x, y, z - 2.0), s * 2.2));
}

fn tern() -> Mesh {
    let mut b = MeshBuilder::new();
    let hull = rgb(176, 190, 208);
    let dark = rgb(60, 72, 92);
    let accent = rgb(226, 106, 44);
    dart(&mut b, p(0.0, 1.0, 72.0), 20.0, -34.0, 12.0, 8.0, hull);
    // canopy
    let cv = [p(-7.0, 7.0, -4.0), p(7.0, 7.0, -4.0), p(0.0, 7.5, 34.0), p(0.0, 15.0, 4.0)];
    b.part(&cv, &[[0, 1, 3], [1, 2, 3], [2, 0, 3], [0, 1, 2]], rgb(24, 70, 96), 0.25);
    for s in [-1.0f32, 1.0] {
        tri_prism(&mut b, p(s * 12.0, 0.0, 14.0), p(s * 16.0, 0.0, -32.0), p(s * 52.0, -2.0, -36.0), 1.6, if s < 0.0 { accent } else { hull }, 0.0);
        tri_prism(&mut b, p(s * 40.0, -2.0, -26.0), p(s * 52.0, -2.0, -36.0), p(s * 44.0, -2.0, -36.0), 3.0, dark, 0.0);
        b.cuboid(p(s * 9.0 - 5.0, -5.0, -40.0), p(s * 9.0 + 5.0, 5.0, -30.0), dark, 0.0);
        engine_glow(&mut b, s * 9.0, 0.0, -40.0, 3.6);
    }
    b.finish()
}

fn gull() -> Mesh {
    let mut b = MeshBuilder::new();
    let hull = rgb(168, 154, 120);
    let dark = rgb(70, 64, 54);
    let back = [p(-18.0, -13.0, -42.0), p(18.0, -13.0, -42.0), p(18.0, 13.0, -42.0), p(-18.0, 13.0, -42.0)];
    let front = [p(-13.0, -9.0, 26.0), p(13.0, -9.0, 26.0), p(13.0, 9.0, 26.0), p(-13.0, 9.0, 26.0)];
    b.prism8([back[0], back[1], back[2], back[3], front[0], front[1], front[2], front[3]], hull, 0.0);
    pyramid(&mut b, front, p(0.0, 0.0, 48.0), rgb(210, 200, 170), 0.0);
    let cv = [p(-6.0, 9.0, 8.0), p(6.0, 9.0, 8.0), p(6.0, 9.0, 24.0), p(-6.0, 9.0, 24.0), p(0.0, 13.0, 16.0)];
    b.part(&cv, &[[0, 1, 4], [1, 2, 4], [2, 3, 4], [3, 0, 4], [0, 1, 2], [0, 2, 3]], rgb(28, 80, 110), 0.3);
    for s in [-1.0f32, 1.0] {
        b.cuboid(p(s * 20.0 - 6.0, -9.0, -30.0), p(s * 20.0 + 6.0, 9.0, 8.0), dark, 0.0);
        b.cuboid(p(s * 14.0 - 4.0, -6.0, -50.0), p(s * 14.0 + 4.0, 6.0, -42.0), dark, 0.0);
        engine_glow(&mut b, s * 14.0, 0.0, -50.0, 3.0);
    }
    b.finish()
}

fn pelican() -> Mesh {
    let mut b = MeshBuilder::new();
    let spine = rgb(120, 126, 136);
    let cols = [rgb(176, 84, 52), rgb(70, 110, 150), rgb(190, 160, 70), rgb(90, 140, 100)];
    b.cuboid(p(-12.0, -12.0, -130.0), p(12.0, 12.0, 80.0), spine, 0.0);
    pyramid(&mut b, [p(-12.0, -12.0, 80.0), p(12.0, -12.0, 80.0), p(12.0, 12.0, 80.0), p(-12.0, 12.0, 80.0)], p(0.0, 0.0, 110.0), rgb(200, 205, 214), 0.0);
    b.cuboid(p(-10.0, 12.0, 40.0), p(10.0, 26.0, 74.0), rgb(210, 214, 222), 0.0);
    b.cuboid(p(-7.0, 22.0, 62.0), p(7.0, 27.0, 74.0), rgb(26, 82, 112), 0.3);
    let mut k = 0;
    for zc in [-100.0f32, -50.0, 0.0] {
        for (sx, sy) in [(-1.0f32, 1.0f32), (1.0, 1.0), (-1.0, -1.0), (1.0, -1.0)] {
            let x0 = if sx < 0.0 { -42.0 } else { 12.0 };
            let y0 = if sy < 0.0 { -38.0 } else { 12.0 };
            b.cuboid(p(x0, y0, zc - 22.0), p(x0 + 30.0, y0 + 26.0, zc + 22.0), cols[k % 4], 0.0);
            k += 1;
        }
    }
    b.cuboid(p(-22.0, -16.0, -146.0), p(22.0, 16.0, -130.0), rgb(60, 64, 72), 0.0);
    for s in [-1.0f32, 1.0] {
        engine_glow(&mut b, s * 12.0, 0.0, -146.0, 6.0);
    }
    b.finish()
}

fn jackal() -> Mesh {
    let mut b = MeshBuilder::new();
    let hull = rgb(150, 44, 40);
    let dark = rgb(34, 30, 34);
    dart(&mut b, p(0.0, 0.0, 62.0), 12.0, -32.0, 10.0, 7.0, hull);
    let cv = [p(-5.0, 6.0, 0.0), p(5.0, 6.0, 0.0), p(0.0, 6.5, 26.0), p(0.0, 12.0, 6.0)];
    b.part(&cv, &[[0, 1, 3], [1, 2, 3], [2, 0, 3], [0, 1, 2]], rgb(210, 70, 40), 0.7);
    for s in [-1.0f32, 1.0] {
        tri_prism(&mut b, p(s * 8.0, 0.0, 8.0), p(s * 10.0, 0.0, -30.0), p(s * 46.0, -10.0, -34.0), 1.4, dark, 0.0);
        tri_prism(&mut b, p(s * 8.0, 0.0, 8.0), p(s * 10.0, 0.0, -30.0), p(s * 38.0, 12.0, -30.0), 1.2, hull, 0.0);
        b.cuboid(p(s * 6.0 - 3.0, -3.0, -38.0), p(s * 6.0 + 3.0, 3.0, -30.0), dark, 0.0);
        engine_glow(&mut b, s * 6.0, 0.0, -38.0, 2.6);
    }
    b.finish()
}

fn hyena() -> Mesh {
    let mut b = MeshBuilder::new();
    let hull = rgb(92, 98, 70);
    let dark = rgb(38, 40, 34);
    let red = rgb(220, 50, 40);
    let back = [p(-22.0, -14.0, -50.0), p(22.0, -14.0, -50.0), p(22.0, 14.0, -50.0), p(-22.0, 14.0, -50.0)];
    let front = [p(-12.0, -8.0, 34.0), p(12.0, -8.0, 34.0), p(12.0, 8.0, 34.0), p(-12.0, 8.0, 34.0)];
    b.prism8([back[0], back[1], back[2], back[3], front[0], front[1], front[2], front[3]], hull, 0.0);
    pyramid(&mut b, front, p(0.0, -2.0, 62.0), dark, 0.0);
    b.cuboid(p(-5.0, 14.0, -10.0), p(5.0, 20.0, 20.0), rgb(210, 60, 40), 0.5);
    for s in [-1.0f32, 1.0] {
        b.cuboid(p(s * 30.0 - 9.0, -12.0, -62.0), p(s * 30.0 + 9.0, 12.0, 14.0), dark, 0.0);
        pyramid(&mut b, [p(s * 30.0 - 9.0, -12.0, 14.0), p(s * 30.0 + 9.0, -12.0, 14.0), p(s * 30.0 + 9.0, 12.0, 14.0), p(s * 30.0 - 9.0, 12.0, 14.0)], p(s * 30.0, 0.0, 40.0), hull, 0.0);
        b.cuboid(p(s * 18.0 - 2.0, -3.0, 10.0), p(s * 22.0 + 2.0, 3.0, 20.0), red, 1.0);
        engine_glow(&mut b, s * 30.0, 0.0, -62.0, 5.0);
    }
    b.finish()
}

fn warden() -> Mesh {
    let mut b = MeshBuilder::new();
    let hull = rgb(222, 228, 238);
    let blue = rgb(40, 84, 170);
    let back = [p(-16.0, -8.0, -42.0), p(16.0, -8.0, -42.0), p(16.0, 8.0, -42.0), p(-16.0, 8.0, -42.0)];
    let front = [p(-8.0, -5.0, 36.0), p(8.0, -5.0, 36.0), p(8.0, 5.0, 36.0), p(-8.0, 5.0, 36.0)];
    b.prism8([back[0], back[1], back[2], back[3], front[0], front[1], front[2], front[3]], hull, 0.0);
    pyramid(&mut b, front, p(0.0, 0.0, 66.0), blue, 0.0);
    b.cuboid(p(-5.0, 8.0, -4.0), p(5.0, 12.0, 26.0), rgb(24, 70, 96), 0.3);
    b.cuboid(p(-8.0, 8.0, -20.0), p(-2.0, 11.0, -12.0), rgb(60, 120, 255), 2.0);
    b.cuboid(p(2.0, 8.0, -20.0), p(8.0, 11.0, -12.0), rgb(255, 70, 70), 2.0);
    for s in [-1.0f32, 1.0] {
        tri_prism(&mut b, p(s * 14.0, 0.0, 10.0), p(s * 16.0, 0.0, -42.0), p(s * 40.0, 0.0, -44.0), 1.5, blue, 0.0);
        b.cuboid(p(s * 38.0 - 1.5, 0.0, -48.0), p(s * 38.0 + 1.5, 18.0, -30.0), hull, 0.0);
        engine_glow(&mut b, s * 9.0, 0.0, -42.0, 3.2);
    }
    b.finish()
}

fn hound() -> Mesh {
    let mut b = MeshBuilder::new();
    let hull = rgb(52, 98, 100);
    let gold = rgb(214, 170, 60);
    let dark = rgb(26, 40, 44);
    // cockpit pod
    dart(&mut b, p(0.0, 0.0, 70.0), 11.0, -10.0, 10.0, 8.0, hull);
    b.cuboid(p(-5.0, 8.0, 10.0), p(5.0, 12.0, 36.0), rgb(30, 120, 150), 0.4);
    for s in [-1.0f32, 1.0] {
        b.cuboid(p(s * 30.0 - 6.0, -6.0, -50.0), p(s * 30.0 + 6.0, 6.0, 40.0), hull, 0.0);
        pyramid(&mut b, [p(s * 30.0 - 6.0, -6.0, 40.0), p(s * 30.0 + 6.0, -6.0, 40.0), p(s * 30.0 + 6.0, 6.0, 40.0), p(s * 30.0 - 6.0, 6.0, 40.0)], p(s * 30.0, 0.0, 62.0), gold, 0.0);
        b.cuboid(p(s * 12.0, -2.5, -14.0), p(s * 24.0, 2.5, 6.0), dark, 0.0);
        b.cuboid(p(s * 30.0 - 2.0, 6.0, -10.0), p(s * 30.0 + 2.0, 9.0, 20.0), gold, 0.0);
        engine_glow(&mut b, s * 30.0, 0.0, -50.0, 4.2);
    }
    b.finish()
}

fn needle() -> Mesh {
    let mut b = MeshBuilder::new();
    let hull = rgb(98, 62, 150);
    let glow = rgb(90, 255, 200);
    let mut ring = Vec::new();
    for i in 0..6 {
        let a = TAU * i as f32 / 6.0;
        ring.push(p(14.0 * cos(a), 14.0 * sin(a), 0.0));
    }
    ring.push(p(0.0, 0.0, 78.0));
    ring.push(p(0.0, 0.0, -50.0));
    let mut f: Vec<[u8; 3]> = Vec::new();
    for i in 0..6u8 {
        f.push([i, (i + 1) % 6, 6]);
        f.push([i, (i + 1) % 6, 7]);
    }
    b.part(&ring, &f, hull, 0.0);
    for i in 0..3 {
        let a = TAU * (i as f32 + 0.5) / 3.0 + 0.5;
        let (cx, cy) = (cos(a), sin(a));
        let v = [p(cx * 12.0, cy * 12.0, 10.0), p(cx * 12.0 + sin(a) * 4.0, cy * 12.0 - cos(a) * 4.0, -20.0), p(cx * 12.0 - sin(a) * 4.0, cy * 12.0 + cos(a) * 4.0, -20.0), p(cx * 42.0, cy * 42.0, -40.0)];
        b.part(&v, &[[0, 1, 2], [0, 1, 3], [1, 2, 3], [2, 0, 3]], rgb(70, 40, 110), 0.0);
    }
    b.cuboid(p(-3.0, -3.0, -52.0), p(3.0, 3.0, -48.0), glow, 1.8);
    b.engines.push((p(0.0, 0.0, -54.0), 7.0));
    b.cuboid(p(-2.0, -2.0, 30.0), p(2.0, 2.0, 60.0), glow, 1.2);
    b.finish()
}

fn husk() -> Mesh {
    let mut b = MeshBuilder::new();
    let phi = 1.618034f32;
    let base: [V3; 12] = [
        p(-1.0, phi, 0.0),
        p(1.0, phi, 0.0),
        p(-1.0, -phi, 0.0),
        p(1.0, -phi, 0.0),
        p(0.0, -1.0, phi),
        p(0.0, 1.0, phi),
        p(0.0, -1.0, -phi),
        p(0.0, 1.0, -phi),
        p(phi, 0.0, -1.0),
        p(phi, 0.0, 1.0),
        p(-phi, 0.0, -1.0),
        p(-phi, 0.0, 1.0),
    ];
    let faces: [[u8; 3]; 20] = [
        [0, 11, 5],
        [0, 5, 1],
        [0, 1, 7],
        [0, 7, 10],
        [0, 10, 11],
        [1, 5, 9],
        [5, 11, 4],
        [11, 10, 2],
        [10, 7, 6],
        [7, 1, 8],
        [3, 9, 4],
        [3, 4, 2],
        [3, 2, 6],
        [3, 6, 8],
        [3, 8, 9],
        [4, 9, 5],
        [2, 4, 11],
        [6, 2, 10],
        [8, 6, 7],
        [9, 8, 1],
    ];
    let mut v = Vec::new();
    for (i, q) in base.iter().enumerate() {
        let k = if i % 2 == 0 { 21.0 } else { 11.0 };
        v.push(q.norm() * k);
    }
    b.part(&v, &faces, rgb(84, 52, 130), 0.0);
    let mut core = Vec::new();
    for q in base.iter() {
        core.push(q.norm() * 7.0);
    }
    b.part(&core, &faces, rgb(110, 255, 210), 1.6);
    b.finish()
}

fn brood() -> Mesh {
    let mut b = MeshBuilder::new();
    let hull = rgb(78, 48, 120);
    for (z, r, c) in [(-120.0f32, 60.0f32, 0.0f32), (-40.0, 90.0, 0.2), (60.0, 70.0, 0.0), (140.0, 40.0, 0.0)] {
        let mut ring = Vec::new();
        for i in 0..8 {
            let a = TAU * i as f32 / 8.0;
            ring.push(p(r * cos(a), r * sin(a), z - 30.0));
        }
        for i in 0..8 {
            let a = TAU * i as f32 / 8.0;
            ring.push(p(r * 0.8 * cos(a), r * 0.8 * sin(a), z + 40.0));
        }
        let mut f: Vec<[u8; 3]> = Vec::new();
        for i in 0..8u8 {
            let j = (i + 1) % 8;
            f.push([i, j, 8 + i]);
            f.push([j, 8 + j, 8 + i]);
        }
        for i in 1..7u8 {
            f.push([0, i, i + 1]);
            f.push([8, 8 + i, 8 + i + 1]);
        }
        b.part(&ring, &f, hull, c);
    }
    b.cuboid(p(-8.0, -8.0, -140.0), p(8.0, 8.0, -128.0), rgb(110, 255, 210), 1.8);
    b.engines.push((p(0.0, 0.0, -142.0), 14.0));
    b.finish()
}

fn rock(seed: u64) -> Mesh {
    let mut b = MeshBuilder::new();
    let phi = 1.618034f32;
    let base: [V3; 12] = [
        p(-1.0, phi, 0.0),
        p(1.0, phi, 0.0),
        p(-1.0, -phi, 0.0),
        p(1.0, -phi, 0.0),
        p(0.0, -1.0, phi),
        p(0.0, 1.0, phi),
        p(0.0, -1.0, -phi),
        p(0.0, 1.0, -phi),
        p(phi, 0.0, -1.0),
        p(phi, 0.0, 1.0),
        p(-phi, 0.0, -1.0),
        p(-phi, 0.0, 1.0),
    ];
    let faces: [[u8; 3]; 20] = [
        [0, 11, 5],
        [0, 5, 1],
        [0, 1, 7],
        [0, 7, 10],
        [0, 10, 11],
        [1, 5, 9],
        [5, 11, 4],
        [11, 10, 2],
        [10, 7, 6],
        [7, 1, 8],
        [3, 9, 4],
        [3, 4, 2],
        [3, 2, 6],
        [3, 6, 8],
        [3, 8, 9],
        [4, 9, 5],
        [2, 4, 11],
        [6, 2, 10],
        [8, 6, 7],
        [9, 8, 1],
    ];
    let mut rng = Rng::new(seed);
    let sx = rng.fr(0.8, 1.2);
    let sy = rng.fr(0.7, 1.1);
    let sz = rng.fr(0.8, 1.3);
    let mut v = Vec::new();
    for q in base.iter() {
        let k = rng.fr(0.75, 1.15) * 30.0;
        let n = q.norm();
        v.push(v3(n.x * k * sx, n.y * k * sy, n.z * k * sz));
    }
    b.part(&v, &faces, rgb(112, 100, 90), 0.0);
    // darken some faces for variation
    for (i, t) in b.t.iter_mut().enumerate() {
        if i % 3 == 0 {
            t.col = rgb(96, 86, 80);
        } else if i % 7 == 0 {
            t.col = rgb(128, 118, 108);
        }
    }
    b.smooth();
    b.finish()
}

fn canister() -> Mesh {
    let mut b = MeshBuilder::new();
    b.cuboid(p(-9.0, -9.0, -12.0), p(9.0, 9.0, 12.0), rgb(206, 170, 58), 0.0);
    b.cuboid(p(-9.5, -9.5, -2.0), p(9.5, 9.5, 2.0), rgb(60, 60, 66), 0.0);
    b.cuboid(p(-3.0, 9.0, -4.0), p(3.0, 10.0, 4.0), rgb(255, 120, 60), 2.0);
    b.finish()
}

fn capsule() -> Mesh {
    let mut b = MeshBuilder::new();
    let v = [p(0.0, 0.0, 16.0), p(-9.0, -9.0, -8.0), p(9.0, -9.0, -8.0), p(9.0, 9.0, -8.0), p(-9.0, 9.0, -8.0)];
    b.part(&v, &[[0, 1, 2], [0, 2, 3], [0, 3, 4], [0, 4, 1], [1, 2, 3], [1, 3, 4]], rgb(240, 120, 40), 0.3);
    b.cuboid(p(-3.0, 9.0, -2.0), p(3.0, 10.0, 4.0), rgb(255, 255, 255), 2.0);
    b.finish()
}

fn missile() -> Mesh {
    let mut b = MeshBuilder::new();
    pyramid(&mut b, [p(-2.5, -2.5, -10.0), p(2.5, -2.5, -10.0), p(2.5, 2.5, -10.0), p(-2.5, 2.5, -10.0)], p(0.0, 0.0, 16.0), rgb(230, 232, 238), 0.0);
    pyramid(&mut b, [p(-2.5, -2.5, 2.0), p(2.5, -2.5, 2.0), p(2.5, 2.5, 2.0), p(-2.5, 2.5, 2.0)], p(0.0, 0.0, 16.0), rgb(214, 60, 50), 0.0);
    b.cuboid(p(-9.0, -0.6, -12.0), p(9.0, 0.6, -6.0), rgb(90, 96, 108), 0.0);
    b.cuboid(p(-0.6, -9.0, -12.0), p(0.6, 9.0, -6.0), rgb(90, 96, 108), 0.0);
    b.engines.push((p(0.0, 0.0, -12.0), 4.0));
    b.finish()
}

fn station() -> Mesh {
    let mut b = MeshBuilder::new();
    let r = STATION_RADIUS;
    let hz = STATION_HALF_LEN;
    let zf = hz - 40.0;
    // octagonal shell
    let mut v = Vec::new();
    for i in 0..8 {
        let a = TAU * (i as f32 + 0.5) / 8.0;
        v.push(p(r * cos(a), r * sin(a), -hz));
    }
    for i in 0..8 {
        let a = TAU * (i as f32 + 0.5) / 8.0;
        v.push(p(r * cos(a), r * sin(a), zf));
    }
    let mut f: Vec<[u8; 3]> = Vec::new();
    for i in 0..8u8 {
        let j = (i + 1) % 8;
        f.push([i, j, 8 + i]);
        f.push([j, 8 + j, 8 + i]);
    }
    for i in 1..7u8 {
        f.push([0, i, i + 1]);
        f.push([8, 8 + i, 8 + i + 1]);
    }
    let first = b.t.len();
    b.part(&v, &f, rgb(150, 156, 168), 0.0);
    for (k, t) in b.t[first..first + 16].iter_mut().enumerate() {
        let side = k / 2;
        t.col = if side % 2 == 0 { rgb(150, 156, 168) } else { rgb(112, 120, 136) };
    }
    // front face interior (dark with lights)
    let n = b.t.len();
    for t in b.t[first + 16..n].iter_mut() {
        t.col = rgb(62, 70, 88);
    }
    // frame around the slot
    let frame = rgb(205, 210, 220);
    let z0 = zf;
    let z1 = hz;
    let o = 440.0;
    b.cuboid(p(-o, SLOT_HY, z0), p(o, o, z1), frame, 0.0);
    b.cuboid(p(-o, -o, z0), p(o, -SLOT_HY, z1), frame, 0.0);
    b.cuboid(p(-o, -SLOT_HY, z0), p(-SLOT_HX, SLOT_HY, z1), frame, 0.0);
    b.cuboid(p(SLOT_HX, -SLOT_HY, z0), p(o, SLOT_HY, z1), frame, 0.0);
    // slot lights: green on one side, amber on the other, red top/bottom (they rotate with the station)
    b.cuboid(p(-SLOT_HX - 10.0, -12.0, z1), p(-SLOT_HX, 12.0, z1 + 8.0), rgb(80, 255, 120), 2.2);
    b.cuboid(p(SLOT_HX, -12.0, z1), p(SLOT_HX + 10.0, 12.0, z1 + 8.0), rgb(255, 80, 60), 2.2);
    b.cuboid(p(-12.0, SLOT_HY, z1), p(12.0, SLOT_HY + 10.0, z1 + 8.0), rgb(255, 190, 70), 2.2);
    b.cuboid(p(-12.0, -SLOT_HY - 10.0, z1), p(12.0, -SLOT_HY, z1 + 8.0), rgb(255, 190, 70), 2.2);
    // inner lit strip deep in the slot
    b.cuboid(p(-SLOT_HX + 20.0, -SLOT_HY + 20.0, zf - 4.0), p(SLOT_HX - 20.0, SLOT_HY - 20.0, zf), rgb(120, 170, 230), 0.9);
    // solar wings, mast, dish
    for s in [-1.0f32, 1.0] {
        b.cuboid(p(s * 560.0 - if s < 0.0 { 420.0 } else { 0.0 }, -4.0, -120.0), p(s * 560.0 + if s < 0.0 { 0.0 } else { 420.0 }, 4.0, 140.0), rgb(32, 58, 120), 0.35);
        b.cuboid(p(s * 520.0 - 8.0, -8.0, -10.0), p(s * 520.0 + 8.0, 8.0, 10.0), rgb(110, 116, 128), 0.0);
    }
    b.cuboid(p(-10.0, r - 20.0, -40.0), p(10.0, r + 150.0, -20.0), rgb(110, 116, 128), 0.0);
    b.cuboid(p(-4.0, r + 150.0, -34.0), p(4.0, r + 190.0, -26.0), rgb(255, 80, 70), 2.0);
    // hull band lights
    for i in 0..8 {
        let a = TAU * (i as f32 + 0.5) / 8.0;
        let (c, s) = (cos(a), sin(a));
        b.cuboid(p(c * r * 0.93 - 6.0, s * r * 0.93 - 6.0, -hz + 20.0), p(c * r * 0.93 + 6.0, s * r * 0.93 + 6.0, zf - 20.0), rgb(255, 214, 140), 0.6);
    }
    b.finish()
}

fn debris() -> Mesh {
    let mut b = MeshBuilder::new();
    let v = [p(-1.0, -0.6, -0.8), p(1.0, -0.6, -0.8), p(0.0, 1.0, -0.6), p(0.0, 0.0, 1.2)];
    b.part(&v, &[[0, 1, 2], [0, 1, 3], [1, 2, 3], [2, 0, 3]], rgb(150, 150, 158), 0.0);
    b.finish()
}

pub fn build_all() -> Vec<Mesh> {
    let mut v = Vec::with_capacity(NUM_MESHES);
    v.push(tern());
    v.push(gull());
    v.push(pelican());
    v.push(jackal());
    v.push(hyena());
    v.push(warden());
    v.push(hound());
    v.push(needle());
    v.push(husk());
    v.push(brood());
    v.push(rock(11));
    v.push(rock(222));
    v.push(rock(3333));
    v.push(canister());
    v.push(capsule());
    v.push(missile());
    v.push(station());
    v.push(debris());
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_meshes_build() {
        let m = build_all();
        assert_eq!(m.len(), NUM_MESHES);
        for (i, mesh) in m.iter().enumerate() {
            assert!(!mesh.t.is_empty(), "mesh {}", i);
            assert!(mesh.radius > 1.0);
        }
    }
}
