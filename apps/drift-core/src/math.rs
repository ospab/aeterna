// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Own math: vectors, orientation frames, trig without libm, random numbers, value noise.
use core::ops::{Add, AddAssign, Mul, Neg, Sub};

pub const PI: f32 = 3.14159265;
pub const TAU: f32 = 6.2831853;

#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct V3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

pub const fn v3(x: f32, y: f32, z: f32) -> V3 {
    V3 { x, y, z }
}

impl V3 {
    pub const ZERO: V3 = v3(0.0, 0.0, 0.0);
    pub fn dot(self, o: V3) -> f32 {
        self.x * o.x + self.y * o.y + self.z * o.z
    }
    pub fn cross(self, o: V3) -> V3 {
        v3(self.y * o.z - self.z * o.y, self.z * o.x - self.x * o.z, self.x * o.y - self.y * o.x)
    }
    pub fn len2(self) -> f32 {
        self.dot(self)
    }
    pub fn len(self) -> f32 {
        sqrt(self.len2())
    }
    pub fn norm(self) -> V3 {
        let l = self.len();
        if l < 1e-9 {
            v3(0.0, 0.0, 1.0)
        } else {
            self * (1.0 / l)
        }
    }
    pub fn lerp(self, o: V3, t: f32) -> V3 {
        self + (o - self) * t
    }
}
impl Add for V3 {
    type Output = V3;
    fn add(self, o: V3) -> V3 {
        v3(self.x + o.x, self.y + o.y, self.z + o.z)
    }
}
impl Sub for V3 {
    type Output = V3;
    fn sub(self, o: V3) -> V3 {
        v3(self.x - o.x, self.y - o.y, self.z - o.z)
    }
}
impl Mul<f32> for V3 {
    type Output = V3;
    fn mul(self, s: f32) -> V3 {
        v3(self.x * s, self.y * s, self.z * s)
    }
}
impl Neg for V3 {
    type Output = V3;
    fn neg(self) -> V3 {
        v3(-self.x, -self.y, -self.z)
    }
}
impl AddAssign for V3 {
    fn add_assign(&mut self, o: V3) {
        *self = *self + o;
    }
}

#[inline]
pub fn sqrt(x: f32) -> f32 {
    if x <= 0.0 {
        return 0.0;
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use core::arch::x86_64::*;
        _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(x)))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let mut y = f32::from_bits((x.to_bits() >> 1) + 0x1fbd_1df5);
        y = 0.5 * (y + x / y);
        y = 0.5 * (y + x / y);
        y = 0.5 * (y + x / y);
        y
    }
}

#[inline]
pub fn abs(x: f32) -> f32 {
    f32::from_bits(x.to_bits() & 0x7fff_ffff)
}
#[inline]
pub fn floor(x: f32) -> f32 {
    let i = x as i32 as f32;
    if i > x {
        i - 1.0
    } else {
        i
    }
}
pub fn fract(x: f32) -> f32 {
    x - floor(x)
}
#[inline]
pub fn clamp(x: f32, a: f32, b: f32) -> f32 {
    if x < a {
        a
    } else if x > b {
        b
    } else {
        x
    }
}
pub fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}
pub fn smoothstep(a: f32, b: f32, x: f32) -> f32 {
    let t = clamp((x - a) / (b - a), 0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}
#[inline]
pub fn min(a: f32, b: f32) -> f32 {
    if a < b {
        a
    } else {
        b
    }
}
#[inline]
pub fn max(a: f32, b: f32) -> f32 {
    if a > b {
        a
    } else {
        b
    }
}

/// sin for any finite argument; error below 1e-4.
pub fn sin(x: f32) -> f32 {
    let mut x = x - TAU * floor(x / TAU + 0.5); // [-pi, pi]
    if x > PI / 2.0 {
        x = PI - x;
    } else if x < -PI / 2.0 {
        x = -PI - x;
    }
    let x2 = x * x;
    x * (1.0 - x2 * (1.0 / 6.0 - x2 * (1.0 / 120.0 - x2 * (1.0 / 5040.0 - x2 * (1.0 / 362880.0)))))
}
pub fn cos(x: f32) -> f32 {
    sin(x + PI / 2.0)
}
/// Angle of (x, y) in -pi..pi; error about 1e-4.
pub fn atan2(y: f32, x: f32) -> f32 {
    let ax = abs(x);
    let ay = abs(y);
    let mx = max(ax, ay);
    if mx < 1e-20 {
        return 0.0;
    }
    let a = min(ax, ay) / mx;
    let s = a * a;
    let mut r = ((-0.0464964749 * s + 0.15931422) * s - 0.327622764) * s * a + a;
    if ay > ax {
        r = PI / 2.0 - r;
    }
    if x < 0.0 {
        r = PI - r;
    }
    if y < 0.0 {
        -r
    } else {
        r
    }
}
pub fn acos(x: f32) -> f32 {
    let x = clamp(x, -1.0, 1.0);
    atan2(sqrt(1.0 - x * x), x)
}
/// exp(-x) for x >= 0, small error, enough for falloff curves.
pub fn exp_neg(x: f32) -> f32 {
    if x > 16.0 {
        return 0.0;
    }
    let h = x * 0.25;
    let e = 1.0 / (1.0 + h + h * h * 0.5 + h * h * h / 6.0 + h * h * h * h / 24.0);
    let e2 = e * e;
    e2 * e2
}
/// x^p for x >= 0 via repeated squaring of an integer power.
pub fn powi(mut b: f32, mut e: u32) -> f32 {
    let mut r = 1.0;
    while e > 0 {
        if e & 1 == 1 {
            r *= b;
        }
        b *= b;
        e >>= 1;
    }
    r
}

/// Orthonormal frame: right, up, forward.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Orient {
    pub r: V3,
    pub u: V3,
    pub f: V3,
}

impl Orient {
    pub const ID: Orient = Orient { r: v3(1.0, 0.0, 0.0), u: v3(0.0, 1.0, 0.0), f: v3(0.0, 0.0, 1.0) };

    /// Frame looking along `fwd` with `up_hint` as approximate up.
    pub fn look(fwd: V3, up_hint: V3) -> Orient {
        let f = fwd.norm();
        let mut r = up_hint.cross(f);
        if r.len2() < 1e-8 {
            r = v3(1.0, 0.0, 0.0).cross(f);
            if r.len2() < 1e-8 {
                r = v3(0.0, 0.0, 1.0).cross(f);
            }
        }
        let r = r.norm();
        let u = f.cross(r);
        Orient { r, u, f }
    }
    /// Right wing down for positive angle.
    pub fn roll(&mut self, a: f32) {
        let (s, c) = (sin(a), cos(a));
        let r = self.r * c - self.u * s;
        let u = self.u * c + self.r * s;
        self.r = r;
        self.u = u;
    }
    /// Nose up for positive angle.
    pub fn pitch(&mut self, a: f32) {
        let (s, c) = (sin(a), cos(a));
        let f = self.f * c + self.u * s;
        let u = self.u * c - self.f * s;
        self.f = f;
        self.u = u;
    }
    pub fn rotate_axis(&mut self, axis: V3, a: f32) {
        let (s, c) = (sin(a), cos(a));
        let rot = |v: V3| v * c + axis.cross(v) * s + axis * (axis.dot(v) * (1.0 - c));
        self.r = rot(self.r);
        self.u = rot(self.u);
        self.f = rot(self.f);
    }
    pub fn orthonormalize(&mut self) {
        self.f = self.f.norm();
        let mut r = self.r - self.f * self.f.dot(self.r);
        if r.len2() < 1e-8 {
            r = self.u.cross(self.f);
        }
        self.r = r.norm();
        self.u = self.f.cross(self.r);
    }
    /// World vector to local components (x right, y up, z forward).
    #[inline]
    pub fn to_local(&self, v: V3) -> V3 {
        v3(v.dot(self.r), v.dot(self.u), v.dot(self.f))
    }
    #[inline]
    pub fn to_world(&self, v: V3) -> V3 {
        self.r * v.x + self.u * v.y + self.f * v.z
    }
    /// Turn the nose towards `dir` by at most `max_angle`; returns the remaining angle.
    pub fn turn_towards(&mut self, dir: V3, max_angle: f32) -> f32 {
        let d = dir.norm();
        let c = clamp(self.f.dot(d), -1.0, 1.0);
        let ang = acos(c);
        if ang < 1e-4 {
            return 0.0;
        }
        let mut axis = self.f.cross(d);
        if axis.len2() < 1e-10 {
            axis = self.u;
        }
        let axis = axis.norm();
        let step = min(ang, max_angle);
        self.rotate_axis(axis, step);
        self.orthonormalize();
        ang - step
    }
}

/// Deterministic generator (splitmix64 stream).
#[derive(Clone, Copy, Debug)]
pub struct Rng(pub u64);

pub fn mix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(mix64(seed ^ 0xD1B5_4A32_D192_ED03))
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        mix64(self.0.wrapping_sub(0x9E37_79B9_7F4A_7C15))
    }
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    /// 0..n
    pub fn below(&mut self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            ((self.next_u32() as u64 * n as u64) >> 32) as u32
        }
    }
    pub fn range(&mut self, a: i32, b: i32) -> i32 {
        a + self.below((b - a + 1) as u32) as i32
    }
    /// [0, 1)
    pub fn f(&mut self) -> f32 {
        (self.next_u32() >> 8) as f32 * (1.0 / 16777216.0)
    }
    pub fn fr(&mut self, a: f32, b: f32) -> f32 {
        a + (b - a) * self.f()
    }
    pub fn chance(&mut self, p: f32) -> bool {
        self.f() < p
    }
    pub fn unit(&mut self) -> V3 {
        loop {
            let v = v3(self.fr(-1.0, 1.0), self.fr(-1.0, 1.0), self.fr(-1.0, 1.0));
            let l = v.len2();
            if l > 0.01 && l <= 1.0 {
                return v * (1.0 / sqrt(l));
            }
        }
    }
}

fn hash3(x: i32, y: i32, z: i32, seed: u32) -> f32 {
    let mut h = (x as u32).wrapping_mul(0x8da6b343)
        ^ (y as u32).wrapping_mul(0xd8163841)
        ^ (z as u32).wrapping_mul(0xcb1ab31f)
        ^ seed.wrapping_mul(0x9e3779b9);
    h ^= h >> 15;
    h = h.wrapping_mul(0x2c1b3c6d);
    h ^= h >> 12;
    h = h.wrapping_mul(0x297a2d39);
    h ^= h >> 15;
    (h >> 8) as f32 * (1.0 / 16777216.0)
}

pub fn noise3(p: V3, seed: u32) -> f32 {
    let (fx, fy, fz) = (floor(p.x), floor(p.y), floor(p.z));
    let (ix, iy, iz) = (fx as i32, fy as i32, fz as i32);
    let (tx, ty, tz) = (p.x - fx, p.y - fy, p.z - fz);
    let sm = |t: f32| t * t * (3.0 - 2.0 * t);
    let (ux, uy, uz) = (sm(tx), sm(ty), sm(tz));
    let h = |dx, dy, dz| hash3(ix + dx, iy + dy, iz + dz, seed);
    let x00 = lerp(h(0, 0, 0), h(1, 0, 0), ux);
    let x10 = lerp(h(0, 1, 0), h(1, 1, 0), ux);
    let x01 = lerp(h(0, 0, 1), h(1, 0, 1), ux);
    let x11 = lerp(h(0, 1, 1), h(1, 1, 1), ux);
    lerp(lerp(x00, x10, uy), lerp(x01, x11, uy), uz)
}

pub fn fbm3(p: V3, octaves: u32, seed: u32) -> f32 {
    let mut a = 0.5;
    let mut f = 1.0;
    let mut sum = 0.0;
    let mut norm = 0.0;
    for o in 0..octaves {
        sum += a * noise3(p * f, seed.wrapping_add(o * 101));
        norm += a;
        a *= 0.5;
        f *= 2.03;
    }
    sum / norm
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trig_accuracy() {
        let mut x = -10.0f32;
        while x < 10.0 {
            assert!(abs(sin(x) - (x as f64).sin() as f32) < 2e-4, "sin {}", x);
            assert!(abs(cos(x) - (x as f64).cos() as f32) < 2e-4);
            x += 0.037;
        }
        assert!(abs(atan2(1.0, -2.0) - (1.0f64).atan2(-2.0) as f32) < 2e-4);
        assert!(abs(sqrt(2.0) - 1.4142135) < 1e-5);
        assert!(abs(acos(0.3) - (0.3f64).acos() as f32) < 5e-4);
    }
    #[test]
    fn orient_stays_orthonormal() {
        let mut o = Orient::ID;
        for i in 0..2000 {
            o.roll(0.013);
            o.pitch(0.021 * if i % 3 == 0 { 1.0 } else { -0.5 });
            if i % 100 == 0 {
                o.orthonormalize();
            }
        }
        assert!(abs(o.r.dot(o.f)) < 1e-2 && abs(o.f.len() - 1.0) < 1e-2);
    }
}
