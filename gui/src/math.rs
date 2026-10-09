// SPDX-License-Identifier: AGPL-3.0-only
//! Float helpers for `no_std` (core has no f32::sqrt/floor without std).

#[inline(always)]
pub fn sqrt(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use core::arch::x86_64::*;
        _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(x)))
    }
    #[cfg(not(target_arch = "x86_64"))]
    { libm::sqrtf(x) }
}

#[inline(always)]
pub fn floor(x: f32) -> f32 {
    let t = x as i32 as f32;
    if t > x { t - 1.0 } else { t }
}

#[inline(always)]
pub fn round(x: f32) -> i32 { floor(x + 0.5) as i32 }

#[inline(always)]
pub fn ceil(x: f32) -> i32 { -floor(-x) as i32 }

#[inline(always)]
pub fn clamp01(x: f32) -> f32 {
    if x < 0.0 { 0.0 } else if x > 1.0 { 1.0 } else { x }
}

pub fn powf(x: f32, y: f32) -> f32 { libm::powf(x, y) }

/// Cubic ease-out, t in 0..=1.
pub fn ease_out(t: f32) -> f32 {
    let t = clamp01(t);
    let u = 1.0 - t;
    1.0 - u * u * u
}
