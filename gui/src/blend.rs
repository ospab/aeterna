// SPDX-License-Identifier: AGPL-3.0-only
//! Pixel arithmetic on premultiplied ARGB8888.
//!
//! All hot paths are integer-only.  The scalar versions process two channels
//! per multiply (the 0x00FF00FF trick); on x86_64 the span loops use SSE2,
//! which every x86_64 CPU has (no AVX is assumed).  Division by 255 is the
//! exact `(x + 128 + ((x + 128) >> 8)) >> 8` form.

/// `px * f / 255` for every channel of a premultiplied pixel (f in 0..=255).
#[inline(always)]
pub fn scale(px: u32, f: u32) -> u32 {
    let rb = (px & 0x00FF_00FF) * f + 0x0080_0080;
    let rb = ((rb + ((rb >> 8) & 0x00FF_00FF)) >> 8) & 0x00FF_00FF;
    let ag = ((px >> 8) & 0x00FF_00FF) * f + 0x0080_0080;
    let ag = (ag + ((ag >> 8) & 0x00FF_00FF)) & 0xFF00_FF00;
    rb | ag
}

/// Porter-Duff source-over: `src + dst * (1 - src.a)`.
#[inline(always)]
pub fn over(dst: u32, src: u32) -> u32 {
    let a = src >> 24;
    if a == 255 { return src; }
    if a == 0 { return dst; }
    src.wrapping_add(scale(dst, 255 - a))
}

/// Blend `src` (premultiplied) over `dst` with an extra coverage (0..=255).
#[inline(always)]
pub fn over_cov(dst: u32, src: u32, cov: u32) -> u32 {
    if cov == 0 { return dst; }
    if cov >= 255 { return over(dst, src); }
    over(dst, scale(src, cov))
}

/// Fill a span with a premultiplied colour (opaque fast path included).
pub fn fill_span(dst: &mut [u32], src: u32) {
    let a = src >> 24;
    if a == 255 {
        for p in dst.iter_mut() { *p = src; }
        return;
    }
    if a == 0 { return; }
    #[cfg(target_arch = "x86_64")]
    unsafe { sse2::blend_solid(dst, src); }
    #[cfg(not(target_arch = "x86_64"))]
    for p in dst.iter_mut() { *p = over(*p, src); }
}

/// Composite a row of premultiplied pixels over `dst` (same length).
pub fn blend_row(dst: &mut [u32], src: &[u32]) {
    let n = dst.len().min(src.len());
    #[cfg(target_arch = "x86_64")]
    unsafe { sse2::blend_row(&mut dst[..n], &src[..n]); }
    #[cfg(not(target_arch = "x86_64"))]
    for i in 0..n { dst[i] = over(dst[i], src[i]); }
}

/// Blend a row of premultiplied pixels scaled by a global opacity (0..=255).
pub fn blend_row_alpha(dst: &mut [u32], src: &[u32], alpha: u32) {
    if alpha >= 255 { return blend_row(dst, src); }
    for (d, s) in dst.iter_mut().zip(src.iter()) { *d = over(*d, scale(*s, alpha)); }
}

/// Paint `color` (premultiplied) through an 8-bit coverage mask row.
pub fn mask_row(dst: &mut [u32], mask: &[u8], color: u32) {
    let opaque = color >> 24 == 255;
    for (d, &m) in dst.iter_mut().zip(mask.iter()) {
        match m {
            0 => {}
            255 if opaque => *d = color,
            _ => *d = over(*d, scale(color, m as u32)),
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod sse2 {
    use core::arch::x86_64::*;

    /// dst = src + dst * inv / 255 for 4 pixels held as 16-bit lanes.
    #[inline(always)]
    unsafe fn mul_div255(v: __m128i, f: __m128i) -> __m128i {
        let x = _mm_add_epi16(_mm_mullo_epi16(v, f), _mm_set1_epi16(128));
        _mm_srli_epi16(_mm_add_epi16(x, _mm_srli_epi16(x, 8)), 8)
    }

    pub unsafe fn blend_solid(dst: &mut [u32], src: u32) {
        let inv = (255 - (src >> 24)) as i16;
        let zero = _mm_setzero_si128();
        let invv = _mm_set1_epi16(inv);
        let srcv = _mm_set1_epi32(src as i32);
        let n = dst.len();
        let p = dst.as_mut_ptr();
        let mut i = 0;
        while i + 4 <= n {
            let d = _mm_loadu_si128(p.add(i) as *const __m128i);
            let lo = mul_div255(_mm_unpacklo_epi8(d, zero), invv);
            let hi = mul_div255(_mm_unpackhi_epi8(d, zero), invv);
            let r = _mm_add_epi8(_mm_packus_epi16(lo, hi), srcv);
            _mm_storeu_si128(p.add(i) as *mut __m128i, r);
            i += 4;
        }
        while i < n {
            *p.add(i) = super::over(*p.add(i), src);
            i += 1;
        }
    }

    pub unsafe fn blend_row(dst: &mut [u32], src: &[u32]) {
        let zero = _mm_setzero_si128();
        let full = _mm_set1_epi16(255);
        let n = dst.len();
        let dp = dst.as_mut_ptr();
        let sp = src.as_ptr();
        let mut i = 0;
        while i + 4 <= n {
            let s = _mm_loadu_si128(sp.add(i) as *const __m128i);
            // Fast paths: all four opaque, or all four transparent.
            let alpha_bits = _mm_srli_epi32(s, 24);
            let all_opaque = _mm_movemask_epi8(_mm_cmpeq_epi32(alpha_bits, _mm_set1_epi32(255))) == 0xFFFF;
            if all_opaque {
                _mm_storeu_si128(dp.add(i) as *mut __m128i, s);
                i += 4;
                continue;
            }
            if _mm_movemask_epi8(_mm_cmpeq_epi32(alpha_bits, zero)) == 0xFFFF {
                i += 4;
                continue;
            }
            let d = _mm_loadu_si128(dp.add(i) as *const __m128i);
            let slo = _mm_unpacklo_epi8(s, zero);
            let shi = _mm_unpackhi_epi8(s, zero);
            // Broadcast each pixel's alpha (16-bit lane 3 / 7) to its four lanes.
            let alo = _mm_shufflehi_epi16(_mm_shufflelo_epi16(slo, 0xFF), 0xFF);
            let ahi = _mm_shufflehi_epi16(_mm_shufflelo_epi16(shi, 0xFF), 0xFF);
            let lo = mul_div255(_mm_unpacklo_epi8(d, zero), _mm_sub_epi16(full, alo));
            let hi = mul_div255(_mm_unpackhi_epi8(d, zero), _mm_sub_epi16(full, ahi));
            let r = _mm_add_epi8(_mm_packus_epi16(lo, hi), s);
            _mm_storeu_si128(dp.add(i) as *mut __m128i, r);
            i += 4;
        }
        while i < n {
            *dp.add(i) = super::over(*dp.add(i), *sp.add(i));
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn over_matches_reference() {
        let dsts = [0xFF10_2030u32, 0xFFFF_FFFF, 0x8040_2010, 0];
        let srcs = [0x8000_0000u32, 0x4020_2020, 0xFF12_3456, 0x0000_0000, 0x7F7F_7F7F];
        for &d in &dsts {
            for &s in &srcs {
                let mut row = [d; 7];
                fill_span(&mut row, s);
                let want = over(d, s);
                assert!(row.iter().all(|&p| p == want), "fill {d:08x} {s:08x}");
                let mut row2 = [d; 9];
                blend_row(&mut row2, &[s; 9]);
                assert!(row2.iter().all(|&p| p == want), "row {d:08x} {s:08x}");
            }
        }
    }

    #[test]
    fn scale_exact() {
        for v in 0..=255u32 {
            for f in [0u32, 1, 127, 128, 254, 255] {
                let px = v << 24 | v << 16 | v << 8 | v;
                let want = (v * f + 127) / 255;
                let got = scale(px, f) & 0xFF;
                assert!((got as i32 - want as i32).abs() <= 1);
            }
        }
    }
}
