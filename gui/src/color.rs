// SPDX-License-Identifier: AGPL-3.0-only
//! Colours.
//!
//! [`Color`] is a *straight* (non-premultiplied) 0xAARRGGBB value; that is what
//! the theme and widget code talk in.  Surfaces store *premultiplied* ARGB8888
//! (see `surface.rs`), which makes compositing a single multiply-add.

/// Straight-alpha colour, 0xAARRGGBB.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Color(pub u32);

impl Color {
    pub const TRANSPARENT: Color = Color(0);
    pub const BLACK: Color = Color(0xFF00_0000);
    pub const WHITE: Color = Color(0xFFFF_FFFF);

    /// Opaque colour from 0xRRGGBB.
    pub const fn hex(rgb: u32) -> Color { Color(0xFF00_0000 | (rgb & 0x00FF_FFFF)) }
    pub const fn rgb(r: u8, g: u8, b: u8) -> Color { Color(0xFF00_0000 | (r as u32) << 16 | (g as u32) << 8 | b as u32) }
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Color {
        Color((a as u32) << 24 | (r as u32) << 16 | (g as u32) << 8 | b as u32)
    }
    /// White with the given alpha (0..255): the usual "hairline on dark" colour.
    pub const fn white_a(a: u8) -> Color { Color((a as u32) << 24 | 0x00FF_FFFF) }
    pub const fn black_a(a: u8) -> Color { Color((a as u32) << 24) }

    #[inline] pub const fn a(self) -> u8 { (self.0 >> 24) as u8 }
    #[inline] pub const fn r(self) -> u8 { (self.0 >> 16) as u8 }
    #[inline] pub const fn g(self) -> u8 { (self.0 >> 8) as u8 }
    #[inline] pub const fn b(self) -> u8 { self.0 as u8 }

    pub const fn with_alpha(self, a: u8) -> Color { Color((self.0 & 0x00FF_FFFF) | (a as u32) << 24) }

    /// Multiply the alpha by `f` (0..255).
    pub const fn fade(self, f: u8) -> Color {
        let a = (self.a() as u32 * f as u32 + 127) / 255;
        self.with_alpha(a as u8)
    }

    /// Premultiplied ARGB8888 pixel value.
    #[inline]
    pub const fn premul(self) -> u32 {
        let a = self.0 >> 24;
        if a == 255 { return self.0; }
        if a == 0 { return 0; }
        let r = (((self.0 >> 16) & 0xFF) * a + 127) / 255;
        let g = (((self.0 >> 8) & 0xFF) * a + 127) / 255;
        let b = ((self.0 & 0xFF) * a + 127) / 255;
        a << 24 | r << 16 | g << 8 | b
    }

    /// Linear interpolation between two colours, t in 0..=256.
    pub fn mix(self, o: Color, t: u32) -> Color {
        let t = t.min(256);
        let f = |a: u8, b: u8| -> u32 { ((a as u32 * (256 - t) + b as u32 * t) >> 8) & 0xFF };
        Color(f(self.a(), o.a()) << 24 | f(self.r(), o.r()) << 16 | f(self.g(), o.g()) << 8 | f(self.b(), o.b()))
    }

    /// Flatten this colour over an opaque background (result is opaque).
    pub fn over(self, bg: Color) -> Color {
        let a = self.a() as u32;
        let f = |s: u8, d: u8| -> u32 { (s as u32 * a + d as u32 * (255 - a) + 127) / 255 };
        Color(0xFF00_0000 | f(self.r(), bg.r()) << 16 | f(self.g(), bg.g()) << 8 | f(self.b(), bg.b()))
    }

    /// WCAG relative luminance, 0..1 (used by tests and the theme contrast check).
    pub fn luminance(self) -> f32 {
        fn lin(c: u8) -> f32 {
            let c = c as f32 / 255.0;
            if c <= 0.04045 { c / 12.92 } else { libm::powf((c + 0.055) / 1.055, 2.4) }
        }
        0.2126 * lin(self.r()) + 0.7152 * lin(self.g()) + 0.0722 * lin(self.b())
    }

    /// WCAG contrast ratio between two opaque colours.
    pub fn contrast(self, o: Color) -> f32 {
        let (a, b) = (self.luminance(), o.luminance());
        let (hi, lo) = if a > b { (a, b) } else { (b, a) };
        (hi + 0.05) / (lo + 0.05)
    }
}
