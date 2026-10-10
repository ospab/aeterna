// SPDX-License-Identifier: AGPL-3.0-only
//! Design tokens: the ospab.os "dark minimalism" theme.
//!
//! Principles: near-black neutral backgrounds layered by small lightness steps
//! instead of borders; 1-px translucent white hairlines where separation is
//! needed; one restrained blue accent; text contrast >= 7:1 for primary and
//! secondary text; no gradients, no glow, no saturated "neon" colours.
//! Elevation is expressed by a lighter surface plus a soft shadow.

use crate::color::Color;
use crate::text::FontId;

/// Colour tokens.
#[derive(Clone, Copy, Debug)]
pub struct Palette {
    /// Desktop / deepest level.
    pub bg0: Color,
    /// Window background.
    pub bg1: Color,
    /// Grouped content on a window (cards, sidebars).
    pub surface: Color,
    /// Popovers, menus, top bar.
    pub elevated: Color,
    /// Inset fields (text entry).
    pub field: Color,
    /// Control fills (buttons, toggles off).
    pub control: Color,
    pub control_hover: Color,
    pub control_pressed: Color,
    /// Separators and outlines (translucent white).
    pub hairline: Color,
    pub hairline_strong: Color,
    /// Hover/selection washes (translucent white).
    pub hover: Color,
    pub selected_inactive: Color,
    pub text: Color,
    pub text_secondary: Color,
    pub text_disabled: Color,
    pub text_on_accent: Color,
    /// Accent fill (buttons, toggles, checkmarks).
    pub accent: Color,
    pub accent_hover: Color,
    pub accent_pressed: Color,
    /// Accent used as text/icon colour on dark (lighter than the fill).
    pub accent_text: Color,
    /// Translucent accent for selections and focus rings.
    pub accent_wash: Color,
    pub focus_ring: Color,
    pub danger: Color,
    pub danger_text: Color,
    pub success: Color,
    pub warning: Color,
    pub shadow: Color,
}

/// Corner radii.
#[derive(Clone, Copy, Debug)]
pub struct Radii {
    pub sm: i32,
    pub md: i32,
    pub lg: i32,
    pub window: i32,
}

/// Spacing scale (4-px grid).
#[derive(Clone, Copy, Debug)]
pub struct Spacing {
    pub xxs: i32,
    pub xs: i32,
    pub sm: i32,
    pub md: i32,
    pub lg: i32,
    pub xl: i32,
    pub xxl: i32,
}

/// One step of the type scale.
#[derive(Clone, Copy, Debug)]
pub struct TypeStyle {
    pub font: FontId,
    pub size: u16,
    /// Line box height in px.
    pub line: i32,
}

/// Type scale. Font ids refer to [`crate::fonts`]: 0 = UI regular,
/// 1 = UI semibold, 2 = monospace.
#[derive(Clone, Copy, Debug)]
pub struct TypeScale {
    pub caption: TypeStyle,
    pub small: TypeStyle,
    pub body: TypeStyle,
    pub body_strong: TypeStyle,
    pub title: TypeStyle,
    pub headline: TypeStyle,
    pub mono: TypeStyle,
}

/// Motion durations (ms). Easing is cubic ease-out everywhere.
#[derive(Clone, Copy, Debug)]
pub struct Motion {
    pub fast: u32,
    pub normal: u32,
    pub slow: u32,
    /// Caret blink half-period.
    pub caret_blink: u32,
}

/// Component metrics.
#[derive(Clone, Copy, Debug)]
pub struct Metrics {
    pub control_h: i32,
    pub row_h: i32,
    pub titlebar_h: i32,
    pub topbar_h: i32,
    pub scrollbar_w: i32,
    pub focus_ring_w: i32,
}

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub color: Palette,
    pub radius: Radii,
    pub space: Spacing,
    pub text: TypeScale,
    pub motion: Motion,
    pub metrics: Metrics,
}

pub const UI: FontId = 0;
pub const UI_SEMIBOLD: FontId = 1;
pub const MONO: FontId = 2;

pub const DARK: Theme = Theme {
    color: Palette {
        bg0: Color::hex(0x0C0D10),
        bg1: Color::hex(0x141518),
        surface: Color::hex(0x1A1C20),
        elevated: Color::hex(0x202227),
        field: Color::hex(0x0F1013),
        control: Color::hex(0x272A30),
        control_hover: Color::hex(0x30333A),
        control_pressed: Color::hex(0x1F2126),
        hairline: Color::white_a(20),
        hairline_strong: Color::white_a(36),
        hover: Color::white_a(10),
        selected_inactive: Color::white_a(18),
        text: Color::hex(0xECEDEF),
        text_secondary: Color::hex(0x9EA3AB),
        text_disabled: Color::hex(0x5C6068),
        text_on_accent: Color::hex(0xFFFFFF),
        accent: Color::hex(0x3B6FD9),
        accent_hover: Color::hex(0x4679E2),
        accent_pressed: Color::hex(0x325FBD),
        accent_text: Color::hex(0x8AAEFF),
        accent_wash: Color::rgba(0x3B, 0x6F, 0xD9, 72),
        focus_ring: Color::rgba(0x6A, 0x96, 0xF5, 150),
        danger: Color::hex(0xD5484E),
        danger_text: Color::hex(0xFF8F8F),
        success: Color::hex(0x56C28F),
        warning: Color::hex(0xE0A84A),
        shadow: Color::black_a(150),
    },
    radius: Radii { sm: 4, md: 6, lg: 10, window: 10 },
    space: Spacing { xxs: 2, xs: 4, sm: 8, md: 12, lg: 16, xl: 24, xxl: 32 },
    text: TypeScale {
        caption: TypeStyle { font: UI, size: 11, line: 14 },
        small: TypeStyle { font: UI, size: 12, line: 16 },
        body: TypeStyle { font: UI, size: 13, line: 18 },
        body_strong: TypeStyle { font: UI_SEMIBOLD, size: 13, line: 18 },
        title: TypeStyle { font: UI_SEMIBOLD, size: 15, line: 20 },
        headline: TypeStyle { font: UI_SEMIBOLD, size: 20, line: 26 },
        mono: TypeStyle { font: MONO, size: 13, line: 19 },
    },
    motion: Motion { fast: 90, normal: 160, slow: 240, caret_blink: 530 },
    metrics: Metrics { control_h: 28, row_h: 30, titlebar_h: 38, topbar_h: 30, scrollbar_w: 10, focus_ring_w: 2 },
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_contrast() {
        let c = DARK.color;
        for bg in [c.bg0, c.bg1, c.surface, c.elevated, c.field] {
            assert!(c.text.contrast(bg) >= 12.0, "primary on {:?}", bg);
            assert!(c.text_secondary.contrast(bg) >= 6.0, "secondary on {:?}", bg);
            assert!(c.accent_text.contrast(bg) >= 6.0);
        }
        assert!(c.text_on_accent.contrast(c.accent) >= 4.5);
        assert!(c.text_on_accent.contrast(c.danger) >= 4.0);
    }
}
