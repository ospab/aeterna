// SPDX-License-Identifier: AGPL-3.0-only
//! A toolkit window: its own surface, client-side chrome and a widget tree.
//!
//! This is the client half of the future compositor protocol: the window
//! renders into its own premultiplied surface (later: a shared-memory buffer)
//! and reports damage in window coordinates.  The compositor only adds the
//! shadow and places the surface.
//!
//! Chrome: a 38-px title bar in the window's own colour (no separate band),
//! the title centred, and two small monochrome round controls on the left —
//! close and minimise — that show their glyph only when the pointer is near
//! them and turn red/grey on hover.  Focus is shown by a brighter hairline
//! border, a stronger shadow and primary-coloured title text.

use alloc::string::String;
use alloc::vec::Vec;

use crate::blend;
use crate::canvas::Canvas;
use crate::color::Color;
use crate::damage::Damage;
use crate::event::{CursorShape, Event, MouseButton};
use crate::geom::Rect;
use crate::icons::Icon;
use crate::math;
use crate::surface::Surface;
use crate::text::TextEngine;
use crate::theme::Theme;
use crate::ui::Ui;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chrome {
    Close,
    Minimize,
}

/// What the window asks its owner (the compositor) to do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowResponse {
    pub begin_drag: bool,
    pub close: bool,
    pub minimize: bool,
    pub consumed: bool,
}

pub struct Window {
    pub title: String,
    pub icon: Icon,
    /// Position and size on screen.
    pub rect: Rect,
    pub ui: Ui,
    pub surface: Surface,
    pub focused: bool,
    pub visible: bool,
    chrome_hover: Option<Chrome>,
    controls_hover: bool,
    chrome_pressed: Option<Chrome>,
    ui_capture: bool,
    damage: Damage,
    full: bool,
}

const CTRL_R: f32 = 6.0;

impl Window {
    pub fn new(title: &str, icon: Icon, rect: Rect, ui: Ui) -> Window {
        Window {
            title: title.into(), icon, rect, ui, surface: Surface::new(rect.w, rect.h),
            focused: false, visible: true, chrome_hover: None, controls_hover: false, chrome_pressed: None,
            ui_capture: false, damage: Damage::new(), full: true,
        }
    }

    pub fn local(&self) -> Rect { Rect::from_size(self.rect.w, self.rect.h) }

    fn titlebar(&self, theme: &Theme) -> Rect { Rect::new(0, 0, self.rect.w, theme.metrics.titlebar_h) }

    fn control_center(&self, which: Chrome, theme: &Theme) -> (f32, f32) {
        let cy = theme.metrics.titlebar_h as f32 / 2.0;
        match which {
            Chrome::Close => (20.0, cy),
            Chrome::Minimize => (40.0, cy),
        }
    }

    fn control_at(&self, x: i32, y: i32, theme: &Theme) -> Option<Chrome> {
        for w in [Chrome::Close, Chrome::Minimize] {
            let (cx, cy) = self.control_center(w, theme);
            let (dx, dy) = (x as f32 + 0.5 - cx, y as f32 + 0.5 - cy);
            if dx * dx + dy * dy <= 10.0 * 10.0 { return Some(w); }
        }
        None
    }

    fn controls_rect(&self, theme: &Theme) -> Rect { Rect::new(0, 0, 60, theme.metrics.titlebar_h) }

    /// Request a complete repaint (e.g. after a resize or theme change).
    pub fn invalidate_all(&mut self) { self.full = true; }

    fn invalidate_frame(&mut self, theme: &Theme) {
        let l = self.local();
        self.damage.add(self.titlebar(theme));
        self.damage.add(Rect::new(0, 0, 1, l.h));
        self.damage.add(Rect::new(l.w - 1, 0, 1, l.h));
        self.damage.add(Rect::new(0, l.h - 1, l.w, 1));
    }

    pub fn set_focused(&mut self, f: bool, text: &mut TextEngine, theme: &Theme) {
        if self.focused == f { return; }
        self.focused = f;
        self.invalidate_frame(theme);
        self.ui.handle(if f { &Event::FocusIn } else { &Event::FocusOut }, text, theme);
    }

    pub fn cursor_at(&self, x: i32, y: i32, theme: &Theme) -> CursorShape {
        if y < theme.metrics.titlebar_h { CursorShape::Arrow } else { self.ui.cursor_at(x, y) }
    }

    /// Feed an event in window-local coordinates.
    pub fn handle(&mut self, ev: &Event, text: &mut TextEngine, theme: &Theme) -> WindowResponse {
        let mut resp = WindowResponse { consumed: true, ..Default::default() };
        let th = theme.metrics.titlebar_h;
        if self.ui.menu_open() {
            self.ui.handle(ev, text, theme);
            return resp;
        }
        match *ev {
            Event::PointerMove { x, y } => {
                let h = if y < th { self.control_at(x, y, theme) } else { None };
                let near = y < th && self.controls_rect(theme).contains(x, y);
                if h != self.chrome_hover || near != self.controls_hover {
                    self.chrome_hover = h;
                    self.controls_hover = near;
                    let r = self.controls_rect(theme);
                    self.damage.add(r);
                }
                if self.ui_capture || y >= th { self.ui.handle(ev, text, theme); }
                else { self.ui.handle(&Event::PointerLeave, text, theme); }
            }
            Event::PointerDown { x, y, button } => {
                if y < th {
                    if let Some(c) = self.control_at(x, y, theme) {
                        self.chrome_pressed = Some(c);
                        let r = self.controls_rect(theme);
                        self.damage.add(r);
                    } else if button == MouseButton::Left {
                        resp.begin_drag = true;
                    }
                } else {
                    self.ui_capture = true;
                    self.ui.handle(ev, text, theme);
                }
            }
            Event::PointerUp { x, y, .. } => {
                if let Some(p) = self.chrome_pressed.take() {
                    let r = self.controls_rect(theme);
                    self.damage.add(r);
                    if y < th && self.control_at(x, y, theme) == Some(p) {
                        match p {
                            Chrome::Close => resp.close = true,
                            Chrome::Minimize => resp.minimize = true,
                        }
                    }
                }
                if self.ui_capture {
                    self.ui_capture = false;
                    self.ui.handle(ev, text, theme);
                }
            }
            Event::PointerLeave => {
                if self.chrome_hover.is_some() || self.controls_hover {
                    self.chrome_hover = None;
                    self.controls_hover = false;
                    let r = self.controls_rect(theme);
                    self.damage.add(r);
                }
                self.ui.handle(ev, text, theme);
            }
            _ => { resp.consumed = self.ui.handle(ev, text, theme); }
        }
        resp
    }

    pub fn tick(&mut self, now_ms: u64, theme: &Theme) { self.ui.tick(now_ms, theme); }

    /// Repaint damaged parts of the surface. Returns damage in window coords.
    pub fn render(&mut self, text: &mut TextEngine, theme: &Theme) -> Vec<Rect> {
        let local = self.local();
        if self.surface.width != local.w || self.surface.height != local.h {
            self.surface.resize(local.w, local.h);
            self.full = true;
        }
        if self.full {
            self.full = false;
            let th = theme.metrics.titlebar_h;
            self.ui.layout(text, theme, Rect::new(0, th, local.w, local.h - th));
            self.damage.clear();
            self.damage.add(local);
        }
        let ui_rects = self.ui.take_damage(text, theme);
        self.damage.add_all(&ui_rects);
        self.damage.clip(local);
        let rects = self.damage.take();
        for r in &rects {
            self.paint_rect(*r, text, theme);
        }
        rects
    }

    fn paint_rect(&mut self, r: Rect, text: &mut TextEngine, theme: &Theme) {
        let tb = self.titlebar(theme);
        let local = self.local();
        let rad = theme.radius.window;
        {
            let mut c = Canvas::new(self.surface.view_mut());
            c.set_clip(r);
            if tb.intersects(&r) {
                Self::paint_chrome(&mut c, text, theme, &self.title, tb, self.focused, self.chrome_hover, self.controls_hover, self.chrome_pressed);
            }
            let ur = r.intersect(&self.ui.rect());
            if !ur.is_empty() { self.ui.paint_rect(&mut c, text, theme, ur); }
            c.set_clip(r);
            let border = if self.focused { Color::white_a(30) } else { Color::white_a(18) };
            c.stroke_round_rect(local, rad, 1, border);
        }
        self.mask_corners(r, rad);
    }

    #[allow(clippy::too_many_arguments)]
    fn paint_chrome(c: &mut Canvas, text: &mut TextEngine, theme: &Theme, title: &str, tb: Rect, focused: bool,
                    hover: Option<Chrome>, near: bool, pressed: Option<Chrome>) {
        let col = &theme.color;
        c.fill_rect(tb, col.bg1);
        c.hline(tb.x, tb.right(), tb.bottom() - 1, col.hairline);
        let st = theme.text.body_strong;
        let lm = text.metrics(st.font, st.size);
        let max_w = tb.w - 2 * 72;
        let tw = text.measure(st.font, st.size, title).min(max_w);
        let fg = if focused { col.text } else { col.text_disabled };
        text.draw_ellipsis(c, tb.x + (tb.w - tw) / 2, tb.y + (tb.h - lm.height) / 2, max_w, st.font, st.size, fg, title);
        let cy = tb.h as f32 / 2.0;
        for (w, cx) in [(Chrome::Close, 20.0f32), (Chrome::Minimize, 40.0)] {
            let hovered = hover == Some(w);
            let down = pressed == Some(w);
            let fill = match (w, hovered, down) {
                (Chrome::Close, true, false) => col.danger,
                (Chrome::Close, _, true) => col.danger.mix(Color::BLACK, 50),
                (Chrome::Minimize, true, false) => Color::white_a(80),
                (Chrome::Minimize, _, true) => Color::white_a(50),
                _ if focused => Color::white_a(44),
                _ => Color::TRANSPARENT,
            };
            if fill.a() > 0 { c.fill_circle(cx, cy, CTRL_R, fill); }
            else { c.stroke_circle(cx, cy, CTRL_R, 1.0, Color::white_a(34)); }
            if near || hovered {
                let g = if hovered && w == Chrome::Close { Color::WHITE } else { Color::hex(0x1A1B1E) };
                match w {
                    Chrome::Close => {
                        c.line(cx - 2.3, cy - 2.3, cx + 2.3, cy + 2.3, 1.3, g);
                        c.line(cx + 2.3, cy - 2.3, cx - 2.3, cy + 2.3, 1.3, g);
                    }
                    Chrome::Minimize => c.line(cx - 2.8, cy, cx + 2.8, cy, 1.3, g),
                }
            }
        }
    }

    /// Re-apply the rounded window shape to freshly painted pixels in `r`.
    fn mask_corners(&mut self, r: Rect, rad: i32) {
        let (w, h) = (self.surface.width, self.surface.height);
        let rf = rad as f32;
        let corners = [
            (Rect::new(0, 0, rad, rad), rf, rf),
            (Rect::new(w - rad, 0, rad, rad), w as f32 - rf, rf),
            (Rect::new(0, h - rad, rad, rad), rf, h as f32 - rf),
            (Rect::new(w - rad, h - rad, rad, rad), w as f32 - rf, h as f32 - rf),
        ];
        let stride = self.surface.stride;
        for (sq, cx, cy) in corners {
            let d = sq.intersect(&r);
            for y in d.y..d.bottom() {
                for x in d.x..d.right() {
                    let (dx, dy) = (x as f32 + 0.5 - cx, y as f32 + 0.5 - cy);
                    let cov = math::clamp01(rf - math::sqrt(dx * dx + dy * dy) + 0.5);
                    let i = y as usize * stride + x as usize;
                    self.surface.data[i] = blend::scale(self.surface.data[i], (cov * 255.0 + 0.5) as u32);
                }
            }
        }
    }
}
