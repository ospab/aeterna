// SPDX-License-Identifier: AGPL-3.0-only
//! Menus / popovers: a floating list of commands.
//!
//! A [`Menu`] is self-contained (layout, paint, input) so it can live inside a
//! window's widget tree (context menus, drop-downs) or in the shell layer (the
//! launcher in the top bar).

use alloc::string::String;
use alloc::vec::Vec;

use crate::canvas::Canvas;
use crate::color::Color;
use crate::event::{Event, Key, MouseButton};
use crate::geom::Rect;
use crate::icons::{self, Icon};
use crate::shadow::{Shadow, ShadowCache};
use crate::text::TextEngine;
use crate::theme::Theme;

#[derive(Clone, Debug)]
pub struct MenuItem {
    pub label: String,
    pub shortcut: Option<String>,
    pub icon: Option<Icon>,
    pub enabled: bool,
    pub separator: bool,
    pub checked: bool,
}

impl MenuItem {
    pub fn new(label: &str) -> MenuItem {
        MenuItem { label: label.into(), shortcut: None, icon: None, enabled: true, separator: false, checked: false }
    }
    pub fn separator() -> MenuItem {
        MenuItem { label: String::new(), shortcut: None, icon: None, enabled: false, separator: true, checked: false }
    }
    pub fn shortcut(mut self, s: &str) -> Self { self.shortcut = Some(s.into()); self }
    pub fn icon(mut self, i: Icon) -> Self { self.icon = Some(i); self }
    pub fn disabled(mut self) -> Self { self.enabled = false; self }
    pub fn checked(mut self, c: bool) -> Self { self.checked = c; self }
}

/// Result of feeding an event to a menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuResult {
    /// Event consumed, menu stays open.
    None,
    /// An item was chosen; the menu should close.
    Chosen(usize),
    /// Dismissed (click outside, Escape).
    Dismissed,
}

const ROW_H: i32 = 28;
const SEP_H: i32 = 9;
const PAD: i32 = 5;

pub struct Menu {
    pub items: Vec<MenuItem>,
    pub rect: Rect,
    pub hover: Option<usize>,
    pressed_inside: bool,
}

impl Menu {
    /// Lay out a menu below `anchor` (or above it if it does not fit), kept
    /// inside `bounds`.
    pub fn new(items: Vec<MenuItem>, anchor: Rect, bounds: Rect, text: &mut TextEngine, theme: &Theme) -> Menu {
        let t = &theme.text;
        let mut w = 180;
        let mut h = 2 * PAD;
        let has_icons = items.iter().any(|i| i.icon.is_some() || i.checked);
        for it in &items {
            if it.separator { h += SEP_H; continue; }
            h += ROW_H;
            let mut iw = text.measure(t.body.font, t.body.size, &it.label) + 2 * 12;
            if has_icons { iw += 24; }
            if let Some(s) = &it.shortcut { iw += 32 + text.measure(t.body.font, t.body.size, s); }
            w = w.max(iw + 2 * PAD);
        }
        let mut x = anchor.x;
        let mut y = anchor.bottom() + 4;
        if y + h > bounds.bottom() { y = (anchor.y - 4 - h).max(bounds.y); }
        if x + w > bounds.right() { x = (bounds.right() - w).max(bounds.x); }
        Menu { items, rect: Rect::new(x, y, w, h), hover: None, pressed_inside: false }
    }

    /// Rect including the shadow (for damage).
    pub fn damage_rect(&self) -> Rect { self.rect.outset(24).offset(0, 6) }

    fn row_rects(&self) -> Vec<Rect> {
        let mut v = Vec::with_capacity(self.items.len());
        let mut y = self.rect.y + PAD;
        for it in &self.items {
            let h = if it.separator { SEP_H } else { ROW_H };
            v.push(Rect::new(self.rect.x + PAD, y, self.rect.w - 2 * PAD, h));
            y += h;
        }
        v
    }

    fn item_at(&self, x: i32, y: i32) -> Option<usize> {
        if !self.rect.contains(x, y) { return None; }
        self.row_rects().iter().position(|r| r.contains(x, y))
            .filter(|&i| !self.items[i].separator && self.items[i].enabled)
    }

    fn step(&self, from: Option<usize>, dir: i32) -> Option<usize> {
        let n = self.items.len() as i32;
        if n == 0 { return None; }
        let mut i = from.map_or(if dir > 0 { -1 } else { n }, |v| v as i32);
        for _ in 0..n {
            i += dir;
            if i < 0 || i >= n { return from; }
            let it = &self.items[i as usize];
            if !it.separator && it.enabled { return Some(i as usize); }
        }
        from
    }

    /// Handle an event (coordinates in the menu's coordinate space).
    /// Sets `*dirty` when the menu needs repainting.
    pub fn handle(&mut self, ev: &Event, dirty: &mut bool) -> MenuResult {
        match *ev {
            Event::PointerMove { x, y } => {
                let h = self.item_at(x, y);
                if h != self.hover { self.hover = h; *dirty = true; }
                MenuResult::None
            }
            Event::PointerDown { x, y, .. } => {
                if !self.rect.contains(x, y) { return MenuResult::Dismissed; }
                self.pressed_inside = true;
                MenuResult::None
            }
            Event::PointerUp { x, y, button: MouseButton::Left } => {
                match self.item_at(x, y) {
                    Some(i) => MenuResult::Chosen(i),
                    None => {
                        self.pressed_inside = false;
                        MenuResult::None
                    }
                }
            }
            Event::KeyDown { key, .. } => match key {
                Key::Escape => MenuResult::Dismissed,
                Key::Down | Key::Up => {
                    let h = self.step(self.hover, if key == Key::Down { 1 } else { -1 });
                    if h != self.hover { self.hover = h; *dirty = true; }
                    MenuResult::None
                }
                Key::Enter | Key::Char(' ') => match self.hover {
                    Some(i) => MenuResult::Chosen(i),
                    None => MenuResult::None,
                },
                _ => MenuResult::None,
            },
            _ => MenuResult::None,
        }
    }

    pub fn paint(&self, c: &mut Canvas, text: &mut TextEngine, theme: &Theme, shadows: &mut ShadowCache) {
        let col = &theme.color;
        let r = self.rect;
        let rad = theme.radius.lg - 2;
        shadows.draw(c, r, rad, &Shadow { dx: 0, dy: 8, blur: 20, spread: 0, color: Color::black_a(110) }, Some(r.inset(rad)));
        shadows.draw(c, r, rad, &Shadow { dx: 0, dy: 1, blur: 3, spread: 0, color: Color::black_a(90) }, Some(r.inset(rad)));
        c.fill_round_rect(r, rad, col.elevated);
        c.stroke_round_rect(r, rad, 1, col.hairline_strong);
        let has_icons = self.items.iter().any(|i| i.icon.is_some() || i.checked);
        let ts = theme.text.body;
        let lm = text.metrics(ts.font, ts.size);
        for (i, (it, rr)) in self.items.iter().zip(self.row_rects()).enumerate() {
            if it.separator {
                c.hline(rr.x + 8, rr.right() - 8, rr.y + SEP_H / 2, col.hairline);
                continue;
            }
            let hovered = self.hover == Some(i);
            if hovered {
                c.fill_round_rect(rr, theme.radius.md - 1, col.accent);
            }
            let fg = if !it.enabled { col.text_disabled } else if hovered { col.text_on_accent } else { col.text };
            let mut x = rr.x + 10;
            if has_icons {
                let ir = Rect::new(x, rr.y + (rr.h - 16) / 2, 16, 16);
                if it.checked { icons::draw(c, Icon::Check, ir, fg); }
                else if let Some(ic) = it.icon {
                    icons::draw(c, ic, ir, if hovered { fg } else if it.enabled { col.text_secondary } else { col.text_disabled });
                }
                x += 24;
            }
            let ty = rr.y + (rr.h - lm.height) / 2;
            text.draw(c, x, ty, ts.font, ts.size, fg, &it.label);
            if let Some(s) = &it.shortcut {
                let sw = text.measure(ts.font, ts.size, s);
                let sc = if hovered { col.text_on_accent.fade(200) } else { col.text_secondary };
                text.draw(c, rr.right() - 10 - sw, ty, ts.font, ts.size, sc, s);
            }
        }
    }
}
