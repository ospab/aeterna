// SPDX-License-Identifier: AGPL-3.0-only
//! In-process compositor prototype ("shell layer").
//!
//! Stacks [`Window`] surfaces over the desktop background with soft shadows,
//! draws the top bar, the launcher menu and the pointer into a back buffer,
//! and reports which screen rectangles changed.  The caller presents those
//! rectangles (copy to the framebuffer, write a PNG, ...).
//!
//! Today this runs inside one program; once IPC channels and shared memory
//! exist it becomes the ring-3 compositor server and every `Window` becomes a
//! client-owned shared surface (see docs/gui.md).

use alloc::string::String;
use alloc::vec::Vec;

use crate::canvas::Canvas;
use crate::color::Color;
use crate::cursor;
use crate::damage::Damage;
use crate::event::{CursorShape, Event, MouseButton};
use crate::geom::{Point, Rect};
use crate::icons::{self, Icon};
use crate::menu::{Menu, MenuItem, MenuResult};
use crate::shadow::{Shadow, ShadowCache};
use crate::surface::Surface;
use crate::text::TextEngine;
use crate::theme::Theme;
use crate::window::Window;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopItem {
    Launcher,
    Chip(usize),
    Status,
}

/// Something the shell layer reports to its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellAction {
    /// Launcher menu item chosen.
    Launch(usize),
}

pub struct Desktop {
    pub width: i32,
    pub height: i32,
    /// Composited frame (premultiplied, fully opaque).
    pub back: Surface,
    pub windows: Vec<Window>,
    /// Stacking order: indices into `windows`, last = topmost.
    pub order: Vec<usize>,
    shadows: ShadowCache,
    pub cursor: Point,
    pub cursor_shape: CursorShape,
    pub show_cursor: bool,
    drag: Option<(usize, i32, i32)>,
    capture: Option<usize>,
    hover_win: Option<usize>,
    top_hover: Option<TopItem>,
    launcher: Option<Menu>,
    pub launcher_items: Vec<MenuItem>,
    pub clock: String,
    pub actions: Vec<ShellAction>,
    damage: Damage,
}

impl Desktop {
    pub fn new(width: i32, height: i32) -> Desktop {
        let mut d = Desktop {
            width, height, back: Surface::new(width, height), windows: Vec::new(), order: Vec::new(),
            shadows: ShadowCache::new(), cursor: Point::new(width / 2, height / 2), cursor_shape: CursorShape::Arrow,
            show_cursor: true, drag: None, capture: None, hover_win: None, top_hover: None, launcher: None,
            launcher_items: Vec::new(), clock: String::new(), actions: Vec::new(), damage: Damage::new(),
        };
        d.damage.max_rects = 24;
        d.damage.add(Rect::from_size(width, height));
        d
    }

    pub fn screen(&self) -> Rect { Rect::from_size(self.width, self.height) }

    pub fn add_window(&mut self, w: Window) -> usize {
        self.windows.push(w);
        let i = self.windows.len() - 1;
        self.order.push(i);
        self.damage_window(i);
        i
    }

    pub fn invalidate_all(&mut self) { self.damage.add(self.screen()); }

    /// The area a window affects on screen, shadow included.
    fn window_extent(&self, i: usize) -> Rect { self.windows[i].rect.outset(36).offset(0, 10) }

    fn damage_window(&mut self, i: usize) {
        let r = self.window_extent(i);
        self.damage.add(r);
    }

    fn topbar_rect(&self, theme: &Theme) -> Rect { Rect::new(0, 0, self.width, theme.metrics.topbar_h) }

    pub fn focused(&self) -> Option<usize> {
        self.order.iter().rev().copied().find(|&i| self.windows[i].visible && self.windows[i].focused)
    }

    /// Raise and focus window `i` (showing it if minimised).
    pub fn focus_window(&mut self, i: usize, text: &mut TextEngine, theme: &Theme) {
        for j in 0..self.windows.len() {
            if j != i { self.windows[j].set_focused(false, text, theme); }
        }
        if !self.windows[i].visible { self.windows[i].visible = true; }
        self.windows[i].set_focused(true, text, theme);
        if self.order.last() != Some(&i) {
            self.order.retain(|&o| o != i);
            self.order.push(i);
        }
        self.damage_window(i);
        let tb = self.topbar_rect(theme);
        self.damage.add(tb);
    }

    fn hide_window(&mut self, i: usize, text: &mut TextEngine, theme: &Theme) {
        self.damage_window(i);
        self.windows[i].visible = false;
        self.windows[i].set_focused(false, text, theme);
        if let Some(&next) = self.order.iter().rev().find(|&&o| self.windows[o].visible) {
            self.focus_window(next, text, theme);
        }
        let tb = self.topbar_rect(theme);
        self.damage.add(tb);
    }

    fn window_at(&self, x: i32, y: i32) -> Option<usize> {
        self.order.iter().rev().copied().find(|&i| self.windows[i].visible && self.windows[i].rect.contains(x, y))
    }

    /// Top bar layout: (item, rect).
    fn top_items(&self, text: &mut TextEngine, theme: &Theme) -> Vec<(TopItem, Rect)> {
        let h = theme.metrics.topbar_h;
        let st = theme.text.body_strong;
        let small = theme.text.body;
        let mut v = Vec::new();
        let lw = 16 + 8 + text.measure(st.font, st.size, "ospab") + 20;
        v.push((TopItem::Launcher, Rect::new(6, 3, lw, h - 6)));
        let mut x = 6 + lw + 10;
        for (i, w) in self.windows.iter().enumerate() {
            let cw = 14 + 7 + text.measure(small.font, small.size, &w.title) + 20;
            v.push((TopItem::Chip(i), Rect::new(x, 3, cw, h - 6)));
            x += cw + 4;
        }
        let sw = text.measure(small.font, small.size, &self.clock) + 16 + 2 * 22 + 12;
        v.push((TopItem::Status, Rect::new(self.width - sw - 6, 3, sw, h - 6)));
        v
    }

    /// Feed an input event in screen coordinates.
    pub fn handle(&mut self, ev: &Event, text: &mut TextEngine, theme: &Theme) {
        // Pointer bookkeeping.
        if let Some((x, y)) = ev.pos() {
            if x != self.cursor.x || y != self.cursor.y {
                let old = cursor::bounds(self.cursor_shape, self.cursor.x, self.cursor.y);
                self.damage.add(old);
                self.cursor = Point::new(x.clamp(0, self.width - 1), y.clamp(0, self.height - 1));
                let new = cursor::bounds(self.cursor_shape, self.cursor.x, self.cursor.y);
                self.damage.add(new);
            }
        }
        let (px, py) = (self.cursor.x, self.cursor.y);

        // Launcher menu grabs input.
        if let Some(m) = &mut self.launcher {
            if !matches!(ev, Event::Wheel { .. }) {
                let mut dirty = false;
                let res = m.handle(ev, &mut dirty);
                let dr = m.damage_rect();
                if dirty { self.damage.add(dr); }
                match res {
                    MenuResult::None => {}
                    MenuResult::Chosen(i) => {
                        self.damage.add(dr);
                        self.launcher = None;
                        self.actions.push(ShellAction::Launch(i));
                    }
                    MenuResult::Dismissed => { self.damage.add(dr); self.launcher = None; }
                }
                self.set_cursor_shape(CursorShape::Arrow);
                return;
            }
        }

        match *ev {
            Event::PointerMove { .. } => {
                if let Some((i, gx, gy)) = self.drag {
                    let nr = Rect::new(px - gx, (py - gy).max(theme.metrics.topbar_h), self.windows[i].rect.w, self.windows[i].rect.h);
                    if nr != self.windows[i].rect {
                        self.damage_window(i);
                        self.windows[i].rect = nr;
                        self.damage_window(i);
                    }
                    return;
                }
                let target = self.capture.or_else(|| if py < theme.metrics.topbar_h { None } else { self.window_at(px, py) });
                if target != self.hover_win {
                    if let Some(o) = self.hover_win { self.windows[o].handle(&Event::PointerLeave, text, theme); }
                    self.hover_win = target;
                }
                let top = if self.capture.is_none() && py < theme.metrics.topbar_h {
                    self.top_items(text, theme).into_iter().find(|(_, r)| r.contains(px, py)).map(|(t, _)| t)
                } else { None };
                if top != self.top_hover {
                    self.top_hover = top;
                    let tb = self.topbar_rect(theme);
                    self.damage.add(tb);
                }
                let shape = match target {
                    Some(i) => {
                        let w = &mut self.windows[i];
                        let (lx, ly) = (px - w.rect.x, py - w.rect.y);
                        w.handle(&Event::PointerMove { x: lx, y: ly }, text, theme);
                        w.cursor_at(lx, ly, theme)
                    }
                    None => CursorShape::Arrow,
                };
                self.set_cursor_shape(shape);
            }
            Event::PointerDown { button, .. } => {
                if py < theme.metrics.topbar_h {
                    let hit = self.top_items(text, theme).into_iter().find(|(_, r)| r.contains(px, py));
                    match hit {
                        Some((TopItem::Launcher, r)) => {
                            let m = Menu::new(self.launcher_items.clone(), r, self.screen(), text, theme);
                            self.damage.add(m.damage_rect());
                            self.launcher = Some(m);
                        }
                        Some((TopItem::Chip(i), _)) => {
                            if self.windows[i].visible && self.focused() == Some(i) { self.hide_window(i, text, theme); }
                            else { self.focus_window(i, text, theme); }
                        }
                        _ => {}
                    }
                    return;
                }
                if let Some(i) = self.window_at(px, py) {
                    if self.focused() != Some(i) { self.focus_window(i, text, theme); }
                    let w = &mut self.windows[i];
                    let (lx, ly) = (px - w.rect.x, py - w.rect.y);
                    let resp = w.handle(&Event::PointerDown { x: lx, y: ly, button }, text, theme);
                    if resp.begin_drag { self.drag = Some((i, lx, ly)); } else { self.capture = Some(i); }
                }
            }
            Event::PointerUp { button, .. } => {
                if self.drag.take().is_some() { return; }
                if let Some(i) = self.capture.take() {
                    let w = &mut self.windows[i];
                    let (lx, ly) = (px - w.rect.x, py - w.rect.y);
                    let resp = w.handle(&Event::PointerUp { x: lx, y: ly, button }, text, theme);
                    if resp.close || resp.minimize { self.hide_window(i, text, theme); }
                }
            }
            Event::Wheel { dy, .. } => {
                if let Some(i) = self.window_at(px, py) {
                    let w = &mut self.windows[i];
                    let (lx, ly) = (px - w.rect.x, py - w.rect.y);
                    w.handle(&Event::Wheel { x: lx, y: ly, dy }, text, theme);
                }
            }
            Event::KeyDown { .. } | Event::KeyUp { .. } => {
                if let Some(i) = self.focused() { self.windows[i].handle(ev, text, theme); }
            }
            _ => {}
        }
        let _ = MouseButton::Left;
    }

    fn set_cursor_shape(&mut self, s: CursorShape) {
        if s != self.cursor_shape {
            self.damage.add(cursor::bounds(self.cursor_shape, self.cursor.x, self.cursor.y));
            self.cursor_shape = s;
            self.damage.add(cursor::bounds(s, self.cursor.x, self.cursor.y));
        }
    }

    pub fn set_clock(&mut self, s: &str, theme: &Theme) {
        if self.clock != s {
            self.clock = s.into();
            let tb = self.topbar_rect(theme);
            self.damage.add(tb);
        }
    }

    pub fn tick(&mut self, now_ms: u64, theme: &Theme) {
        for w in self.windows.iter_mut() { if w.visible { w.tick(now_ms, theme); } }
    }

    /// Render windows and composite every damaged area into `back`.
    /// Returns the screen rectangles that changed.
    pub fn render(&mut self, text: &mut TextEngine, theme: &Theme) -> Vec<Rect> {
        for i in 0..self.windows.len() {
            if !self.windows[i].visible { continue; }
            let rects = self.windows[i].render(text, theme);
            let o = self.windows[i].rect;
            for r in rects { self.damage.add(r.offset(o.x, o.y)); }
        }
        self.damage.clip(self.screen());
        let rects = self.damage.take();
        for r in &rects { self.compose(*r, text, theme); }
        rects
    }

    fn compose(&mut self, r: Rect, text: &mut TextEngine, theme: &Theme) {
        let col = &theme.color;
        let mut back = core::mem::replace(&mut self.back, Surface::new(0, 0));
        let mut c = Canvas::new(back.view_mut());
        c.set_clip(r);
        c.clear_rect(r, col.bg0.premul());
        let rad = theme.radius.window;
        for &i in &self.order {
            let w = &self.windows[i];
            if !w.visible || !w.rect.outset(40).offset(0, 10).intersects(&r) { continue; }
            let occ = Some(w.rect.inset(rad));
            let (ambient, key) = if w.focused {
                (Shadow { dx: 0, dy: 14, blur: 30, spread: -2, color: Color::black_a(150) },
                 Shadow { dx: 0, dy: 2, blur: 5, spread: 0, color: Color::black_a(110) })
            } else {
                (Shadow { dx: 0, dy: 8, blur: 20, spread: -4, color: Color::black_a(110) },
                 Shadow { dx: 0, dy: 1, blur: 3, spread: 0, color: Color::black_a(90) })
            };
            self.shadows.draw(&mut c, w.rect, rad, &ambient, occ);
            self.shadows.draw(&mut c, w.rect, rad, &key, occ);
            let v = w.surface.view();
            c.blit(&v, v.rect(), w.rect.x, w.rect.y);
        }
        if self.topbar_rect(theme).intersects(&r) { self.paint_topbar(&mut c, text, theme); }
        if let Some(m) = &self.launcher {
            if m.damage_rect().intersects(&r) { m.paint(&mut c, text, theme, &mut self.shadows); }
        }
        if self.show_cursor { cursor::draw(&mut c, self.cursor_shape, self.cursor.x, self.cursor.y); }
        drop(c);
        self.back = back;
    }

    fn paint_topbar(&self, c: &mut Canvas, text: &mut TextEngine, theme: &Theme) {
        let col = &theme.color;
        let tb = Rect::new(0, 0, self.width, theme.metrics.topbar_h);
        c.fill_rect(tb, Color::hex(0x0F1012));
        c.hline(0, self.width, tb.bottom() - 1, col.hairline);
        let st = theme.text.body_strong;
        let body = theme.text.body;
        let lm = text.metrics(body.font, body.size);
        let focused = self.focused();
        for (item, r) in self.top_items(text, theme) {
            let hovered = self.top_hover == Some(item) || (item == TopItem::Launcher && self.launcher.is_some());
            let ty = r.y + (r.h - lm.height) / 2;
            match item {
                TopItem::Launcher => {
                    if hovered { c.fill_round_rect(r, theme.radius.md, col.hover); }
                    icons::draw(c, Icon::Logo, Rect::new(r.x + 10, r.y + (r.h - 16) / 2, 16, 16), col.text);
                    text.draw(c, r.x + 10 + 16 + 8, ty, st.font, st.size, col.text, "ospab");
                }
                TopItem::Chip(i) => {
                    let w = &self.windows[i];
                    let is_focus = focused == Some(i);
                    if is_focus { c.fill_round_rect(r, theme.radius.md, Color::white_a(16)); }
                    else if hovered { c.fill_round_rect(r, theme.radius.md, col.hover); }
                    let fg = if is_focus { col.text } else if w.visible { col.text_secondary } else { col.text_disabled };
                    icons::draw(c, w.icon, Rect::new(r.x + 10, r.y + (r.h - 14) / 2, 14, 14), fg);
                    text.draw(c, r.x + 10 + 14 + 7, ty, body.font, body.size, fg, &w.title);
                    if w.visible && !is_focus {
                        c.fill_circle((r.x + r.w / 2) as f32, (r.bottom() + 1) as f32, 1.5, col.text_secondary);
                    }
                }
                TopItem::Status => {
                    if hovered { c.fill_round_rect(r, theme.radius.md, col.hover); }
                    let mut x = r.x + 10;
                    for ic in [Icon::Wifi, Icon::Volume] {
                        icons::draw(c, ic, Rect::new(x, r.y + (r.h - 14) / 2, 14, 14), col.text_secondary);
                        x += 22;
                    }
                    text.draw(c, x + 4, ty, body.font, body.size, col.text, &self.clock);
                }
            }
        }
    }
}
