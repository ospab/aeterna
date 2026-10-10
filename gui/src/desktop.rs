// SPDX-License-Identifier: AGPL-3.0-only
//! Compositor and window manager (server side of [`crate::proto`]).
//!
//! Owns window geometry, stacking, focus and the shell chrome (top bar,
//! dock, launcher, Alt+Tab switcher, pointer).  It reads client surfaces,
//! composites damaged screen areas into a back buffer with soft shadows and
//! reports the changed rectangles; the caller presents them (framebuffer copy
//! or PNG).  It never draws inside a client window.
//!
//! Today it runs in the kernel's desktop session; it is written against the
//! message protocol only, so it can become the ring-3 compositor server once
//! IPC channels and shared memory exist (see docs/en/gui.md).

use alloc::string::String;
use alloc::vec::Vec;

use crate::canvas::Canvas;
use crate::color::Color;
use crate::cursor;
use crate::damage::Damage;
use crate::event::{CursorShape, Event, Key, MouseButton};
use crate::geom::{Point, Rect};
use crate::icons::{self, Icon};
use crate::menu::{Menu, MenuItem, MenuResult};
use crate::proto::{Bus, SharedSurface, ToClient, ToServer, WinId};
use crate::shadow::{Shadow, ShadowCache};
use crate::surface::Surface;
use crate::text::TextEngine;
use crate::theme::Theme;

/// Shell status shown in the top bar (provided by the session).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShellStatus {
    pub clock: String,
    /// "10.0.2.15", "No network", ...
    pub net: String,
    pub net_up: bool,
    pub ostp: bool,
    pub volume: Option<u8>,
}

#[derive(Clone, Debug)]
pub struct DockItem {
    pub name: String,
    pub icon: Icon,
    pub running: bool,
}

/// Something the shell chrome asks the session to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellAction {
    Launcher(usize),
    Dock(usize),
    Status,
    Clock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Top {
    Launcher,
    Status,
    Clock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Grab {
    Move { id: WinId, dx: i32, dy: i32 },
    Resize { id: WinId, edges: u8, start: Rect, px: i32, py: i32 },
}

const E_L: u8 = 1;
const E_R: u8 = 2;
const E_T: u8 = 4;
const E_B: u8 = 8;
const RESIZE_OUT: i32 = 6;
const RESIZE_IN: i32 = 3;

pub struct WmWindow {
    pub id: WinId,
    pub title: String,
    pub icon: Icon,
    pub rect: Rect,
    pub min: (i32, i32),
    pub surface: SharedSurface,
    pub minimized: bool,
    pub saved: Option<Rect>,
    pub focused: bool,
    pub cursor: CursorShape,
    pub resizable: bool,
    mapped: bool,
}

pub struct Desktop {
    pub width: i32,
    pub height: i32,
    pub back: Surface,
    pub windows: Vec<WmWindow>,
    /// Stacking order, last = topmost.
    pub order: Vec<WinId>,
    shadows: ShadowCache,
    pub cursor: Point,
    pub cursor_shape: CursorShape,
    pub show_cursor: bool,
    grab: Option<Grab>,
    capture: Option<WinId>,
    hover_win: Option<WinId>,
    buttons: u8,
    top_hover: Option<Top>,
    dock_hover: Option<usize>,
    launcher: Option<Menu>,
    pub launcher_items: Vec<MenuItem>,
    pub dock: Vec<DockItem>,
    pub status: ShellStatus,
    switcher: Option<usize>,
    pub actions: Vec<ShellAction>,
    damage: Damage,
    placed: i32,
}

pub const DOCK_H: i32 = 60;
const DOCK_TILE: i32 = 44;
const DOCK_GAP: i32 = 8;
const DOCK_PAD: i32 = 8;

impl Desktop {
    pub fn new(width: i32, height: i32) -> Desktop {
        let mut d = Desktop {
            width, height, back: Surface::new(width, height), windows: Vec::new(), order: Vec::new(),
            shadows: ShadowCache::new(), cursor: Point::new(width / 2, height / 2), cursor_shape: CursorShape::Arrow,
            show_cursor: true, grab: None, capture: None, hover_win: None, buttons: 0, top_hover: None, dock_hover: None,
            launcher: None, launcher_items: Vec::new(), dock: Vec::new(), status: ShellStatus::default(), switcher: None,
            actions: Vec::new(), damage: Damage::new(), placed: 0,
        };
        d.damage.max_rects = 24;
        d.damage.add(Rect::from_size(width, height));
        d
    }

    pub fn screen(&self) -> Rect { Rect::from_size(self.width, self.height) }
    pub fn invalidate_all(&mut self) { self.damage.add(self.screen()); }

    /// Area windows maximise into (between the top bar and the dock).
    pub fn work_area(&self, theme: &Theme) -> Rect {
        let top = theme.metrics.topbar_h;
        Rect::new(0, top, self.width, self.height - top - DOCK_H - 12)
    }

    /// Change the screen size (display mode switch).
    pub fn resize_screen(&mut self, w: i32, h: i32, bus: &mut Bus, theme: &Theme) {
        self.width = w;
        self.height = h;
        self.back = Surface::new(w, h);
        let wa = self.work_area(theme);
        for win in self.windows.iter_mut() {
            if win.saved.is_some() {
                win.rect = wa;
            } else {
                win.rect.w = win.rect.w.min(wa.w);
                win.rect.h = win.rect.h.min(wa.h);
                win.rect.x = win.rect.x.clamp(0, (w - win.rect.w).max(0));
                win.rect.y = win.rect.y.clamp(wa.y, (wa.bottom() - win.rect.h).max(wa.y));
            }
            bus.to_client.push_back(ToClient::Configure { id: win.id, w: win.rect.w, h: win.rect.h });
        }
        self.cursor = Point::new(self.cursor.x.min(w - 1), self.cursor.y.min(h - 1));
        self.invalidate_all();
    }

    fn idx(&self, id: WinId) -> Option<usize> { self.windows.iter().position(|w| w.id == id) }

    pub fn window(&self, id: WinId) -> Option<&WmWindow> { self.windows.iter().find(|w| w.id == id) }

    fn extent(r: Rect) -> Rect { r.outset(40).offset(0, 12) }

    fn damage_win(&mut self, id: WinId) {
        if let Some(i) = self.idx(id) {
            let r = Self::extent(self.windows[i].rect);
            self.damage.add(r);
        }
    }

    fn visible(&self, id: WinId) -> bool {
        self.window(id).map_or(false, |w| w.mapped && !w.minimized)
    }

    pub fn focused(&self) -> Option<WinId> { self.windows.iter().find(|w| w.focused).map(|w| w.id) }

    /// Raise, un-minimise and focus a window.
    pub fn activate(&mut self, id: WinId, bus: &mut Bus, theme: &Theme) {
        let Some(i) = self.idx(id) else { return };
        self.windows[i].minimized = false;
        for w in self.windows.iter_mut() {
            let f = w.id == id;
            if w.focused != f {
                w.focused = f;
                bus.to_client.push_back(ToClient::Focus { id: w.id, focused: f });
                let r = Self::extent(w.rect);
                self.damage.add(r);
            }
        }
        self.order.retain(|&o| o != id);
        self.order.push(id);
        self.damage_win(id);
        self.damage_topbar(theme);
    }

    fn focus_next(&mut self, bus: &mut Bus, theme: &Theme) {
        let next = self.order.iter().rev().copied().find(|&o| self.visible(o) && !self.windows[self.idx(o).unwrap()].focused);
        for w in self.windows.iter_mut() {
            if w.focused && (w.minimized || Some(w.id) != next) {
                w.focused = false;
                bus.to_client.push_back(ToClient::Focus { id: w.id, focused: false });
            }
        }
        if let Some(n) = next { self.activate(n, bus, theme); }
        self.damage_topbar(theme);
    }

    fn damage_topbar(&mut self, theme: &Theme) {
        self.damage.add(Rect::new(0, 0, self.width, theme.metrics.topbar_h));
    }

    fn dock_rect(&self) -> Rect {
        let n = self.dock.len() as i32;
        let w = n * DOCK_TILE + (n - 1).max(0) * DOCK_GAP + 2 * DOCK_PAD;
        Rect::new((self.width - w) / 2, self.height - DOCK_H - 8, w, DOCK_H)
    }

    fn dock_tile(&self, i: usize) -> Rect {
        let d = self.dock_rect();
        Rect::new(d.x + DOCK_PAD + i as i32 * (DOCK_TILE + DOCK_GAP), d.y + (DOCK_H - DOCK_TILE) / 2 - 2, DOCK_TILE, DOCK_TILE)
    }

    fn dock_damage(&self) -> Rect { self.dock_rect().outset(30).union(&Rect::new(self.dock_rect().x - 80, self.dock_rect().y - 44, self.dock_rect().w + 160, 44)) }

    pub fn set_dock_running(&mut self, running: &[bool]) {
        let mut changed = false;
        for (d, &r) in self.dock.iter_mut().zip(running.iter()) {
            if d.running != r { d.running = r; changed = true; }
        }
        if changed { let r = self.dock_damage(); self.damage.add(r); }
    }

    pub fn set_status(&mut self, s: ShellStatus, theme: &Theme) {
        if s != self.status {
            self.status = s;
            self.damage_topbar(theme);
        }
    }

    fn top_items(&self, text: &mut TextEngine, theme: &Theme) -> Vec<(Top, Rect)> {
        let h = theme.metrics.topbar_h;
        let st = theme.text.body_strong;
        let body = theme.text.body;
        let mut v = Vec::new();
        let lw = 16 + 8 + text.measure(st.font, st.size, "ospab") + 20;
        v.push((Top::Launcher, Rect::new(6, 3, lw, h - 6)));
        let cw = text.measure(body.font, body.size, &self.status.clock) + 20;
        let clock = Rect::new(self.width - cw - 6, 3, cw, h - 6);
        v.push((Top::Clock, clock));
        let mut sw = 12 + 16 + 6 + text.measure(body.font, body.size, &self.status.net) + 14;
        if self.status.ostp { sw += 14 + 6 + text.measure(theme.text.caption.font, theme.text.caption.size, "OSTP") + 14; }
        if let Some(v) = self.status.volume { sw += 16 + 6 + text.measure(body.font, body.size, &alloc::format!("{}%", v)) + 6; }
        v.push((Top::Status, Rect::new(clock.x - sw - 4, 3, sw, h - 6)));
        v
    }

    /// Resize edges under the pointer for window `i` (in screen coords).
    fn edges_at(&self, i: usize, x: i32, y: i32) -> u8 {
        let w = &self.windows[i];
        if w.saved.is_some() || !w.resizable { return 0; }
        let r = w.rect;
        if !r.outset(RESIZE_OUT).contains(x, y) || r.inset(RESIZE_IN).contains(x, y) { return 0; }
        let corner = 14;
        let mut e = 0;
        if x < r.x + RESIZE_IN || (x < r.x + corner && (y < r.y + RESIZE_IN || y >= r.bottom() - RESIZE_IN)) { e |= E_L; }
        if x >= r.right() - RESIZE_IN || (x >= r.right() - corner && (y < r.y + RESIZE_IN || y >= r.bottom() - RESIZE_IN)) { e |= E_R; }
        if y < r.y + RESIZE_IN || (y < r.y + corner && (x < r.x + RESIZE_IN || x >= r.right() - RESIZE_IN)) { e |= E_T; }
        if y >= r.bottom() - RESIZE_IN || (y >= r.bottom() - corner && (x < r.x + RESIZE_IN || x >= r.right() - RESIZE_IN)) { e |= E_B; }
        e
    }

    fn edge_cursor(e: u8) -> CursorShape {
        match e {
            x if x == E_L | E_T || x == E_R | E_B => CursorShape::ResizeNwse,
            x if x == E_R | E_T || x == E_L | E_B => CursorShape::ResizeNesw,
            E_L | E_R => CursorShape::ResizeH,
            _ => CursorShape::ResizeV,
        }
    }

    /// Topmost visible window (index) whose rect, or resize border, contains (x, y).
    fn window_at(&self, x: i32, y: i32, with_border: bool) -> Option<usize> {
        for &id in self.order.iter().rev() {
            let i = self.idx(id).unwrap();
            let w = &self.windows[i];
            if !w.mapped || w.minimized { continue; }
            let r = if with_border && w.saved.is_none() { w.rect.outset(RESIZE_OUT) } else { w.rect };
            if r.contains(x, y) { return Some(i); }
        }
        None
    }

    fn set_cursor_shape(&mut self, s: CursorShape) {
        if s != self.cursor_shape {
            self.damage.add(cursor::bounds(self.cursor_shape, self.cursor.x, self.cursor.y));
            self.cursor_shape = s;
            self.damage.add(cursor::bounds(s, self.cursor.x, self.cursor.y));
        }
    }

    fn send_input(&mut self, i: usize, ev: Event, bus: &mut Bus) {
        let w = &self.windows[i];
        let ev = ev.translated(-w.rect.x, -w.rect.y);
        bus.to_client.push_back(ToClient::Input { id: w.id, ev });
    }

    /// Open the launcher menu (also bound to the Meta key).
    pub fn open_launcher(&mut self, text: &mut TextEngine, theme: &Theme) {
        let items = self.top_items(text, theme);
        let r = items[0].1;
        let m = Menu::new(self.launcher_items.clone(), r, self.screen(), text, theme);
        self.damage.add(m.damage_rect());
        self.launcher = Some(m);
        self.damage_topbar(theme);
    }

    fn close_launcher(&mut self, theme: &Theme) {
        if let Some(m) = self.launcher.take() { self.damage.add(m.damage_rect()); }
        self.damage_topbar(theme);
    }

    fn switch_list(&self) -> Vec<WinId> {
        self.order.iter().rev().copied().filter(|&id| self.window(id).map_or(false, |w| w.mapped)).collect()
    }

    fn switcher_rect(&self, n: usize) -> Rect {
        let item = 104;
        let w = n as i32 * item + 24;
        Rect::new((self.width - w) / 2, (self.height - 128) / 2, w, 128)
    }

    /// Feed a device event (screen coordinates).
    pub fn handle(&mut self, ev: &Event, bus: &mut Bus, text: &mut TextEngine, theme: &Theme) {
        if let Some((x, y)) = ev.pos() {
            let (x, y) = (x.clamp(0, self.width - 1), y.clamp(0, self.height - 1));
            if x != self.cursor.x || y != self.cursor.y {
                self.damage.add(cursor::bounds(self.cursor_shape, self.cursor.x, self.cursor.y));
                self.cursor = Point::new(x, y);
                self.damage.add(cursor::bounds(self.cursor_shape, x, y));
            }
        }
        let (px, py) = (self.cursor.x, self.cursor.y);
        let ev = ev.translated(0, 0);
        match ev {
            Event::PointerDown { button: MouseButton::Left, .. } => self.buttons |= 1,
            Event::PointerUp { button: MouseButton::Left, .. } => self.buttons &= !1,
            _ => {}
        }

        // Keyboard shell shortcuts.
        if let Event::KeyDown { key, mods, .. } = ev {
            if key == Key::Tab && mods.alt {
                let list = self.switch_list();
                if list.is_empty() { return; }
                let n = list.len();
                let cur = self.switcher.unwrap_or(0);
                let next = if self.switcher.is_none() { if n > 1 { 1 } else { 0 } } else if mods.shift { (cur + n - 1) % n } else { (cur + 1) % n };
                self.switcher = Some(next);
                let r = self.switcher_rect(n).outset(40);
                self.damage.add(r);
                return;
            }
            if self.switcher.is_some() && key == Key::Escape {
                self.switcher = None;
                self.invalidate_all();
                return;
            }
            if key == Key::F(4) && mods.alt {
                if let Some(f) = self.focused() { bus.to_client.push_back(ToClient::CloseRequested { id: f }); }
                return;
            }
            if key == Key::Meta {
                if self.launcher.is_some() { self.close_launcher(theme); } else { self.open_launcher(text, theme); }
                return;
            }
        }
        if let Event::KeyUp { key: Key::Alt, .. } = ev {
            if let Some(sel) = self.switcher.take() {
                let list = self.switch_list();
                let r = self.switcher_rect(list.len()).outset(40);
                self.damage.add(r);
                if let Some(&id) = list.get(sel) { self.activate(id, bus, theme); }
                return;
            }
        }

        // Launcher menu grabs input.
        if let Some(m) = &mut self.launcher {
            if !matches!(ev, Event::Wheel { .. } | Event::KeyUp { .. }) {
                let mut dirty = false;
                let res = m.handle(&ev, &mut dirty);
                let dr = m.damage_rect();
                if dirty { self.damage.add(dr); }
                match res {
                    MenuResult::None => {
                        // A click on the launcher button itself closes the menu.
                        if let Event::PointerDown { .. } = ev {
                            if py < theme.metrics.topbar_h && !dr.contains(px, py) { self.close_launcher(theme); }
                        }
                    }
                    MenuResult::Chosen(i) => { self.close_launcher(theme); self.actions.push(ShellAction::Launcher(i)); }
                    MenuResult::Dismissed => self.close_launcher(theme),
                }
                self.set_cursor_shape(CursorShape::Arrow);
                return;
            }
        }

        match ev {
            Event::PointerMove { .. } => {
                if let Some(g) = self.grab {
                    self.drag_to(g, px, py, bus, theme);
                    return;
                }
                if let Some(id) = self.capture {
                    if let Some(i) = self.idx(id) { self.send_input(i, Event::PointerMove { x: px, y: py }, bus); }
                    return;
                }
                let top_h = theme.metrics.topbar_h;
                let in_dock = self.dock_rect().contains(px, py);
                let target = if py < top_h || in_dock { None } else { self.window_at(px, py, true) };
                let tid = target.map(|i| self.windows[i].id);
                if tid != self.hover_win {
                    if let Some(o) = self.hover_win { bus.to_client.push_back(ToClient::Input { id: o, ev: Event::PointerLeave }); }
                    self.hover_win = tid;
                }
                // Top bar and dock hover.
                let top = if py < top_h { self.top_items(text, theme).into_iter().find(|(_, r)| r.contains(px, py)).map(|(t, _)| t) } else { None };
                if top != self.top_hover { self.top_hover = top; self.damage_topbar(theme); }
                let dh = if in_dock { (0..self.dock.len()).find(|&i| self.dock_tile(i).outset(DOCK_GAP / 2).contains(px, py)) } else { None };
                if dh != self.dock_hover { self.dock_hover = dh; let r = self.dock_damage(); self.damage.add(r); }
                let shape = match target {
                    Some(i) => {
                        let e = self.edges_at(i, px, py);
                        if e != 0 { Self::edge_cursor(e) } else {
                            self.send_input(i, Event::PointerMove { x: px, y: py }, bus);
                            self.windows[i].cursor
                        }
                    }
                    None => CursorShape::Arrow,
                };
                self.set_cursor_shape(shape);
            }
            Event::PointerDown { button, .. } => {
                let top_h = theme.metrics.topbar_h;
                if py < top_h {
                    let hit = self.top_items(text, theme).into_iter().find(|(_, r)| r.contains(px, py));
                    match hit {
                        Some((Top::Launcher, _)) => self.open_launcher(text, theme),
                        Some((Top::Status, _)) => self.actions.push(ShellAction::Status),
                        Some((Top::Clock, _)) => self.actions.push(ShellAction::Clock),
                        None => {}
                    }
                    return;
                }
                if self.dock_rect().contains(px, py) {
                    if let Some(i) = (0..self.dock.len()).find(|&i| self.dock_tile(i).outset(DOCK_GAP / 2).contains(px, py)) {
                        self.actions.push(ShellAction::Dock(i));
                    }
                    return;
                }
                if let Some(i) = self.window_at(px, py, true) {
                    let id = self.windows[i].id;
                    if !self.windows[i].focused || self.order.last() != Some(&id) { self.activate(id, bus, theme); }
                    let e = self.edges_at(i, px, py);
                    if e != 0 && button == MouseButton::Left {
                        self.grab = Some(Grab::Resize { id, edges: e, start: self.windows[i].rect, px, py });
                    } else {
                        self.capture = Some(id);
                        self.send_input(i, Event::PointerDown { x: px, y: py, button }, bus);
                    }
                }
            }
            Event::PointerUp { button, .. } => {
                if self.grab.take().is_some() { return; }
                if let Some(id) = self.capture.take() {
                    if let Some(i) = self.idx(id) { self.send_input(i, Event::PointerUp { x: px, y: py, button }, bus); }
                }
            }
            Event::Wheel { dy, .. } => {
                if let Some(i) = self.window_at(px, py, false) { self.send_input(i, Event::Wheel { x: px, y: py, dy }, bus); }
            }
            Event::KeyDown { .. } | Event::KeyUp { .. } => {
                if let Some(f) = self.focused() { bus.to_client.push_back(ToClient::Input { id: f, ev }); }
            }
            _ => {}
        }
    }

    fn drag_to(&mut self, g: Grab, px: i32, py: i32, bus: &mut Bus, theme: &Theme) {
        let top = theme.metrics.topbar_h;
        match g {
            Grab::Move { id, dx, dy } => {
                let Some(i) = self.idx(id) else { return };
                let mut r = self.windows[i].rect;
                if let Some(saved) = self.windows[i].saved.take() {
                    // Dragging a maximised window restores it under the pointer.
                    let fx = (px - r.x) * saved.w / r.w.max(1);
                    r = Rect::new(px - fx, py - dy, saved.w, saved.h);
                    self.grab = Some(Grab::Move { id, dx: fx, dy });
                    bus.to_client.push_back(ToClient::Configure { id, w: r.w, h: r.h });
                } else {
                    r.x = px - dx;
                    r.y = (py - dy).max(top).min(self.height - 40);
                }
                if r != self.windows[i].rect {
                    self.damage_win(id);
                    self.windows[i].rect = r;
                    self.damage_win(id);
                }
            }
            Grab::Resize { id, edges, start, px: sx, py: sy } => {
                let Some(i) = self.idx(id) else { return };
                let (mw, mh) = self.windows[i].min;
                let (ddx, ddy) = (px - sx, py - sy);
                let mut l = start.x;
                let mut t = start.y;
                let mut r = start.right();
                let mut b = start.bottom();
                if edges & E_L != 0 { l = (start.x + ddx).min(r - mw); }
                if edges & E_R != 0 { r = (start.right() + ddx).max(l + mw).min(self.width); }
                if edges & E_T != 0 { t = (start.y + ddy).min(b - mh).max(top); }
                if edges & E_B != 0 { b = (start.bottom() + ddy).max(t + mh).min(self.height); }
                let nr = Rect::from_ltrb(l, t, r, b);
                if nr != self.windows[i].rect {
                    self.damage_win(id);
                    self.windows[i].rect = nr;
                    self.damage_win(id);
                    bus.to_client.push_back(ToClient::Configure { id, w: nr.w, h: nr.h });
                }
            }
        }
    }

    /// Apply client requests.
    pub fn apply(&mut self, bus: &mut Bus, theme: &Theme) {
        while let Some(m) = bus.to_server.pop_front() {
            match m {
                ToServer::Create { id, title, icon, size, min, resizable, surface } => {
                    let wa = self.work_area(theme);
                    let (w, h) = (size.0.min(wa.w - 20).max(min.0.min(wa.w)), size.1.min(wa.h - 10).max(min.1.min(wa.h)));
                    let n = self.placed % 6;
                    self.placed += 1;
                    let x = ((self.width - w) / 2 - 150 + n * 40).clamp(0, (self.width - w).max(0));
                    let y = (wa.y + 30 + n * 32).min((wa.bottom() - h).max(wa.y));
                    self.windows.push(WmWindow {
                        id, title, icon, rect: Rect::new(x, y, w, h), min, surface, minimized: false, saved: None,
                        focused: false, cursor: CursorShape::Arrow, resizable, mapped: true,
                    });
                    self.order.push(id);
                    if (w, h) != size { bus.to_client.push_back(ToClient::Configure { id, w, h }); }
                    self.activate(id, bus, theme);
                }
                ToServer::SetTitle { id, title } => {
                    if let Some(i) = self.idx(id) { self.windows[i].title = title; }
                    self.damage_topbar(theme);
                }
                ToServer::Damage { id, rects } => {
                    if let Some(i) = self.idx(id) {
                        let w = &self.windows[i];
                        if w.mapped && !w.minimized {
                            let o = w.rect;
                            for r in rects { self.damage.add(r.offset(o.x, o.y).intersect(&o)); }
                        }
                    }
                }
                ToServer::BeginMove { id } => {
                    if self.buttons & 1 != 0 {
                        if let Some(i) = self.idx(id) {
                            let r = self.windows[i].rect;
                            self.grab = Some(Grab::Move { id, dx: self.cursor.x - r.x, dy: self.cursor.y - r.y });
                            self.capture = None;
                        }
                    }
                }
                ToServer::Minimize { id } => {
                    if let Some(i) = self.idx(id) {
                        self.damage_win(id);
                        self.windows[i].minimized = true;
                        self.focus_next(bus, theme);
                        let r = self.dock_damage();
                        self.damage.add(r);
                    }
                }
                ToServer::ToggleMaximize { id } => {
                    if let Some(i) = self.idx(id).filter(|&i| self.windows[i].resizable) {
                        self.damage_win(id);
                        let wa = self.work_area(theme);
                        let w = &mut self.windows[i];
                        match w.saved.take() {
                            Some(s) => w.rect = s,
                            None => { w.saved = Some(w.rect); w.rect = wa.inset(0); }
                        }
                        let r = w.rect;
                        bus.to_client.push_back(ToClient::Configure { id, w: r.w, h: r.h });
                        self.damage_win(id);
                    }
                }
                ToServer::SetCursor { id, shape } => {
                    if let Some(i) = self.idx(id) {
                        self.windows[i].cursor = shape;
                        if self.hover_win == Some(id) && self.grab.is_none() { self.set_cursor_shape(shape); }
                    }
                }
                ToServer::Destroy { id } => {
                    self.damage_win(id);
                    let was_focused = self.window(id).map_or(false, |w| w.focused);
                    self.windows.retain(|w| w.id != id);
                    self.order.retain(|&o| o != id);
                    if self.capture == Some(id) { self.capture = None; }
                    if self.hover_win == Some(id) { self.hover_win = None; }
                    if matches!(self.grab, Some(Grab::Move { id: g, .. }) | Some(Grab::Resize { id: g, .. }) if g == id) { self.grab = None; }
                    if was_focused { self.focus_next(bus, theme); }
                    self.damage_topbar(theme);
                }
                ToServer::Activate { id } => self.activate(id, bus, theme),
            }
        }
    }

    /// Composite every damaged area. Returns the changed screen rectangles.
    pub fn render(&mut self, text: &mut TextEngine, theme: &Theme) -> Vec<Rect> {
        self.damage.clip(self.screen());
        let rects = self.damage.take();
        for r in &rects { self.compose(*r, text, theme); }
        rects
    }

    fn compose(&mut self, r: Rect, text: &mut TextEngine, theme: &Theme) {
        let col = theme.color;
        let mut back = core::mem::replace(&mut self.back, Surface::new(0, 0));
        {
            let mut c = Canvas::new(back.view_mut());
            c.set_clip(r);
            c.clear_rect(r, col.bg0.premul());
            let rad = theme.radius.window;
            for &id in &self.order {
                let Some(w) = self.windows.iter().find(|w| w.id == id) else { continue };
                if !w.mapped || w.minimized || !Self::extent(w.rect).intersects(&r) { continue; }
                let occ = Some(w.rect.inset(rad));
                let (ambient, key) = if w.focused {
                    (Shadow { dx: 0, dy: 14, blur: 30, spread: -2, color: Color::black_a(160) },
                     Shadow { dx: 0, dy: 2, blur: 5, spread: 0, color: Color::black_a(120) })
                } else {
                    (Shadow { dx: 0, dy: 8, blur: 20, spread: -4, color: Color::black_a(120) },
                     Shadow { dx: 0, dy: 1, blur: 3, spread: 0, color: Color::black_a(100) })
                };
                if w.saved.is_none() {
                    self.shadows.draw(&mut c, w.rect, rad, &ambient, occ);
                    self.shadows.draw(&mut c, w.rect, rad, &key, occ);
                }
                let s = w.surface.borrow();
                let v = s.view();
                let src = Rect::new(0, 0, w.rect.w.min(v.width), w.rect.h.min(v.height));
                c.blit(&v, src, w.rect.x, w.rect.y);
            }
            if r.y < theme.metrics.topbar_h { self.paint_topbar(&mut c, text, theme); }
            if self.dock_damage().intersects(&r) { self.paint_dock(&mut c, text, theme); }
            if let Some(sel) = self.switcher { self.paint_switcher(&mut c, text, theme, sel); }
            if let Some(m) = &self.launcher {
                if m.damage_rect().intersects(&r) { m.paint(&mut c, text, theme, &mut self.shadows); }
            }
            if self.show_cursor { cursor::draw(&mut c, self.cursor_shape, self.cursor.x, self.cursor.y); }
        }
        self.back = back;
    }

    fn paint_topbar(&self, c: &mut Canvas, text: &mut TextEngine, theme: &Theme) {
        let col = &theme.color;
        let tb = Rect::new(0, 0, self.width, theme.metrics.topbar_h);
        c.fill_rect(tb, Color::hex(0x0F1012));
        c.hline(0, self.width, tb.bottom() - 1, col.hairline);
        let st = theme.text.body_strong;
        let body = theme.text.body;
        let cap = theme.text.caption;
        let lm = text.metrics(body.font, body.size);
        let items = self.top_items(text, theme);
        for (item, r) in items.iter().copied() {
            let hovered = self.top_hover == Some(item) || (item == Top::Launcher && self.launcher.is_some());
            if hovered { c.fill_round_rect(r, theme.radius.md, col.hover); }
            let ty = r.y + (r.h - lm.height) / 2;
            match item {
                Top::Launcher => {
                    icons::draw(c, Icon::Logo, Rect::new(r.x + 10, r.y + (r.h - 16) / 2, 16, 16), col.text);
                    text.draw(c, r.x + 34, ty, st.font, st.size, col.text, "ospab");
                }
                Top::Clock => { text.draw(c, r.x + 10, ty, body.font, body.size, col.text, &self.status.clock); }
                Top::Status => {
                    let mut x = r.x + 12;
                    if self.status.ostp {
                        icons::draw(c, Icon::Lock, Rect::new(x, r.y + (r.h - 14) / 2, 14, 14), col.accent_text);
                        x += 20;
                        let cl = text.metrics(cap.font, cap.size);
                        x += text.draw(c, x, r.y + (r.h - cl.height) / 2, theme.text.caption.font, cap.size, col.accent_text, "OSTP") + 14;
                    }
                    let nc = if self.status.net_up { col.text_secondary } else { col.text_disabled };
                    icons::draw(c, if self.status.net_up { Icon::Network } else { Icon::Close }, Rect::new(x, r.y + (r.h - 15) / 2, 15, 15), nc);
                    x += 22;
                    x += text.draw(c, x, ty, body.font, body.size, nc, &self.status.net) + 14;
                    if let Some(v) = self.status.volume {
                        icons::draw(c, Icon::Volume, Rect::new(x, r.y + (r.h - 15) / 2, 15, 15), col.text_secondary);
                        x += 22;
                        text.draw(c, x, ty, body.font, body.size, col.text_secondary, &alloc::format!("{}%", v));
                    }
                }
            }
        }
        // Focused window title, after the launcher.
        if let Some(w) = self.windows.iter().find(|w| w.focused) {
            let x = items[0].1.right() + 14;
            let maxw = items[2].1.x - x - 20;
            if maxw > 40 { text.draw_ellipsis(c, x, items[0].1.y + (items[0].1.h - lm.height) / 2, maxw, st.font, st.size, col.text_secondary, &w.title); }
        }
    }

    fn paint_dock(&mut self, c: &mut Canvas, text: &mut TextEngine, theme: &Theme) {
        if self.dock.is_empty() { return; }
        let col = theme.color;
        let d = self.dock_rect();
        self.shadows.draw(c, d, 16, &Shadow { dx: 0, dy: 8, blur: 22, spread: 0, color: Color::black_a(150) }, Some(d.inset(16)));
        c.fill_round_rect(d, 16, Color::hex(0x16171A));
        c.stroke_round_rect(d, 16, 1, col.hairline_strong);
        for i in 0..self.dock.len() {
            let t = self.dock_tile(i);
            let hov = self.dock_hover == Some(i);
            c.fill_round_rect(t, 11, if hov { Color::hex(0x2C2F36) } else { Color::hex(0x202227) });
            c.stroke_round_rect(t, 11, 1, Color::white_a(if hov { 26 } else { 14 }));
            icons::draw(c, self.dock[i].icon, Rect::new(t.x + 11, t.y + 11, 22, 22), if hov { col.text } else { Color::hex(0xC9CDD3) });
            if self.dock[i].running {
                c.fill_circle((t.x + t.w / 2) as f32, (t.bottom() + 5) as f32, 2.0, col.text_secondary);
            }
        }
        if let Some(i) = self.dock_hover {
            let t = self.dock_tile(i);
            let st = theme.text.small;
            let name = &self.dock[i].name;
            let tw = text.measure(st.font, st.size, name);
            let tip = Rect::new(t.x + t.w / 2 - (tw + 20) / 2, d.y - 34, tw + 20, 24);
            c.fill_round_rect(tip, 6, col.elevated);
            c.stroke_round_rect(tip, 6, 1, col.hairline_strong);
            let lm = text.metrics(st.font, st.size);
            text.draw(c, tip.x + 10, tip.y + (tip.h - lm.height) / 2, st.font, st.size, col.text, name);
        }
    }

    fn paint_switcher(&mut self, c: &mut Canvas, text: &mut TextEngine, theme: &Theme, sel: usize) {
        let list = self.switch_list();
        if list.is_empty() { return; }
        let col = theme.color;
        let r = self.switcher_rect(list.len());
        self.shadows.draw(c, r, 16, &Shadow { dx: 0, dy: 10, blur: 28, spread: 0, color: Color::black_a(160) }, Some(r.inset(16)));
        c.fill_round_rect(r, 16, col.elevated);
        c.stroke_round_rect(r, 16, 1, col.hairline_strong);
        let st = theme.text.small;
        let lm = text.metrics(st.font, st.size);
        for (i, id) in list.iter().enumerate() {
            let Some(w) = self.window(*id) else { continue };
            let cell = Rect::new(r.x + 12 + i as i32 * 104, r.y + 12, 104, 104);
            if i == sel { c.fill_round_rect(cell.inset(4), 12, col.accent_wash.mix(col.accent, 70)); }
            icons::draw(c, w.icon, Rect::new(cell.x + 34, cell.y + 18, 36, 36), if w.minimized { col.text_secondary } else { col.text });
            let tw = text.measure(st.font, st.size, &w.title).min(92);
            text.draw_ellipsis(c, cell.x + (cell.w - tw) / 2, cell.y + 70 + (18 - lm.height) / 2, 92, st.font, st.size, col.text, &w.title);
        }
    }
}
