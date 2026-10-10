// SPDX-License-Identifier: AGPL-3.0-only
//! Client side of a window: surface, client-side chrome, widget tree, and
//! the protocol glue (see [`crate::proto`]).
//!
//! Chrome: a 38-px title bar in the window's own colour, the title centred,
//! and three small monochrome round controls on the left — close, minimise,
//! zoom — that show their glyph only when the pointer is near and turn
//! red/grey on hover.  Focus is a brighter hairline border, a stronger shadow
//! (drawn by the server) and primary-coloured title text.  Double-clicking
//! the title bar zooms.

use alloc::collections::VecDeque;
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
use crate::proto::{alloc_id, new_surface, SharedSurface, ToClient, ToServer, WinId};
use crate::text::TextEngine;
use crate::theme::Theme;
use crate::ui::{Action, Ui};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chrome {
    Close,
    Minimize,
    Zoom,
}

/// What a window reports to its application after handling a message.
#[derive(Clone, Debug, PartialEq)]
pub enum AppEvent {
    Action(Action),
    /// A key the widgets did not consume (application shortcuts, terminals).
    Key(Event),
    /// Close button, Alt+F4 or the dock asked to close.
    CloseRequested,
    /// The server gave the window a new size.
    Resized(i32, i32),
    Focus(bool),
    /// A timer set with `Ctx::set_timer` fired.
    Timer(u32),
    /// A dialog opened by this app closed (see [`crate::app::DialogResult`]).
    Dialog(u32, crate::app::DialogResult),
}

/// What a [`Client`] gets while being driven by the session (runner side).
pub struct Cx<'a> {
    pub text: &'a mut TextEngine,
    pub theme: &'a Theme,
    pub out: &'a mut VecDeque<ToServer>,
    pub now: u64,
}

/// Runner-side interface: something that owns client windows and is driven
/// by a session loop.  Applications do not implement this; they implement
/// [`crate::app::Application`] and run inside an [`crate::app::AppHost`].
pub trait Client {
    /// Application id (see `AppInfo::id`), "" if none.
    fn app_id(&self) -> &str { "" }
    /// The window messages for `id` should go to (None: not ours).
    fn window_mut(&mut self, id: WinId) -> Option<&mut ClientWindow>;
    /// Ids of the app's live windows.
    fn window_ids(&self) -> Vec<WinId>;
    /// React to what the window reported.
    fn update(&mut self, id: WinId, events: &[AppEvent], cx: &mut Cx);
    /// Periodic work (timers, polling the system).
    fn tick(&mut self, _cx: &mut Cx) {}
    /// False once every window is destroyed.
    fn alive(&self) -> bool;
}

pub struct ClientWindow {
    pub id: WinId,
    pub title: String,
    pub icon: Icon,
    pub w: i32,
    pub h: i32,
    pub surface: SharedSurface,
    pub ui: Ui,
    pub focused: bool,
    pub destroyed: bool,
    chrome_hover: Option<Chrome>,
    controls_hover: bool,
    chrome_pressed: Option<Chrome>,
    ui_capture: bool,
    damage: Damage,
    full: bool,
    last_title_click: u64,
    now: u64,
    cursor: CursorShape,
}

const CTRL_R: f32 = 6.0;
const CTRL_X: [f32; 3] = [20.0, 40.0, 60.0];
const CTRLS: [Chrome; 3] = [Chrome::Close, Chrome::Minimize, Chrome::Zoom];

impl ClientWindow {
    /// Create a window and announce it to the server.
    pub fn new(out: &mut VecDeque<ToServer>, title: &str, icon: Icon, w: i32, h: i32, min: (i32, i32), resizable: bool, ui: Ui) -> ClientWindow {
        let id = alloc_id();
        let surface = new_surface(w, h);
        out.push_back(ToServer::Create { id, title: title.into(), icon, size: (w, h), min, resizable, surface: surface.clone() });
        ClientWindow {
            id, title: title.into(), icon, w, h, surface, ui, focused: false, destroyed: false,
            chrome_hover: None, controls_hover: false, chrome_pressed: None, ui_capture: false,
            damage: Damage::new(), full: true, last_title_click: 0, now: 0, cursor: CursorShape::Arrow,
        }
    }

    pub fn local(&self) -> Rect { Rect::from_size(self.w, self.h) }

    pub fn set_title(&mut self, title: &str, out: &mut VecDeque<ToServer>, theme: &Theme) {
        if self.title == title { return; }
        self.title = title.into();
        out.push_back(ToServer::SetTitle { id: self.id, title: title.into() });
        self.damage.add(Rect::new(0, 0, self.w, theme.metrics.titlebar_h));
    }

    pub fn destroy(&mut self, out: &mut VecDeque<ToServer>) {
        if !self.destroyed {
            self.destroyed = true;
            out.push_back(ToServer::Destroy { id: self.id });
        }
    }

    pub fn invalidate_all(&mut self) { self.full = true; }

    fn control_at(&self, x: i32, y: i32, theme: &Theme) -> Option<Chrome> {
        let cy = theme.metrics.titlebar_h as f32 / 2.0;
        for (i, &cx) in CTRL_X.iter().enumerate() {
            let (dx, dy) = (x as f32 + 0.5 - cx, y as f32 + 0.5 - cy);
            if dx * dx + dy * dy <= 9.5 * 9.5 { return Some(CTRLS[i]); }
        }
        None
    }

    fn controls_rect(&self, theme: &Theme) -> Rect { Rect::new(0, 0, 76, theme.metrics.titlebar_h) }

    fn invalidate_frame(&mut self, theme: &Theme) {
        let (w, h) = (self.w, self.h);
        self.damage.add(Rect::new(0, 0, w, theme.metrics.titlebar_h));
        self.damage.add(Rect::new(0, 0, 1, h));
        self.damage.add(Rect::new(w - 1, 0, 1, h));
        self.damage.add(Rect::new(0, h - 1, w, 1));
    }

    /// Handle one server message. Returns events for the application.
    pub fn handle(&mut self, msg: &ToClient, cx: &mut Cx) -> Vec<AppEvent> {
        let mut evs = Vec::new();
        let (text, theme) = (&mut *cx.text, cx.theme);
        self.now = cx.now;
        match *msg {
            ToClient::Configure { w, h, .. } => {
                if w != self.w || h != self.h {
                    self.w = w;
                    self.h = h;
                    self.full = true;
                    evs.push(AppEvent::Resized(w, h));
                }
            }
            ToClient::Focus { focused, .. } => {
                if focused != self.focused {
                    self.focused = focused;
                    self.invalidate_frame(theme);
                    self.ui.handle(if focused { &Event::FocusIn } else { &Event::FocusOut }, text, theme);
                    evs.push(AppEvent::Focus(focused));
                }
            }
            ToClient::CloseRequested { .. } => evs.push(AppEvent::CloseRequested),
            ToClient::Input { ev, .. } => self.input(&ev, text, theme, cx.out, &mut evs),
        }
        for a in self.ui.drain_actions() { evs.push(AppEvent::Action(a)); }
        evs
    }

    fn input(&mut self, ev: &Event, text: &mut TextEngine, theme: &Theme, out: &mut VecDeque<ToServer>, evs: &mut Vec<AppEvent>) {
        let th = theme.metrics.titlebar_h;
        if self.ui.menu_open() {
            self.ui.handle(ev, text, theme);
            return;
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
                let shape = if y >= th { self.ui.cursor_at(x, y) } else { CursorShape::Arrow };
                if shape != self.cursor {
                    self.cursor = shape;
                    out.push_back(ToServer::SetCursor { id: self.id, shape });
                }
            }
            Event::PointerDown { x, y, button } => {
                if y < th {
                    if let Some(c) = self.control_at(x, y, theme) {
                        self.chrome_pressed = Some(c);
                        let r = self.controls_rect(theme);
                        self.damage.add(r);
                    } else if button == MouseButton::Left {
                        if self.now.saturating_sub(self.last_title_click) < 400 {
                            out.push_back(ToServer::ToggleMaximize { id: self.id });
                            self.last_title_click = 0;
                        } else {
                            self.last_title_click = self.now;
                            out.push_back(ToServer::BeginMove { id: self.id });
                        }
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
                            Chrome::Close => evs.push(AppEvent::CloseRequested),
                            Chrome::Minimize => out.push_back(ToServer::Minimize { id: self.id }),
                            Chrome::Zoom => out.push_back(ToServer::ToggleMaximize { id: self.id }),
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
            Event::KeyDown { .. } => {
                if !self.ui.handle(ev, text, theme) { evs.push(AppEvent::Key(*ev)); }
            }
            _ => { self.ui.handle(ev, text, theme); }
        }
    }

    pub fn tick(&mut self, now_ms: u64, theme: &Theme) {
        self.now = now_ms;
        self.ui.tick(now_ms, theme);
    }

    /// Repaint damaged parts of the surface and announce them to the server.
    pub fn render(&mut self, text: &mut TextEngine, theme: &Theme, out: &mut VecDeque<ToServer>) {
        if self.destroyed { return; }
        let local = self.local();
        {
            let mut s = self.surface.borrow_mut();
            if s.width != local.w || s.height != local.h {
                s.resize(local.w, local.h);
                self.full = true;
            }
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
        if self.damage.is_empty() { return; }
        let rects = self.damage.take();
        for r in &rects { self.paint_rect(*r, text, theme); }
        out.push_back(ToServer::Damage { id: self.id, rects });
    }

    fn paint_rect(&mut self, r: Rect, text: &mut TextEngine, theme: &Theme) {
        let local = self.local();
        let tb = Rect::new(0, 0, local.w, theme.metrics.titlebar_h);
        let rad = theme.radius.window;
        let surface = self.surface.clone();
        let mut s = surface.borrow_mut();
        {
            let mut c = Canvas::new(s.view_mut());
            c.set_clip(r);
            if tb.intersects(&r) {
                paint_chrome(&mut c, text, theme, &self.title, tb, self.focused, self.chrome_hover, self.controls_hover, self.chrome_pressed);
            }
            let ur = r.intersect(&self.ui.rect());
            if !ur.is_empty() { self.ui.paint_rect(&mut c, text, theme, ur); }
            c.set_clip(r);
            let border = if self.focused { Color::white_a(30) } else { Color::white_a(18) };
            c.stroke_round_rect(local, rad, 1, border);
        }
        let stride = s.stride;
        mask_corners(&mut s.data, stride, local.w, local.h, r, rad);
    }
}

#[allow(clippy::too_many_arguments)]
fn paint_chrome(c: &mut Canvas, text: &mut TextEngine, theme: &Theme, title: &str, tb: Rect, focused: bool,
                hover: Option<Chrome>, near: bool, pressed: Option<Chrome>) {
    let col = &theme.color;
    c.fill_rect(tb, col.bg1);
    c.hline(tb.x, tb.right(), tb.bottom() - 1, col.hairline);
    let st = theme.text.body_strong;
    let lm = text.metrics(st.font, st.size);
    let max_w = tb.w - 2 * 90;
    let tw = text.measure(st.font, st.size, title).min(max_w.max(0));
    let fg = if focused { col.text } else { col.text_disabled };
    if max_w > 20 {
        text.draw_ellipsis(c, tb.x + (tb.w - tw) / 2, tb.y + (tb.h - lm.height) / 2, max_w, st.font, st.size, fg, title);
    }
    let cy = tb.h as f32 / 2.0;
    for (i, &cx) in CTRL_X.iter().enumerate() {
        let w = CTRLS[i];
        let hovered = hover == Some(w);
        let down = pressed == Some(w);
        let fill = match (w, hovered, down) {
            (Chrome::Close, true, false) => col.danger,
            (Chrome::Close, _, true) => col.danger.mix(Color::BLACK, 50),
            (_, true, false) => Color::white_a(80),
            (_, _, true) => Color::white_a(50),
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
                Chrome::Zoom => {
                    c.line(cx - 2.6, cy + 0.6, cx - 2.6, cy - 2.6, 1.2, g);
                    c.line(cx - 2.6, cy - 2.6, cx + 0.6, cy - 2.6, 1.2, g);
                    c.line(cx + 2.6, cy - 0.6, cx + 2.6, cy + 2.6, 1.2, g);
                    c.line(cx + 2.6, cy + 2.6, cx - 0.6, cy + 2.6, 1.2, g);
                }
            }
        }
    }
}

/// Re-apply the rounded window shape to freshly painted pixels in `r`.
fn mask_corners(data: &mut [u32], stride: usize, w: i32, h: i32, r: Rect, rad: i32) {
    let rf = rad as f32;
    let corners = [
        (Rect::new(0, 0, rad, rad), rf, rf),
        (Rect::new(w - rad, 0, rad, rad), w as f32 - rf, rf),
        (Rect::new(0, h - rad, rad, rad), rf, h as f32 - rf),
        (Rect::new(w - rad, h - rad, rad, rad), w as f32 - rf, h as f32 - rf),
    ];
    for (sq, cx, cy) in corners {
        let d = sq.intersect(&r);
        for y in d.y..d.bottom() {
            for x in d.x..d.right() {
                let (dx, dy) = (x as f32 + 0.5 - cx, y as f32 + 0.5 - cy);
                let cov = math::clamp01(rf - math::sqrt(dx * dx + dy * dy) + 0.5);
                let i = y as usize * stride + x as usize;
                data[i] = blend::scale(data[i], (cov * 255.0 + 0.5) as u32);
            }
        }
    }
}
