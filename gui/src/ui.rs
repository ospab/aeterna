// SPDX-License-Identifier: AGPL-3.0-only
//! Retained widget tree: layout, painting, input, damage.
//!
//! Why retained (and not immediate mode): the toolkit's main job on this
//! system is to produce *damage* — the compositor only recomposites what a
//! client reports as changed, and on a CPU-only renderer that is the
//! difference between redrawing a 16-px caret and a whole window.  A tree that
//! keeps bounds and per-widget state (hover, pressed, focus, caret, scroll)
//! knows exactly which rectangle a state change affects.  Widgets are a closed
//! `enum` (this is a vertically integrated system, not a plugin framework), so
//! there are no trait objects and no closures holding borrows: the tree lives
//! in a `Vec` arena, nodes are addressed by `NodeId`, and the application reads
//! typed [`Action`]s after each event (Elm-style messages).  The same shape
//! maps directly onto a future IPC protocol.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::canvas::Canvas;
use crate::color::Color;
use crate::damage::Damage;
use crate::event::{CursorShape, Event, Key, MouseButton};
use crate::geom::{Insets, Rect, Size};
use crate::icons::{self, Icon};
use crate::menu::{Menu, MenuItem, MenuResult};
use crate::shadow::ShadowCache;
use crate::text::TextEngine;
use crate::theme::{Theme, TypeStyle};

pub type NodeId = usize;

/// Size along one axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Length {
    /// Intrinsic size of the content.
    Hug,
    /// Exact pixels.
    Px(i32),
    /// Share of the remaining space (weight).
    Fill(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
    Start,
    Center,
    End,
    /// Cross axis: take the full size. Main axis: same as Start.
    Stretch,
    /// Main axis: distribute leftover space between children.
    SpaceBetween,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Axis {
    Row,
    Column,
    /// Children overlap, each placed by the container's alignment.
    Stack,
}

#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub width: Length,
    pub height: Length,
    pub padding: Insets,
    pub gap: i32,
    pub main: Align,
    pub cross: Align,
}

impl Default for Layout {
    fn default() -> Self {
        Layout { width: Length::Hug, height: Length::Hug, padding: Insets::ZERO, gap: 0, main: Align::Start, cross: Align::Stretch }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextRole {
    Body,
    Strong,
    Secondary,
    Caption,
    Title,
    Headline,
    Mono,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonKind {
    Primary,
    Secondary,
    Danger,
    Ghost,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BoxStyle {
    pub bg: Option<Color>,
    pub border: Option<Color>,
    pub radius: i32,
}

#[derive(Clone, Debug)]
pub struct Column {
    pub title: String,
    pub width: Length,
    pub align_right: bool,
}

impl Column {
    pub fn new(title: &str, width: Length) -> Column { Column { title: title.into(), width, align_right: false } }
    pub fn right(mut self) -> Self { self.align_right = true; self }
}

#[derive(Clone, Debug)]
pub struct ListItem {
    pub icon: Option<Icon>,
    pub icon_color: Option<Color>,
    pub cells: Vec<String>,
}

impl ListItem {
    pub fn new(cells: &[&str]) -> ListItem {
        ListItem { icon: None, icon_color: None, cells: cells.iter().map(|s| String::from(*s)).collect() }
    }
    pub fn icon(mut self, i: Icon, color: Option<Color>) -> Self { self.icon = Some(i); self.icon_color = color; self }
}

/// A coloured run of terminal text.
#[derive(Clone, Debug)]
pub struct Span {
    pub text: String,
    pub color: Color,
}

pub enum Widget {
    Container { axis: Axis, style: BoxStyle },
    Label { text: String, role: TextRole, color: Option<Color>, wrap: bool, center: bool },
    Button { label: String, kind: ButtonKind, icon: Option<Icon> },
    IconButton { icon: Icon },
    TextField { text: String, placeholder: String, caret: usize, anchor: usize, scroll: i32 },
    Checkbox { label: String, checked: bool },
    Toggle { on: bool, pos: f32, anim_from: f32, anim_start: u64, animating: bool },
    List { columns: Vec<Column>, header: bool, items: Vec<ListItem>, selected: Option<usize>, scroll: i32, row_h: i32 },
    Separator,
    Spacer,
    Icon { icon: Icon, size: i32, color: Option<Color> },
    Terminal { lines: Vec<Vec<Span>>, cursor: Option<(usize, usize)> },
    Progress { value: f32 },
}

/// Forced visual states (widget gallery, screenshots).
pub const FORCE_HOVER: u8 = 1;
pub const FORCE_PRESSED: u8 = 2;
pub const FORCE_FOCUS: u8 = 4;

pub struct Node {
    pub widget: Widget,
    pub layout: Layout,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
    pub bounds: Rect,
    pub enabled: bool,
    pub visible: bool,
    pub force: u8,
}

/// Something the user did, for the application to react to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Clicked(NodeId),
    Toggled(NodeId, bool),
    TextChanged(NodeId),
    Submitted(NodeId),
    Selected(NodeId, usize),
    Activated(NodeId, usize),
    MenuChosen(NodeId, usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Drag {
    None,
    TextSelect(NodeId),
    Thumb { list: NodeId, grab: i32 },
}

pub struct Ui {
    nodes: Vec<Node>,
    root: NodeId,
    rect: Rect,
    /// Background painted under the root.
    pub bg: Color,
    hover: Option<NodeId>,
    hover_row: Option<(NodeId, usize)>,
    pressed: Option<NodeId>,
    focus: Option<NodeId>,
    drag: Drag,
    damage: Damage,
    actions: Vec<Action>,
    needs_layout: bool,
    now: u64,
    caret_epoch: u64,
    caret_on: bool,
    menu: Option<(NodeId, Menu)>,
    shadows: ShadowCache,
    /// Whether the window holding this tree has keyboard focus.
    pub active: bool,
    last_click: (usize, usize, u64),
}

const FOCUS_OUTSET: i32 = 4;

impl Ui {
    pub fn new(axis: Axis, bg: Color) -> Ui {
        let root = Node {
            widget: Widget::Container { axis, style: BoxStyle::default() },
            layout: Layout { width: Length::Fill(1), height: Length::Fill(1), ..Layout::default() },
            parent: None, children: Vec::new(), bounds: Rect::default(), enabled: true, visible: true, force: 0,
        };
        Ui {
            nodes: vec![root], root: 0, rect: Rect::default(), bg,
            hover: None, hover_row: None, pressed: None, focus: None, drag: Drag::None,
            damage: Damage::new(), actions: Vec::new(), needs_layout: true,
            now: 0, caret_epoch: 0, caret_on: true, menu: None, shadows: ShadowCache::new(),
            active: true, last_click: (usize::MAX, 0, 0),
        }
    }

    pub fn root(&self) -> NodeId { self.root }
    pub fn rect(&self) -> Rect { self.rect }
    pub fn node(&self, id: NodeId) -> &Node { &self.nodes[id] }

    // ── Building ─────────────────────────────────────────────────────────

    pub fn add(&mut self, parent: NodeId, widget: Widget) -> NodeId {
        let layout = match &widget {
            Widget::Spacer => Layout { width: Length::Fill(1), height: Length::Fill(1), ..Layout::default() },
            Widget::List { .. } | Widget::Terminal { .. } => Layout { width: Length::Fill(1), height: Length::Fill(1), ..Layout::default() },
            _ => Layout::default(),
        };
        let id = self.nodes.len();
        self.nodes.push(Node { widget, layout, parent: Some(parent), children: Vec::new(), bounds: Rect::default(), enabled: true, visible: true, force: 0 });
        self.nodes[parent].children.push(id);
        self.needs_layout = true;
        id
    }

    pub fn container(&mut self, parent: NodeId, axis: Axis, style: BoxStyle) -> NodeId {
        self.add(parent, Widget::Container { axis, style })
    }
    pub fn row(&mut self, parent: NodeId) -> NodeId { self.container(parent, Axis::Row, BoxStyle::default()) }
    pub fn column(&mut self, parent: NodeId) -> NodeId { self.container(parent, Axis::Column, BoxStyle::default()) }
    pub fn stack(&mut self, parent: NodeId) -> NodeId { self.container(parent, Axis::Stack, BoxStyle::default()) }
    pub fn label(&mut self, parent: NodeId, text: &str, role: TextRole) -> NodeId {
        self.add(parent, Widget::Label { text: text.into(), role, color: None, wrap: false, center: false })
    }
    pub fn label_colored(&mut self, parent: NodeId, text: &str, role: TextRole, color: Color) -> NodeId {
        self.add(parent, Widget::Label { text: text.into(), role, color: Some(color), wrap: false, center: false })
    }
    pub fn paragraph(&mut self, parent: NodeId, text: &str, role: TextRole) -> NodeId {
        self.add(parent, Widget::Label { text: text.into(), role, color: None, wrap: true, center: false })
    }
    pub fn button(&mut self, parent: NodeId, label: &str, kind: ButtonKind) -> NodeId {
        self.add(parent, Widget::Button { label: label.into(), kind, icon: None })
    }
    pub fn icon_button(&mut self, parent: NodeId, icon: Icon) -> NodeId { self.add(parent, Widget::IconButton { icon }) }
    pub fn text_field(&mut self, parent: NodeId, text: &str, placeholder: &str) -> NodeId {
        let n = text.chars().count();
        self.add(parent, Widget::TextField { text: text.into(), placeholder: placeholder.into(), caret: n, anchor: n, scroll: 0 })
    }
    pub fn checkbox(&mut self, parent: NodeId, label: &str, checked: bool) -> NodeId {
        self.add(parent, Widget::Checkbox { label: label.into(), checked })
    }
    pub fn toggle(&mut self, parent: NodeId, on: bool) -> NodeId {
        let p = if on { 1.0 } else { 0.0 };
        self.add(parent, Widget::Toggle { on, pos: p, anim_from: p, anim_start: 0, animating: false })
    }
    pub fn list(&mut self, parent: NodeId, columns: Vec<Column>, header: bool, items: Vec<ListItem>, row_h: i32) -> NodeId {
        self.add(parent, Widget::List { columns, header, items, selected: None, scroll: 0, row_h })
    }
    pub fn separator(&mut self, parent: NodeId) -> NodeId { self.add(parent, Widget::Separator) }
    pub fn spacer(&mut self, parent: NodeId) -> NodeId { self.add(parent, Widget::Spacer) }
    pub fn icon(&mut self, parent: NodeId, icon: Icon, size: i32, color: Option<Color>) -> NodeId {
        self.add(parent, Widget::Icon { icon, size, color })
    }
    pub fn terminal(&mut self, parent: NodeId, lines: Vec<Vec<Span>>) -> NodeId {
        self.add(parent, Widget::Terminal { lines, cursor: None })
    }
    pub fn progress(&mut self, parent: NodeId, value: f32) -> NodeId { self.add(parent, Widget::Progress { value }) }

    /// Mutable layout props (marks the tree for relayout).
    pub fn layout_mut(&mut self, id: NodeId) -> &mut Layout {
        self.needs_layout = true;
        &mut self.nodes[id].layout
    }
    pub fn size(&mut self, id: NodeId, w: Length, h: Length) -> NodeId {
        let l = self.layout_mut(id);
        l.width = w;
        l.height = h;
        id
    }
    pub fn width(&mut self, id: NodeId, w: Length) -> NodeId { self.layout_mut(id).width = w; id }
    pub fn height(&mut self, id: NodeId, h: Length) -> NodeId { self.layout_mut(id).height = h; id }
    pub fn padding(&mut self, id: NodeId, p: Insets) -> NodeId { self.layout_mut(id).padding = p; id }
    pub fn gap(&mut self, id: NodeId, g: i32) -> NodeId { self.layout_mut(id).gap = g; id }
    pub fn align(&mut self, id: NodeId, main: Align, cross: Align) -> NodeId {
        let l = self.layout_mut(id);
        l.main = main;
        l.cross = cross;
        id
    }

    // ── State access ─────────────────────────────────────────────────────

    pub fn text(&self, id: NodeId) -> &str {
        match &self.nodes[id].widget {
            Widget::Label { text, .. } | Widget::TextField { text, .. } => text,
            Widget::Button { label, .. } | Widget::Checkbox { label, .. } => label,
            _ => "",
        }
    }

    pub fn set_text(&mut self, id: NodeId, s: &str) {
        let mut relayout = false;
        match &mut self.nodes[id].widget {
            Widget::Label { text, .. } => { if text != s { *text = s.into(); relayout = true; } }
            Widget::Button { label, .. } | Widget::Checkbox { label, .. } => { if label != s { *label = s.into(); relayout = true; } }
            Widget::TextField { text, caret, anchor, .. } => {
                *text = s.into();
                *caret = s.chars().count();
                *anchor = *caret;
            }
            _ => {}
        }
        if relayout && self.nodes[id].layout.width == Length::Hug { self.needs_layout = true; }
        self.invalidate(id);
    }

    pub fn set_label_color(&mut self, id: NodeId, c: Option<Color>) {
        if let Widget::Label { color, .. } = &mut self.nodes[id].widget { *color = c; }
        self.invalidate(id);
    }

    pub fn set_center(&mut self, id: NodeId, c: bool) {
        if let Widget::Label { center, .. } = &mut self.nodes[id].widget { *center = c; }
        self.invalidate(id);
    }

    pub fn checked(&self, id: NodeId) -> bool {
        match &self.nodes[id].widget {
            Widget::Checkbox { checked, .. } => *checked,
            Widget::Toggle { on, .. } => *on,
            _ => false,
        }
    }

    pub fn set_checked(&mut self, id: NodeId, v: bool) {
        match &mut self.nodes[id].widget {
            Widget::Checkbox { checked, .. } => *checked = v,
            Widget::Toggle { on, pos, animating, .. } => { *on = v; *pos = if v { 1.0 } else { 0.0 }; *animating = false; }
            _ => {}
        }
        self.invalidate(id);
    }

    pub fn selected(&self, id: NodeId) -> Option<usize> {
        if let Widget::List { selected, .. } = &self.nodes[id].widget { *selected } else { None }
    }

    pub fn set_selected(&mut self, id: NodeId, sel: Option<usize>) {
        if let Widget::List { selected, .. } = &mut self.nodes[id].widget { *selected = sel; }
        self.ensure_visible(id);
        self.invalidate(id);
    }

    pub fn list_items_mut(&mut self, id: NodeId) -> Option<&mut Vec<ListItem>> {
        self.invalidate(id);
        if let Widget::List { items, .. } = &mut self.nodes[id].widget { Some(items) } else { None }
    }

    pub fn set_terminal(&mut self, id: NodeId, lines: Vec<Vec<Span>>, cursor: Option<(usize, usize)>) {
        if let Widget::Terminal { lines: l, cursor: c } = &mut self.nodes[id].widget { *l = lines; *c = cursor; }
        self.invalidate(id);
    }

    pub fn set_progress(&mut self, id: NodeId, v: f32) {
        if let Widget::Progress { value } = &mut self.nodes[id].widget { *value = v; }
        self.invalidate(id);
    }

    pub fn set_enabled(&mut self, id: NodeId, e: bool) {
        self.nodes[id].enabled = e;
        self.invalidate(id);
    }

    pub fn set_visible(&mut self, id: NodeId, v: bool) {
        if self.nodes[id].visible != v {
            self.nodes[id].visible = v;
            self.needs_layout = true;
        }
    }

    pub fn set_style(&mut self, id: NodeId, s: BoxStyle) {
        if let Widget::Container { style, .. } = &mut self.nodes[id].widget { *style = s; }
        self.invalidate(id);
    }

    pub fn force_state(&mut self, id: NodeId, flags: u8) {
        self.nodes[id].force = flags;
        self.invalidate(id);
    }

    pub fn focused(&self) -> Option<NodeId> { self.focus }

    pub fn set_focus(&mut self, id: Option<NodeId>) {
        if self.focus == id { return; }
        if let Some(o) = self.focus { self.invalidate(o); }
        self.focus = id;
        if let Some(n) = id { self.invalidate(n); }
        self.caret_epoch = self.now;
        self.caret_on = true;
    }

    /// Select all text in a text field (e.g. on programmatic focus).
    pub fn select_all(&mut self, id: NodeId) {
        if let Widget::TextField { text, caret, anchor, .. } = &mut self.nodes[id].widget {
            *anchor = 0;
            *caret = text.chars().count();
        }
        self.invalidate(id);
    }

    /// Set the selection of a text field (char indices; caret is the moving end).
    pub fn set_selection(&mut self, id: NodeId, anchor_i: usize, caret_i: usize) {
        if let Widget::TextField { text, caret, anchor, .. } = &mut self.nodes[id].widget {
            let n = text.chars().count();
            *anchor = anchor_i.min(n);
            *caret = caret_i.min(n);
        }
        self.invalidate(id);
    }

    pub fn drain_actions(&mut self) -> Vec<Action> { core::mem::take(&mut self.actions) }

    /// Mark a node for repaint.
    pub fn invalidate(&mut self, id: NodeId) {
        let b = self.nodes[id].bounds.outset(FOCUS_OUTSET);
        self.damage.add(b);
    }

    pub fn invalidate_all(&mut self) { self.damage.add(self.rect); }

    pub fn has_damage(&self) -> bool { !self.damage.is_empty() || self.needs_layout }

    pub fn open_menu(&mut self, owner: NodeId, anchor: Rect, items: Vec<MenuItem>, text: &mut TextEngine, theme: &Theme) {
        self.close_menu();
        let m = Menu::new(items, anchor, self.rect, text, theme);
        self.damage.add(m.damage_rect());
        self.menu = Some((owner, m));
    }

    pub fn close_menu(&mut self) {
        if let Some((_, m)) = self.menu.take() { self.damage.add(m.damage_rect()); }
    }

    pub fn menu_open(&self) -> bool { self.menu.is_some() }

    /// Force a hover row (gallery / screenshots).
    pub fn set_hover_row(&mut self, list: NodeId, row: Option<usize>) {
        self.hover_row = row.map(|r| (list, r));
        self.invalidate(list);
    }
    pub fn set_menu_hover(&mut self, i: Option<usize>) {
        if let Some((_, m)) = &mut self.menu { m.hover = i; let d = m.damage_rect(); self.damage.add(d); }
    }

    // ── Layout ───────────────────────────────────────────────────────────

    /// Lay the tree out in `rect` (window coordinates).
    pub fn layout(&mut self, text: &mut TextEngine, theme: &Theme, rect: Rect) {
        self.rect = rect;
        let root = self.root;
        self.arrange(root, rect, text, theme);
        self.needs_layout = false;
        for id in 0..self.nodes.len() {
            if matches!(self.nodes[id].widget, Widget::List { .. }) { self.ensure_visible(id); }
        }
        self.damage.clear();
        self.damage.add(rect);
    }

    fn style_of(theme: &Theme, role: TextRole) -> TypeStyle {
        let t = &theme.text;
        match role {
            TextRole::Body | TextRole::Secondary => t.body,
            TextRole::Strong => t.body_strong,
            TextRole::Caption => t.caption,
            TextRole::Title => t.title,
            TextRole::Headline => t.headline,
            TextRole::Mono => t.mono,
        }
    }

    /// Intrinsic size; `avail_w` lets wrapping labels compute their height.
    fn measure(&self, id: NodeId, avail_w: Option<i32>, text: &mut TextEngine, theme: &Theme) -> Size {
        let n = &self.nodes[id];
        let m = &theme.metrics;
        let pad = n.layout.padding;
        let inner_w = match n.layout.width { Length::Px(w) => Some(w), _ => avail_w }.map(|w| w - pad.horizontal());
        let mut s = match &n.widget {
            Widget::Container { axis, .. } => {
                let kids: Vec<NodeId> = n.children.iter().copied().filter(|&c| self.nodes[c].visible).collect();
                let mut main = 0;
                let mut cross = 0;
                for (i, &c) in kids.iter().enumerate() {
                    let child_w = match axis { Axis::Column | Axis::Stack => inner_w, Axis::Row => None };
                    let cs = self.resolved(c, child_w, text, theme);
                    match axis {
                        Axis::Row => { main += cs.w; cross = cross.max(cs.h); }
                        Axis::Column => { main += cs.h; cross = cross.max(cs.w); }
                        Axis::Stack => { main = main.max(cs.w); cross = cross.max(cs.h); }
                    }
                    if i > 0 && *axis != Axis::Stack { main += n.layout.gap; }
                }
                match axis {
                    Axis::Row | Axis::Stack => Size::new(main, cross),
                    Axis::Column => Size::new(cross, main),
                }
            }
            Widget::Label { text: s, role, wrap, .. } => {
                let st = Self::style_of(theme, *role);
                let w = text.measure(st.font, st.size, s);
                if *wrap {
                    let maxw = inner_w.unwrap_or(360).max(40);
                    let lines = text.wrap(st.font, st.size, s, maxw).len() as i32;
                    Size::new(w.min(maxw), lines * st.line)
                } else {
                    Size::new(w, st.line)
                }
            }
            Widget::Button { label, icon, kind } => {
                let st = if matches!(kind, ButtonKind::Primary | ButtonKind::Danger) { theme.text.body_strong } else { theme.text.body };
                let mut w = text.measure(st.font, st.size, label) + 28;
                if icon.is_some() { w += 22; }
                Size::new(w.max(72), m.control_h)
            }
            Widget::IconButton { .. } => Size::new(m.control_h, m.control_h),
            Widget::TextField { .. } => Size::new(180, m.control_h),
            Widget::Checkbox { label, .. } => {
                let st = theme.text.body;
                Size::new(16 + 8 + text.measure(st.font, st.size, label), st.line.max(18))
            }
            Widget::Toggle { .. } => Size::new(34, 20),
            Widget::List { .. } => Size::new(200, 120),
            Widget::Separator => Size::new(1, 1),
            Widget::Spacer => Size::new(0, 0),
            Widget::Icon { size, .. } => Size::new(*size, *size),
            Widget::Terminal { .. } => Size::new(320, 200),
            Widget::Progress { .. } => Size::new(120, 6),
        };
        s.w += pad.horizontal();
        s.h += pad.vertical();
        s
    }

    /// Measured size with Px overrides applied.
    fn resolved(&self, id: NodeId, avail_w: Option<i32>, text: &mut TextEngine, theme: &Theme) -> Size {
        let l = self.nodes[id].layout;
        let mut s = self.measure(id, avail_w, text, theme);
        if let Length::Px(w) = l.width { s.w = w; }
        if let Length::Px(h) = l.height { s.h = h; }
        s
    }

    fn arrange(&mut self, id: NodeId, rect: Rect, text: &mut TextEngine, theme: &Theme) {
        self.nodes[id].bounds = rect;
        let (axis, lay) = match &self.nodes[id].widget {
            Widget::Container { axis, .. } => (*axis, self.nodes[id].layout),
            _ => return,
        };
        let content = rect.inset_by(lay.padding);
        let kids: Vec<NodeId> = self.nodes[id].children.iter().copied().filter(|&c| self.nodes[c].visible).collect();
        if kids.is_empty() { return; }

        if axis == Axis::Stack {
            for &c in &kids {
                let cl = self.nodes[c].layout;
                let s = self.resolved(c, Some(content.w), text, theme);
                let w = if matches!(cl.width, Length::Fill(_)) { content.w } else { s.w.min(content.w) };
                let h = if matches!(cl.height, Length::Fill(_)) { content.h } else { s.h.min(content.h) };
                let x = content.x + align_off(lay.main, content.w - w);
                let y = content.y + align_off(lay.cross, content.h - h);
                self.arrange(c, Rect::new(x, y, w, h), text, theme);
            }
            return;
        }

        let row = axis == Axis::Row;
        let main_len = if row { content.w } else { content.h };
        let cross_len = if row { content.h } else { content.w };
        let gaps = lay.gap * (kids.len() as i32 - 1);

        // Cross sizes first (columns need the width to measure wrapped text).
        let mut cross = Vec::with_capacity(kids.len());
        let mut mains = Vec::with_capacity(kids.len());
        let mut weights = 0u32;
        let mut fixed = 0;
        for &c in &kids {
            let cl = self.nodes[c].layout;
            let (cl_main, cl_cross) = if row { (cl.width, cl.height) } else { (cl.height, cl.width) };
            let pre = self.resolved(c, if row { None } else { Some(content.w) }, text, theme);
            let cs = match cl_cross {
                Length::Px(v) => v,
                Length::Fill(_) => cross_len,
                Length::Hug => if lay.cross == Align::Stretch { cross_len } else { if row { pre.h } else { pre.w }.min(cross_len) },
            };
            cross.push(cs);
            let s = if row { pre } else { self.resolved(c, Some(cs), text, theme) };
            let ms = match cl_main {
                Length::Px(v) => v,
                Length::Hug => if row { s.w } else { s.h },
                Length::Fill(w) => { weights += w as u32; 0 }
            };
            fixed += ms;
            mains.push(ms);
        }
        let mut rest = (main_len - gaps - fixed).max(0);
        if weights > 0 {
            let total = rest;
            let mut wleft = weights;
            for (i, &c) in kids.iter().enumerate() {
                let cl = self.nodes[c].layout;
                if let Length::Fill(w) = if row { cl.width } else { cl.height } {
                    let share = if wleft == w as u32 { rest } else { total * w as i32 / weights as i32 };
                    mains[i] = share;
                    rest -= share;
                    wleft -= w as u32;
                }
            }
            rest = 0;
        }
        let (mut pos, extra_gap) = match lay.main {
            Align::Center => (rest / 2, 0),
            Align::End => (rest, 0),
            Align::SpaceBetween if kids.len() > 1 => (0, rest / (kids.len() as i32 - 1)),
            _ => (0, 0),
        };
        for (i, &c) in kids.iter().enumerate() {
            let co = align_off(lay.cross, cross_len - cross[i]);
            let r = if row {
                Rect::new(content.x + pos, content.y + co, mains[i], cross[i])
            } else {
                Rect::new(content.x + co, content.y + pos, cross[i], mains[i])
            };
            self.arrange(c, r, text, theme);
            pos += mains[i] + lay.gap + extra_gap;
        }
    }

    // ── Hit testing ──────────────────────────────────────────────────────

    fn interactive(w: &Widget) -> bool {
        matches!(w, Widget::Button { .. } | Widget::IconButton { .. } | Widget::TextField { .. } | Widget::Checkbox { .. } | Widget::Toggle { .. } | Widget::List { .. })
    }

    fn hit(&self, id: NodeId, x: i32, y: i32) -> Option<NodeId> {
        let n = &self.nodes[id];
        if !n.visible || !n.bounds.contains(x, y) { return None; }
        for &c in n.children.iter().rev() {
            if let Some(h) = self.hit(c, x, y) { return Some(h); }
        }
        if Self::interactive(&n.widget) { Some(id) } else { None }
    }

    pub fn hit_test(&self, x: i32, y: i32) -> Option<NodeId> { self.hit(self.root, x, y) }

    pub fn cursor_at(&self, x: i32, y: i32) -> CursorShape {
        match self.hit_test(x, y).map(|h| &self.nodes[h].widget) {
            Some(Widget::TextField { .. }) => CursorShape::Text,
            _ => CursorShape::Arrow,
        }
    }

    fn focus_order(&self, id: NodeId, out: &mut Vec<NodeId>) {
        let n = &self.nodes[id];
        if !n.visible { return; }
        if n.enabled && Self::interactive(&n.widget) { out.push(id); }
        for &c in &n.children { self.focus_order(c, out); }
    }

    // ── List geometry ────────────────────────────────────────────────────

    fn list_rows_rect(&self, id: NodeId) -> Rect {
        let n = &self.nodes[id];
        if let Widget::List { header, .. } = &n.widget {
            let b = n.bounds;
            let hh = if *header { 28 } else { 0 };
            Rect::new(b.x, b.y + hh, b.w, b.h - hh)
        } else { n.bounds }
    }

    fn list_scroll_max(&self, id: NodeId) -> i32 {
        if let Widget::List { items, row_h, .. } = &self.nodes[id].widget {
            let rows = self.list_rows_rect(id);
            (items.len() as i32 * row_h + 8 - rows.h).max(0)
        } else { 0 }
    }

    /// Thumb rect (if the list overflows).
    fn list_thumb(&self, id: NodeId) -> Option<Rect> {
        if let Widget::List { scroll, .. } = &self.nodes[id].widget {
            let max = self.list_scroll_max(id);
            if max == 0 { return None; }
            let rows = self.list_rows_rect(id);
            let track = rows.inset(3);
            let content = rows.h + max;
            let th = (track.h * rows.h / content).max(24).min(track.h);
            let ty = track.y + (track.h - th) * *scroll / max;
            Some(Rect::new(rows.right() - 9, ty, 6, th))
        } else { None }
    }

    fn ensure_visible(&mut self, id: NodeId) {
        let rows = self.list_rows_rect(id);
        if rows.h <= 0 { return; }
        let max = self.list_scroll_max(id);
        if let Widget::List { selected: Some(s), scroll, row_h, .. } = &mut self.nodes[id].widget {
            let top = *s as i32 * *row_h + 4;
            if top < *scroll { *scroll = top - 4; }
            if top + *row_h > *scroll + rows.h { *scroll = top + *row_h + 4 - rows.h; }
            *scroll = (*scroll).clamp(0, max);
        }
    }

    fn list_row_at(&self, id: NodeId, y: i32) -> Option<usize> {
        let rows = self.list_rows_rect(id);
        if let Widget::List { items, scroll, row_h, .. } = &self.nodes[id].widget {
            if y < rows.y || y >= rows.bottom() { return None; }
            let i = (y - rows.y - 4 + scroll) / row_h;
            if y - rows.y - 4 + scroll >= 0 && (i as usize) < items.len() { return Some(i as usize); }
        }
        None
    }

    // ── Events ───────────────────────────────────────────────────────────

    /// Feed an event (window coordinates). Returns true if consumed.
    pub fn handle(&mut self, ev: &Event, text: &mut TextEngine, theme: &Theme) -> bool {
        if self.needs_layout { let r = self.rect; self.layout(text, theme, r); }

        // An open menu grabs all input.
        if let Some((owner, m)) = &mut self.menu {
            let owner = *owner;
            let mut dirty = false;
            let res = m.handle(ev, &mut dirty);
            if dirty { let d = m.damage_rect(); self.damage.add(d); }
            match res {
                MenuResult::None => {}
                MenuResult::Chosen(i) => { self.close_menu(); self.actions.push(Action::MenuChosen(owner, i)); }
                MenuResult::Dismissed => { self.close_menu(); }
            }
            return true;
        }

        match *ev {
            Event::PointerMove { x, y } => {
                match self.drag {
                    Drag::TextSelect(id) => { self.field_caret_to(id, x, text, theme, true); return true; }
                    Drag::Thumb { list, grab } => { self.thumb_drag(list, y - grab); return true; }
                    Drag::None => {}
                }
                let h = self.hit_test(x, y);
                if h != self.hover {
                    if let Some(o) = self.hover { self.invalidate(o); }
                    if let Some(n) = h { self.invalidate(n); }
                    self.hover = h;
                }
                let row = h.and_then(|id| match self.nodes[id].widget {
                    Widget::List { .. } => self.list_row_at(id, y).map(|r| (id, r)),
                    _ => None,
                });
                if row != self.hover_row {
                    if let Some((l, _)) = self.hover_row { self.invalidate(l); }
                    if let Some((l, _)) = row { self.invalidate(l); }
                    self.hover_row = row;
                }
                h.is_some()
            }
            Event::PointerLeave => {
                if let Some(o) = self.hover.take() { self.invalidate(o); }
                if let Some((l, _)) = self.hover_row.take() { self.invalidate(l); }
                true
            }
            Event::PointerDown { x, y, button: MouseButton::Left } => {
                let h = self.hit_test(x, y).filter(|&id| self.nodes[id].enabled);
                self.set_focus(h);
                self.pressed = h;
                let id = match h { Some(id) => id, None => return false };
                self.invalidate(id);
                match self.nodes[id].widget {
                    Widget::TextField { .. } => {
                        self.field_caret_to(id, x, text, theme, false);
                        self.drag = Drag::TextSelect(id);
                    }
                    Widget::List { .. } => {
                        if let Some(t) = self.list_thumb(id) {
                            if Rect::new(t.x - 4, t.y, t.w + 8, t.h).contains(x, y) {
                                self.drag = Drag::Thumb { list: id, grab: y - t.y };
                                return true;
                            }
                        }
                        if let Some(r) = self.list_row_at(id, y) {
                            if let Widget::List { selected, .. } = &mut self.nodes[id].widget { *selected = Some(r); }
                            self.actions.push(Action::Selected(id, r));
                            let (lid, lr, lt) = self.last_click;
                            if lid == id && lr == r && self.now.saturating_sub(lt) < 450 {
                                self.actions.push(Action::Activated(id, r));
                                self.last_click = (usize::MAX, 0, 0);
                            } else {
                                self.last_click = (id, r, self.now);
                            }
                        }
                    }
                    _ => {}
                }
                true
            }
            Event::PointerUp { x, y, button: MouseButton::Left } => {
                self.drag = Drag::None;
                let p = self.pressed.take();
                if let Some(id) = p {
                    self.invalidate(id);
                    if self.hit_test(x, y) == Some(id) && self.nodes[id].enabled { self.activate(id); }
                }
                p.is_some()
            }
            Event::Wheel { x, y, dy } => {
                let mut t = self.hit_test(x, y);
                while let Some(id) = t {
                    if let Widget::List { .. } = self.nodes[id].widget { break; }
                    t = self.nodes[id].parent;
                }
                if let Some(id) = t {
                    let max = self.list_scroll_max(id);
                    if let Widget::List { scroll, row_h, .. } = &mut self.nodes[id].widget {
                        *scroll = (*scroll - dy * *row_h).clamp(0, max);
                    }
                    self.invalidate(id);
                    return true;
                }
                false
            }
            Event::KeyDown { key, mods, text: ch } => self.key(key, mods, ch, text, theme),
            Event::FocusIn => { self.active = true; if let Some(f) = self.focus { self.invalidate(f); } true }
            Event::FocusOut => {
                self.active = false;
                if let Some(f) = self.focus { self.invalidate(f); }
                if let Some(o) = self.hover.take() { self.invalidate(o); }
                true
            }
            _ => false,
        }
    }

    fn activate(&mut self, id: NodeId) {
        let now = self.now;
        match &mut self.nodes[id].widget {
            Widget::Button { .. } | Widget::IconButton { .. } => self.actions.push(Action::Clicked(id)),
            Widget::Checkbox { checked, .. } => {
                *checked = !*checked;
                self.actions.push(Action::Toggled(id, *checked));
            }
            Widget::Toggle { on, pos, anim_from, anim_start, animating } => {
                *on = !*on;
                *anim_from = *pos;
                *anim_start = now;
                *animating = true;
                self.actions.push(Action::Toggled(id, *on));
            }
            _ => {}
        }
        self.invalidate(id);
    }

    fn thumb_drag(&mut self, list: NodeId, thumb_y: i32) {
        let max = self.list_scroll_max(list);
        let rows = self.list_rows_rect(list);
        if let Some(t) = self.list_thumb(list) {
            let track = rows.inset(3);
            let span = (track.h - t.h).max(1);
            let s = ((thumb_y - track.y) * max / span).clamp(0, max);
            if let Widget::List { scroll, .. } = &mut self.nodes[list].widget { *scroll = s; }
            self.invalidate(list);
        }
    }

    fn field_inner(&self, id: NodeId) -> Rect { self.nodes[id].bounds.inset_by(Insets::xy(9, 0)) }

    fn field_caret_to(&mut self, id: NodeId, x: i32, text: &mut TextEngine, theme: &Theme, extend: bool) {
        let inner = self.field_inner(id);
        let st = theme.text.body;
        if let Widget::TextField { text: s, caret, anchor, scroll, .. } = &mut self.nodes[id].widget {
            let i = text.hit_index(st.font, st.size, s, x - inner.x + *scroll);
            *caret = i;
            if !extend { *anchor = i; }
        }
        self.caret_epoch = self.now;
        self.caret_on = true;
        self.invalidate(id);
    }

    fn key(&mut self, key: Key, mods: crate::event::Modifiers, ch: Option<char>, text: &mut TextEngine, theme: &Theme) -> bool {
        if key == Key::Tab {
            let mut order = Vec::new();
            self.focus_order(self.root, &mut order);
            if order.is_empty() { return false; }
            let cur = self.focus.and_then(|f| order.iter().position(|&o| o == f));
            let n = order.len();
            let next = match cur {
                None => if mods.shift { n - 1 } else { 0 },
                Some(i) => if mods.shift { (i + n - 1) % n } else { (i + 1) % n },
            };
            self.set_focus(Some(order[next]));
            if let Widget::TextField { .. } = self.nodes[order[next]].widget { self.select_all(order[next]); }
            return true;
        }
        let id = match self.focus { Some(f) => f, None => return false };
        if !self.nodes[id].enabled { return false; }
        let is_field = matches!(self.nodes[id].widget, Widget::TextField { .. });
        if is_field { return self.field_key(id, key, mods, ch, text, theme); }
        match (&self.nodes[id].widget, key) {
            (Widget::Button { .. } | Widget::IconButton { .. }, Key::Enter | Key::Char(' ')) => { self.activate(id); true }
            (Widget::Checkbox { .. } | Widget::Toggle { .. }, Key::Char(' ') | Key::Enter) => { self.activate(id); true }
            (Widget::List { items, selected, row_h, .. }, _) => {
                let n = items.len();
                if n == 0 { return false; }
                let page = (self.list_rows_rect(id).h / *row_h).max(1) as usize;
                let cur = *selected;
                let new = match key {
                    Key::Down => Some(cur.map_or(0, |s| (s + 1).min(n - 1))),
                    Key::Up => Some(cur.map_or(0, |s| s.saturating_sub(1))),
                    Key::Home => Some(0),
                    Key::End => Some(n - 1),
                    Key::PageDown => Some(cur.map_or(0, |s| (s + page).min(n - 1))),
                    Key::PageUp => Some(cur.map_or(0, |s| s.saturating_sub(page))),
                    Key::Enter => { if let Some(s) = cur { self.actions.push(Action::Activated(id, s)); } return true; }
                    _ => None,
                };
                match new {
                    Some(s) => {
                        self.set_selected(id, Some(s));
                        self.actions.push(Action::Selected(id, s));
                        true
                    }
                    None => false,
                }
            }
            _ => false,
        }
    }

    fn field_key(&mut self, id: NodeId, key: Key, mods: crate::event::Modifiers, ch: Option<char>, text: &mut TextEngine, theme: &Theme) -> bool {
        let mut changed = false;
        let mut submit = false;
        if let Widget::TextField { text: s, caret, anchor, .. } = &mut self.nodes[id].widget {
            let len = s.chars().count();
            let (lo, hi) = (*caret.min(anchor), *caret.max(anchor));
            let byte = |s: &str, i: usize| s.char_indices().nth(i).map_or(s.len(), |(b, _)| b);
            let delete_sel = |s: &mut String, caret: &mut usize, anchor: &mut usize| -> bool {
                if lo == hi { return false; }
                let (a, b) = (byte(s, lo), byte(s, hi));
                s.replace_range(a..b, "");
                *caret = lo;
                *anchor = lo;
                true
            };
            match key {
                Key::Backspace => {
                    if !delete_sel(s, caret, anchor) && *caret > 0 {
                        let (a, b) = (byte(s, *caret - 1), byte(s, *caret));
                        s.replace_range(a..b, "");
                        *caret -= 1;
                        *anchor = *caret;
                    }
                    changed = true;
                }
                Key::Delete => {
                    if !delete_sel(s, caret, anchor) && *caret < len {
                        let (a, b) = (byte(s, *caret), byte(s, *caret + 1));
                        s.replace_range(a..b, "");
                    }
                    changed = true;
                }
                Key::Left => {
                    if !mods.shift && lo != hi { *caret = lo; } else if *caret > 0 { *caret -= 1; }
                    if !mods.shift { *anchor = *caret; }
                }
                Key::Right => {
                    if !mods.shift && lo != hi { *caret = hi; } else if *caret < len { *caret += 1; }
                    if !mods.shift { *anchor = *caret; }
                }
                Key::Home => { *caret = 0; if !mods.shift { *anchor = 0; } }
                Key::End => { *caret = len; if !mods.shift { *anchor = len; } }
                Key::Enter => submit = true,
                Key::Char('a') if mods.ctrl => { *anchor = 0; *caret = len; }
                _ => {
                    if let Some(c) = ch {
                        if !c.is_control() && !mods.ctrl {
                            delete_sel(s, caret, anchor);
                            let b = byte(s, *caret);
                            s.insert(b, c);
                            *caret += 1;
                            *anchor = *caret;
                            changed = true;
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }
        }
        self.scroll_field_to_caret(id, text, theme);
        if changed { self.actions.push(Action::TextChanged(id)); }
        if submit { self.actions.push(Action::Submitted(id)); }
        self.caret_epoch = self.now;
        self.caret_on = true;
        self.invalidate(id);
        true
    }

    fn scroll_field_to_caret(&mut self, id: NodeId, text: &mut TextEngine, theme: &Theme) {
        let inner = self.field_inner(id);
        let st = theme.text.body;
        if let Widget::TextField { text: s, caret, scroll, .. } = &mut self.nodes[id].widget {
            let stops = text.caret_stops(st.font, st.size, s);
            let cx = stops[(*caret).min(stops.len() - 1)];
            let total = *stops.last().unwrap();
            if cx - *scroll > inner.w - 2 { *scroll = cx - inner.w + 2; }
            if cx - *scroll < 0 { *scroll = cx; }
            *scroll = (*scroll).min((total - inner.w + 2).max(0)).max(0);
        }
    }

    /// Advance time: caret blink and animations.
    pub fn tick(&mut self, now_ms: u64, theme: &Theme) {
        self.now = now_ms;
        if let Some(f) = self.focus {
            if let Widget::TextField { .. } = self.nodes[f].widget {
                let on = self.active && ((now_ms.saturating_sub(self.caret_epoch)) / theme.motion.caret_blink as u64) % 2 == 0;
                if on != self.caret_on { self.caret_on = on; self.invalidate(f); }
            }
        }
        let dur = theme.motion.normal as f32;
        let mut dirty = Vec::new();
        for (i, n) in self.nodes.iter_mut().enumerate() {
            if let Widget::Toggle { on, pos, anim_from, anim_start, animating } = &mut n.widget {
                if *animating {
                    let t = (now_ms.saturating_sub(*anim_start)) as f32 / dur;
                    let target = if *on { 1.0 } else { 0.0 };
                    let e = crate::math::ease_out(t);
                    *pos = *anim_from + (target - *anim_from) * e;
                    if t >= 1.0 { *pos = target; *animating = false; }
                    dirty.push(i);
                }
            }
        }
        for i in dirty { self.invalidate(i); }
    }

    // ── Painting ─────────────────────────────────────────────────────────

    /// Repaint whatever is damaged (laying out first if needed). Returns the
    /// repainted rectangles (window coordinates).
    pub fn render(&mut self, c: &mut Canvas, text: &mut TextEngine, theme: &Theme) -> Vec<Rect> {
        if self.needs_layout { let r = self.rect; self.layout(text, theme, r); }
        self.damage.clip(self.rect);
        let rects = self.damage.take();
        for r in &rects {
            self.paint_rect(c, text, theme, *r);
        }
        rects
    }

    /// Lay out if needed and hand over pending damage without painting
    /// (for owners that merge it with their own damage, e.g. window chrome).
    pub fn take_damage(&mut self, text: &mut TextEngine, theme: &Theme) -> Vec<Rect> {
        if self.needs_layout { let r = self.rect; self.layout(text, theme, r); }
        self.damage.clip(self.rect);
        self.damage.take()
    }

    /// Paint everything inside `clip` (window coordinates).
    pub fn paint_rect(&mut self, c: &mut Canvas, text: &mut TextEngine, theme: &Theme, clip: Rect) {
        let saved = c.save();
        c.clip_to(clip);
        c.fill_rect(clip, self.bg);
        self.paint_node(self.root, c, text, theme, clip);
        if let Some((_, m)) = &self.menu {
            if m.damage_rect().intersects(&clip) { m.paint(c, text, theme, &mut self.shadows); }
        }
        c.restore(saved);
    }

    fn paint_node(&self, id: NodeId, c: &mut Canvas, text: &mut TextEngine, theme: &Theme, clip: Rect) {
        let n = &self.nodes[id];
        if !n.visible || !n.bounds.outset(FOCUS_OUTSET).intersects(&clip) { return; }
        self.paint_widget(id, c, text, theme);
        for &ch in &n.children { self.paint_node(ch, c, text, theme, clip); }
    }

    fn state(&self, id: NodeId) -> (bool, bool, bool) {
        let f = self.nodes[id].force;
        let hover = self.hover == Some(id) || f & FORCE_HOVER != 0;
        let pressed = (self.pressed == Some(id) && self.hover == Some(id)) || f & FORCE_PRESSED != 0;
        let focus = (self.focus == Some(id) && self.active) || f & FORCE_FOCUS != 0;
        (hover, pressed, focus)
    }

    fn focus_ring(c: &mut Canvas, r: Rect, radius: i32, theme: &Theme) {
        c.stroke_round_rect(r.outset(3), radius + 3, theme.metrics.focus_ring_w, theme.color.focus_ring);
    }

    fn paint_widget(&self, id: NodeId, c: &mut Canvas, text: &mut TextEngine, theme: &Theme) {
        let n = &self.nodes[id];
        let b = n.bounds;
        let col = &theme.color;
        let enabled = n.enabled;
        let (hover, pressed, focus) = self.state(id);
        match &n.widget {
            Widget::Container { style, .. } => {
                if let Some(bg) = style.bg { c.fill_round_rect(b, style.radius, bg); }
                if let Some(bc) = style.border { c.stroke_round_rect(b, style.radius, 1, bc); }
            }
            Widget::Label { text: s, role, color, wrap, center } => {
                let st = Self::style_of(theme, *role);
                let fg = color.unwrap_or(match role {
                    TextRole::Secondary | TextRole::Caption => col.text_secondary,
                    _ => col.text,
                });
                let fg = if enabled { fg } else { col.text_disabled };
                let lm = text.metrics(st.font, st.size);
                let inner = b.inset_by(n.layout.padding);
                let saved = c.save();
                c.clip_to(b);
                if *wrap {
                    let lines = text.wrap(st.font, st.size, s, inner.w.max(1));
                    for (i, r) in lines.iter().enumerate() {
                        let y = inner.y + i as i32 * st.line + (st.line - lm.height) / 2;
                        text.draw(c, inner.x, y, st.font, st.size, fg, &s[r.clone()]);
                    }
                } else {
                    let y = inner.y + (inner.h - lm.height) / 2;
                    let x = if *center { inner.x + (inner.w - text.measure(st.font, st.size, s)).max(0) / 2 } else { inner.x };
                    if *role == TextRole::Mono {
                        text.draw_mono(c, x, y, st.font, st.size, fg, s);
                    } else {
                        text.draw_ellipsis(c, x, y, inner.w, st.font, st.size, fg, s);
                    }
                }
                c.restore(saved);
            }
            Widget::Button { label, kind, icon } => {
                let r = theme.radius.md;
                let (bg, fg, border) = match kind {
                    ButtonKind::Primary => (if pressed { col.accent_pressed } else if hover { col.accent_hover } else { col.accent }, col.text_on_accent, None),
                    ButtonKind::Danger => (if pressed { col.danger.mix(Color::BLACK, 40) } else if hover { col.danger.mix(Color::WHITE, 20) } else { col.danger }, col.text_on_accent, None),
                    ButtonKind::Secondary => (if pressed { col.control_pressed } else if hover { col.control_hover } else { col.control }, col.text, Some(col.hairline)),
                    ButtonKind::Ghost => (if pressed { col.hover.fade(180) } else if hover { col.hover } else { Color::TRANSPARENT }, col.text, None),
                };
                let (bg, fg) = if enabled { (bg, fg) } else {
                    (if *kind == ButtonKind::Ghost { Color::TRANSPARENT } else { col.control.fade(140) }, col.text_disabled)
                };
                c.fill_round_rect(b, r, bg);
                if let Some(bc) = border { c.stroke_round_rect(b, r, 1, bc); }
                let st = if matches!(kind, ButtonKind::Primary | ButtonKind::Danger) { theme.text.body_strong } else { theme.text.body };
                let lm = text.metrics(st.font, st.size);
                let tw = text.measure(st.font, st.size, label);
                let iw = if icon.is_some() { 22 } else { 0 };
                let x = b.x + (b.w - tw - iw) / 2;
                if let Some(ic) = icon { icons::draw(c, *ic, Rect::new(x, b.y + (b.h - 16) / 2, 16, 16), fg); }
                text.draw(c, x + iw, b.y + (b.h - lm.height) / 2, st.font, st.size, fg, label);
                if focus { Self::focus_ring(c, b, r, theme); }
            }
            Widget::IconButton { icon } => {
                let r = theme.radius.md;
                let bg = if pressed { col.hover.fade(180) } else if hover { col.hover } else { Color::TRANSPARENT };
                c.fill_round_rect(b, r, bg);
                let fg = if !enabled { col.text_disabled } else if hover { col.text } else { col.text_secondary };
                icons::draw(c, *icon, Rect::new(b.x + (b.w - 16) / 2, b.y + (b.h - 16) / 2, 16, 16), fg);
                if focus { Self::focus_ring(c, b, r, theme); }
            }
            Widget::TextField { text: s, placeholder, caret, anchor, scroll } => {
                let r = theme.radius.md;
                c.fill_round_rect(b, r, col.field);
                let border = if focus { col.accent } else if hover && enabled { col.hairline_strong.mix(Color::WHITE, 40) } else { col.hairline_strong };
                c.stroke_round_rect(b, r, 1, border);
                if focus { c.stroke_round_rect(b.outset(2), r + 2, 2, col.accent_wash); }
                let inner = self.field_inner(id);
                let st = theme.text.body;
                let lm = text.metrics(st.font, st.size);
                let ty = b.y + (b.h - lm.height) / 2;
                let saved = c.save();
                c.clip_to(inner.inset_by(Insets::new(-1, 1, -1, 1)));
                if s.is_empty() {
                    text.draw(c, inner.x, ty, st.font, st.size, col.text_disabled, placeholder);
                } else {
                    let stops = text.caret_stops(st.font, st.size, s);
                    if caret != anchor && focus {
                        let (lo, hi) = (*caret.min(anchor), *caret.max(anchor));
                        let x0 = inner.x + stops[lo] - scroll;
                        let x1 = inner.x + stops[hi] - scroll;
                        c.fill_rect(Rect::new(x0, b.y + 5, x1 - x0, b.h - 10), col.accent_wash);
                    }
                    text.draw(c, inner.x - scroll, ty, st.font, st.size, if enabled { col.text } else { col.text_disabled }, s);
                }
                if focus && (self.caret_on || n.force & FORCE_FOCUS != 0) {
                    let stops = text.caret_stops(st.font, st.size, s);
                    let cx = inner.x + stops[(*caret).min(stops.len() - 1)] - scroll;
                    c.fill_rect(Rect::new(cx, b.y + 6, 1, b.h - 12), col.accent_text);
                }
                c.restore(saved);
            }
            Widget::Checkbox { label, checked } => {
                let bx = Rect::new(b.x, b.y + (b.h - 16) / 2, 16, 16);
                let r = theme.radius.sm;
                if *checked {
                    let fill = if !enabled { col.control } else if pressed { col.accent_pressed } else if hover { col.accent_hover } else { col.accent };
                    c.fill_round_rect(bx, r, fill);
                    icons::draw(c, Icon::Check, bx.inset(2), if enabled { col.text_on_accent } else { col.text_disabled });
                } else {
                    c.fill_round_rect(bx, r, if pressed { col.control_pressed } else { col.field });
                    let bc = if hover && enabled { col.hairline_strong.mix(Color::WHITE, 80) } else { col.hairline_strong.mix(Color::WHITE, 30) };
                    c.stroke_round_rect(bx, r, 1, bc);
                }
                if focus { Self::focus_ring(c, bx, r, theme); }
                let st = theme.text.body;
                let lm = text.metrics(st.font, st.size);
                text.draw(c, b.x + 24, b.y + (b.h - lm.height) / 2, st.font, st.size, if enabled { col.text } else { col.text_disabled }, label);
            }
            Widget::Toggle { on, pos, .. } => {
                let tr = Rect::new(b.x, b.y + (b.h - 20) / 2, 34, 20);
                let off_c = if hover && enabled { col.control_hover.mix(Color::WHITE, 12) } else { col.control_hover };
                let on_c = if hover { col.accent_hover } else { col.accent };
                let track = off_c.mix(on_c, (*pos * 256.0) as u32);
                let track = if enabled { track } else { track.fade(110) };
                c.fill_round_rect(tr, 10, track);
                let kx = tr.x as f32 + 10.0 + *pos * 14.0;
                let knob = if *on || *pos > 0.5 { Color::WHITE } else { Color::hex(0xD3D6DB) };
                let knob = if enabled { knob } else { knob.fade(120) };
                c.fill_circle(kx, tr.y as f32 + 10.0 + 0.5, 8.5, Color::black_a(50));
                c.fill_circle(kx, tr.y as f32 + 10.0, 8.0, knob);
                if focus { Self::focus_ring(c, tr, 10, theme); }
            }
            Widget::List { columns, header, items, selected, scroll, row_h } => {
                self.paint_list(id, c, text, theme, columns, *header, items, *selected, *scroll, *row_h);
            }
            Widget::Separator => {
                if b.w >= b.h { c.hline(b.x, b.right(), b.y + b.h / 2, col.hairline); }
                else { c.vline(b.x + b.w / 2, b.y, b.bottom(), col.hairline); }
            }
            Widget::Spacer => {}
            Widget::Icon { icon, size, color } => {
                let r = Rect::new(b.x + (b.w - size) / 2, b.y + (b.h - size) / 2, *size, *size);
                icons::draw(c, *icon, r, color.unwrap_or(col.text_secondary));
            }
            Widget::Terminal { lines, cursor } => {
                let st = theme.text.mono;
                let inner = b.inset_by(n.layout.padding);
                let cell = text.mono_advance(st.font, st.size);
                let visible = (inner.h / st.line).max(1) as usize;
                let first = lines.len().saturating_sub(visible);
                let lm = text.metrics(st.font, st.size);
                let saved = c.save();
                c.clip_to(inner);
                for (row, line) in lines[first..].iter().enumerate() {
                    let y = inner.y + row as i32 * st.line;
                    let ty = y + (st.line - lm.height) / 2;
                    let mut col_i = 0;
                    for sp in line {
                        col_i += text.draw_mono(c, inner.x + col_i * cell, ty, st.font, st.size, sp.color, &sp.text);
                    }
                }
                if let Some((r, cc)) = cursor {
                    if *r >= first {
                        let y = inner.y + (*r - first) as i32 * st.line;
                        let blink = self.active;
                        let cur = Rect::new(inner.x + *cc as i32 * cell, y + 1, cell, st.line - 2);
                        if blink { c.fill_rect(cur, col.text.fade(210)); } else { c.stroke_rect(cur, 1, col.text_secondary); }
                    }
                }
                c.restore(saved);
            }
            Widget::Progress { value } => {
                let r = Rect::new(b.x, b.y + (b.h - 6) / 2, b.w, 6);
                c.fill_round_rect(r, 3, col.hairline);
                let w = (r.w as f32 * crate::math::clamp01(*value)) as i32;
                if w > 0 { c.fill_round_rect(Rect::new(r.x, r.y, w.max(6), 6), 3, col.accent); }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn paint_list(&self, id: NodeId, c: &mut Canvas, text: &mut TextEngine, theme: &Theme, columns: &[Column], header: bool,
                  items: &[ListItem], selected: Option<usize>, scroll: i32, row_h: i32) {
        let col = &theme.color;
        let b = self.nodes[id].bounds;
        let (hover, _, _) = self.state(id);
        let focused = (self.focus == Some(id) && self.active) || self.nodes[id].force & FORCE_FOCUS != 0;
        let rows = self.list_rows_rect(id);
        // Column x-ranges.
        let pad = 12;
        let avail = b.w - 2 * pad - 10;
        let fixed: i32 = columns.iter().map(|c| if let Length::Px(v) = c.width { v } else { 0 }).sum();
        let weights: i32 = columns.iter().map(|c| if let Length::Fill(w) = c.width { w as i32 } else { 0 }).sum();
        let mut xs = Vec::with_capacity(columns.len());
        let mut x = b.x + pad;
        for cdef in columns {
            let w = match cdef.width {
                Length::Px(v) => v,
                Length::Fill(wt) => if weights > 0 { (avail - fixed).max(0) * wt as i32 / weights } else { 0 },
                Length::Hug => 80,
            };
            xs.push((x, w));
            x += w;
        }
        let body = theme.text.body;
        let small = theme.text.small;
        let lm = text.metrics(body.font, body.size);
        if header {
            let hl = text.metrics(small.font, small.size);
            for (cdef, &(x, w)) in columns.iter().zip(xs.iter()) {
                let tw = text.measure(small.font, small.size, &cdef.title);
                let tx = if cdef.align_right { x + w - tw - 8 } else { x };
                text.draw(c, tx, b.y + (28 - hl.height) / 2, small.font, small.size, col.text_secondary, &cdef.title);
            }
            c.hline(b.x, b.right(), b.y + 27, col.hairline);
        }
        let saved = c.save();
        c.clip_to(rows);
        let first = ((scroll - 4) / row_h).max(0) as usize;
        let last = (((scroll + rows.h) / row_h) as usize + 1).min(items.len());
        for i in first..last {
            let it = &items[i];
            let ry = rows.y + 4 + i as i32 * row_h - scroll;
            let rr = Rect::new(b.x + 6, ry, b.w - 12, row_h);
            let sel = selected == Some(i);
            if sel {
                c.fill_round_rect(rr, theme.radius.md, if focused { col.accent_wash.mix(col.accent, 60) } else { col.selected_inactive });
            } else if self.hover_row == Some((id, i)) && (hover || self.nodes[id].force & FORCE_HOVER != 0) {
                c.fill_round_rect(rr, theme.radius.md, col.hover);
            }
            let ty = ry + (row_h - lm.height) / 2;
            for (ci, (cdef, &(x, w))) in columns.iter().zip(xs.iter()).enumerate() {
                let cell = it.cells.get(ci).map(|s| s.as_str()).unwrap_or("");
                let mut cx = x;
                let mut cw = w - 8;
                if ci == 0 {
                    if let Some(ic) = it.icon {
                        let icol = it.icon_color.unwrap_or(col.text_secondary);
                        icons::draw(c, ic, Rect::new(cx, ry + (row_h - 16) / 2, 16, 16), if sel && focused { col.text } else { icol });
                        cx += 26;
                        cw -= 26;
                    }
                }
                let fg = if ci == 0 { col.text } else { col.text_secondary };
                let fg = if sel && focused { col.text } else { fg };
                if cdef.align_right {
                    let tw = text.measure(body.font, body.size, cell).min(cw);
                    text.draw_ellipsis(c, x + w - 8 - tw, ty, cw, body.font, body.size, fg, cell);
                } else {
                    text.draw_ellipsis(c, cx, ty, cw, body.font, body.size, fg, cell);
                }
            }
        }
        if let Some(t) = self.list_thumb(id) {
            let dragging = matches!(self.drag, Drag::Thumb { list, .. } if list == id);
            let a = if dragging { 110 } else if hover { 70 } else { 44 };
            c.fill_round_rect(t, 3, Color::white_a(a));
        }
        c.restore(saved);
    }
}

fn align_off(a: Align, free: i32) -> i32 {
    match a {
        Align::Center => free / 2,
        Align::End => free,
        _ => 0,
    }
}
