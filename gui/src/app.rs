// SPDX-License-Identifier: AGPL-3.0-only
//! Application API — what a GUI program for ospab.os is written against.
//!
//! An app implements [`Application`]: it describes itself ([`AppInfo`]),
//! opens windows in [`Application::start`], and reacts to [`AppEvent`]s.
//! Everything it can do goes through [`Ctx`]: windows, widget trees, timers,
//! dialogs, the clipboard and system services ([`Platform`]).
//!
//! An app never touches the window manager.  Its host ([`AppHost`]) turns
//! `Ctx` calls into protocol messages ([`crate::proto`]): today the host runs
//! inside the kernel's desktop session; once the compositor is a ring-3
//! server the same app runs as its own process and the host talks to the
//! compositor over an IPC channel.  App code does not change.
//!
//! ```ignore
//! struct Hello { label: NodeId }
//! impl Application for Hello {
//!     fn info(&self) -> AppInfo { AppInfo::new("org.ospab.hello", "Hello", Icon::Info) }
//!     fn start(&mut self, cx: &mut Ctx) {
//!         let mut ui = Ui::new(Axis::Column, cx.theme().color.bg1);
//!         let root = ui.root();
//!         self.label = ui.label(root, "Hello, ospab.os", TextRole::Title);
//!         ui.button(root, "Close", ButtonKind::Primary);
//!         cx.open_window(WindowSpec::new("Hello", 320, 160), ui);
//!     }
//!     fn event(&mut self, cx: &mut Ctx, win: WinId, ev: &AppEvent) {
//!         match ev {
//!             AppEvent::Action(Action::Clicked(_)) | AppEvent::CloseRequested => cx.close_window(win),
//!             _ => {}
//!         }
//!     }
//! }
//! ```

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::proto::ToServer;
use crate::text::TextEngine;
use crate::window::{Client, ClientWindow, Cx};

// The application API surface: everything an app needs is reachable from
// here (or from `oos_ui::app::prelude`).
pub use crate::color::Color;
pub use crate::event::{Event, Key, Modifiers, MouseButton};
pub use crate::geom::{Insets, Point, Rect, Size};
pub use crate::icons::Icon;
pub use crate::menu::MenuItem;
pub use crate::proto::WinId;
pub use crate::theme::Theme;
pub use crate::ui::{Action, Align, Axis, BoxStyle, ButtonKind, Column, Length, ListItem, NodeId, Span, TextRole, Ui};
pub use crate::window::AppEvent;

/// `use oos_ui::app::prelude::*;` brings the whole app API into scope.
pub mod prelude {
    pub use super::*;
}

/// Who the app is. `id` is reverse-DNS style and unique ("org.ospab.files").
#[derive(Clone, Copy, Debug)]
pub struct AppInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub icon: Icon,
    pub version: &'static str,
}

impl AppInfo {
    pub const fn new(id: &'static str, name: &'static str, icon: Icon) -> AppInfo {
        AppInfo { id, name, icon, version: "0.1.0" }
    }
}

/// How a window should be created.
#[derive(Clone, Debug)]
pub struct WindowSpec {
    pub title: String,
    pub size: (i32, i32),
    pub min: (i32, i32),
    pub resizable: bool,
    /// Defaults to the app icon.
    pub icon: Option<Icon>,
}

impl WindowSpec {
    pub fn new(title: &str, w: i32, h: i32) -> WindowSpec {
        WindowSpec { title: title.into(), size: (w, h), min: (240, 160), resizable: true, icon: None }
    }
    pub fn min_size(mut self, w: i32, h: i32) -> Self { self.min = (w, h); self }
    pub fn fixed(mut self) -> Self { self.resizable = false; self.min = self.size; self }
    pub fn icon(mut self, i: Icon) -> Self { self.icon = Some(i); self }
}

pub type TimerId = u32;
pub type DialogId = u32;

/// How a dialog ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialogResult {
    Ok,
    Cancel,
    /// A file was chosen in an open-file dialog.
    Path(String),
}

/// One directory entry from [`Platform::list_dir`].
#[derive(Clone, Debug)]
pub struct DirItem {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// System services the app may use. The host provides the implementation
/// (in-kernel: the VFS; ring-3: liboos system calls).  Every method has a
/// conservative default so a minimal platform is easy to provide.
pub trait Platform {
    fn list_dir(&mut self, _path: &str) -> Option<Vec<DirItem>> { None }
    fn read_file(&mut self, _path: &str) -> Option<Vec<u8>> { None }
    fn write_file(&mut self, _path: &str, _data: &[u8]) -> bool { false }
    fn rename(&mut self, _from: &str, _to: &str) -> bool { false }
    fn remove(&mut self, _path: &str) -> bool { false }
    fn mkdir(&mut self, _path: &str) -> bool { false }
    /// Ask the session to start another app (by id) with an optional argument.
    fn launch(&mut self, _app: &str, _arg: Option<&str>) -> bool { false }
    /// Wall-clock time as "HH:MM" etc. is app business; this is ms since boot.
    fn uptime_ms(&mut self) -> u64 { 0 }
}

struct NoPlatform;
impl Platform for NoPlatform {}

static mut PLATFORM: Option<Box<dyn Platform>> = None;
static mut CLIPBOARD: Option<String> = None;

/// Install the platform (done once by the host program / session).
pub fn set_platform(p: Box<dyn Platform>) {
    unsafe { PLATFORM = Some(p); }
}

fn platform() -> &'static mut dyn Platform {
    unsafe {
        if PLATFORM.is_none() { PLATFORM = Some(Box::new(NoPlatform)); }
        PLATFORM.as_deref_mut().unwrap()
    }
}

/// Session clipboard (plain text). Text fields use it for Ctrl+C/X/V.
pub fn clipboard_get() -> String { unsafe { CLIPBOARD.clone().unwrap_or_default() } }
pub fn clipboard_set(s: &str) { unsafe { CLIPBOARD = Some(s.into()); } }

/// A GUI application.
pub trait Application {
    fn info(&self) -> AppInfo;
    /// Open the first window(s). `arg` is the launch argument (e.g. a path).
    fn start(&mut self, cx: &mut Ctx, arg: Option<&str>);
    /// Something happened in one of the app's windows (or a timer, `win` = 0).
    fn event(&mut self, cx: &mut Ctx, win: WinId, ev: &AppEvent);
    /// Called once per frame, before rendering.
    fn tick(&mut self, _cx: &mut Ctx) {}
}

struct Timer {
    id: TimerId,
    due: u64,
    period: Option<u64>,
}

enum DialogKind {
    Message,
    OpenFile { dir: String, list: NodeId, path: NodeId, up: NodeId, items: Vec<DirItem> },
}

struct Dialog {
    id: DialogId,
    parent: WinId,
    win: ClientWindow,
    ok: NodeId,
    cancel: Option<NodeId>,
    kind: DialogKind,
}

/// Host-side state behind [`Ctx`].
pub struct HostState {
    windows: Vec<ClientWindow>,
    dialogs: Vec<Dialog>,
    timers: Vec<Timer>,
    next: u32,
    quit: bool,
    queued: Vec<(WinId, AppEvent)>,
    icon: Icon,
}

/// The app's handle to its windows and the system.
pub struct Ctx<'a> {
    st: &'a mut HostState,
    text: &'a mut TextEngine,
    theme: &'a Theme,
    out: &'a mut VecDeque<ToServer>,
    now: u64,
}

impl<'a> Ctx<'a> {
    pub fn theme(&self) -> &Theme { self.theme }
    pub fn text(&mut self) -> &mut TextEngine { self.text }
    /// Size of one monospace cell (advance, line height) in pixels.
    pub fn mono_cell(&mut self) -> (i32, i32) {
        let st = self.theme.text.mono;
        (self.text.mono_advance(st.font, st.size), st.line)
    }
    /// Columns and rows that fit in widget `node` of `win` (terminal-like widgets).
    pub fn grid_size(&mut self, win: WinId, node: NodeId) -> (usize, usize) {
        let (cw, ch) = self.mono_cell();
        let Some(w) = self.st.windows.iter().find(|w| w.id == win) else { return (80, 24) };
        let n = w.ui.node(node);
        let inner = n.bounds.inset_by(n.layout.padding);
        (((inner.w / cw).max(10)) as usize, ((inner.h / ch).max(3)) as usize)
    }
    /// Milliseconds since the session started.
    pub fn now(&self) -> u64 { self.now }
    pub fn platform(&mut self) -> &mut dyn Platform { platform() }

    /// Create a window showing `ui`. Returns its id.
    pub fn open_window(&mut self, spec: WindowSpec, ui: Ui) -> WinId {
        let icon = spec.icon.unwrap_or(self.st.icon);
        let w = ClientWindow::new(self.out, &spec.title, icon, spec.size.0, spec.size.1, spec.min, spec.resizable, ui);
        let id = w.id;
        self.st.windows.push(w);
        id
    }

    /// The widget tree of a window (None if it is closed).
    pub fn ui(&mut self, win: WinId) -> Option<&mut Ui> {
        self.st.windows.iter_mut().find(|w| w.id == win && !w.destroyed).map(|w| &mut w.ui)
    }

    /// Current client size of a window (including the title bar).
    pub fn window_size(&self, win: WinId) -> Option<(i32, i32)> {
        self.st.windows.iter().find(|w| w.id == win).map(|w| (w.w, w.h))
    }

    pub fn set_title(&mut self, win: WinId, title: &str) {
        let (out, theme) = (&mut *self.out, self.theme);
        if let Some(w) = self.st.windows.iter_mut().find(|w| w.id == win) { w.set_title(title, out, theme); }
    }

    pub fn close_window(&mut self, win: WinId) {
        let out = &mut *self.out;
        if let Some(w) = self.st.windows.iter_mut().find(|w| w.id == win) { w.destroy(out); }
        let ds: Vec<DialogId> = self.st.dialogs.iter().filter(|d| d.parent == win).map(|d| d.id).collect();
        for d in ds { self.close_dialog(d); }
    }

    /// Ask the compositor to raise and focus a window.
    pub fn activate(&mut self, win: WinId) { self.out.push_back(ToServer::Activate { id: win }); }

    /// Close every window and end the app.
    pub fn quit(&mut self) {
        self.st.quit = true;
        let ids: Vec<WinId> = self.st.windows.iter().map(|w| w.id).collect();
        for id in ids { self.close_window(id); }
    }

    /// Fire `AppEvent::Timer(id)` after `ms` (and every `ms` if `repeat`).
    pub fn set_timer(&mut self, ms: u64, repeat: bool) -> TimerId {
        self.st.next += 1;
        let id = self.st.next;
        self.st.timers.push(Timer { id, due: self.now + ms, period: if repeat { Some(ms.max(1)) } else { None } });
        id
    }

    pub fn cancel_timer(&mut self, id: TimerId) { self.st.timers.retain(|t| t.id != id); }

    /// Show a popup menu in `win` below `anchor`; the choice arrives as
    /// `Action::MenuChosen(owner, index)`.
    pub fn open_menu(&mut self, win: WinId, owner: NodeId, anchor: Rect, items: Vec<MenuItem>) {
        let (text, theme) = (&mut *self.text, self.theme);
        if let Some(w) = self.st.windows.iter_mut().find(|w| w.id == win) { w.ui.open_menu(owner, anchor, items, text, theme); }
    }

    pub fn clipboard(&self) -> String { clipboard_get() }
    pub fn set_clipboard(&mut self, s: &str) { clipboard_set(s) }

    fn new_dialog_id(&mut self) -> DialogId { self.st.next += 1; self.st.next }

    fn dialog_ui(&self, title: &str, message: &str, ok: &str, cancel: Option<&str>, danger: bool) -> (Ui, NodeId, Option<NodeId>) {
        let t = self.theme;
        let mut ui = Ui::new(Axis::Column, t.color.bg1);
        let root = ui.root();
        ui.padding(root, Insets::new(24, 18, 24, 18));
        ui.gap(root, 10);
        ui.label(root, title, TextRole::Title);
        let p = ui.paragraph(root, message, TextRole::Secondary);
        ui.width(p, Length::Fill(1));
        ui.spacer(root);
        let row = ui.row(root);
        ui.align(row, Align::End, Align::Center);
        ui.gap(row, 8);
        let c = cancel.map(|c| ui.button(row, c, ButtonKind::Secondary));
        let o = ui.button(row, ok, if danger { ButtonKind::Danger } else { ButtonKind::Primary });
        ui.set_focus(Some(o));
        (ui, o, c)
    }

    fn push_dialog(&mut self, parent: WinId, title: &str, ui: Ui, ok: NodeId, cancel: Option<NodeId>, kind: DialogKind, size: (i32, i32)) -> DialogId {
        let id = self.new_dialog_id();
        let win = ClientWindow::new(self.out, title, self.st.icon, size.0, size.1, size, false, ui);
        self.st.dialogs.push(Dialog { id, parent, win, ok, cancel, kind });
        id
    }

    /// Message box with one button. Result: `DialogResult::Ok`.
    pub fn alert(&mut self, parent: WinId, title: &str, message: &str) -> DialogId {
        let (ui, ok, _) = self.dialog_ui(title, message, "OK", None, false);
        self.push_dialog(parent, title, ui, ok, None, DialogKind::Message, (400, 190))
    }

    /// Two-button question. Result: `Ok` or `Cancel`.
    pub fn confirm(&mut self, parent: WinId, title: &str, message: &str, ok: &str, destructive: bool) -> DialogId {
        let (ui, o, c) = self.dialog_ui(title, message, ok, Some("Cancel"), destructive);
        self.push_dialog(parent, title, ui, o, c, DialogKind::Message, (420, 200))
    }

    /// Pick a file. Result: `Path(..)` or `Cancel`. Uses [`Platform::list_dir`].
    pub fn open_file(&mut self, parent: WinId, start_dir: &str) -> DialogId {
        let t = self.theme;
        let mut ui = Ui::new(Axis::Column, t.color.bg1);
        let root = ui.root();
        let bar = ui.row(root);
        ui.size(bar, Length::Fill(1), Length::Px(44));
        ui.padding(bar, Insets::xy(10, 8));
        ui.align(bar, Align::Start, Align::Center);
        ui.gap(bar, 6);
        let up = ui.icon_button(bar, Icon::ChevronLeft);
        let path = ui.label(bar, start_dir, TextRole::Strong);
        ui.width(path, Length::Fill(1));
        ui.separator(root);
        let list = ui.list(root, vec![Column::new("Name", Length::Fill(1)), Column::new("Size", Length::Px(90)).right()], false, Vec::new(), 28);
        ui.separator(root);
        let row = ui.row(root);
        ui.padding(row, Insets::xy(14, 10));
        ui.align(row, Align::End, Align::Center);
        ui.gap(row, 8);
        let cancel = ui.button(row, "Cancel", ButtonKind::Secondary);
        let ok = ui.button(row, "Open", ButtonKind::Primary);
        ui.set_focus(Some(list));
        let kind = DialogKind::OpenFile { dir: String::new(), list, path, up, items: Vec::new() };
        let id = self.push_dialog(parent, "Open", ui, ok, Some(cancel), kind, (520, 420));
        self.dialog_cd(id, start_dir);
        id
    }

    fn dialog_cd(&mut self, id: DialogId, dir: &str) {
        let items = {
            let mut v = platform().list_dir(dir).unwrap_or_default();
            v.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
            v
        };
        let Some(d) = self.st.dialogs.iter_mut().find(|d| d.id == id) else { return };
        if let DialogKind::OpenFile { dir: cur, list, path, items: its, .. } = &mut d.kind {
            *cur = dir.into();
            let rows: Vec<ListItem> = items.iter().map(|e| {
                let it = ListItem::new(&[&e.name, &if e.is_dir { String::from("—") } else { fmt_size(e.size) }]);
                if e.is_dir { it.icon(Icon::Folder, Some(self.theme.color.accent_text)) } else { it.icon(Icon::File, None) }
            }).collect();
            if let Some(l) = d.win.ui.list_items_mut(*list) { *l = rows; }
            d.win.ui.set_selected(*list, if items.is_empty() { None } else { Some(0) });
            d.win.ui.set_text(*path, dir);
            *its = items;
        }
    }

    fn close_dialog(&mut self, id: DialogId) {
        let out = &mut *self.out;
        if let Some(d) = self.st.dialogs.iter_mut().find(|d| d.id == id) { d.win.destroy(out); }
    }
}

pub fn fmt_size(b: u64) -> String {
    if b < 1024 { return alloc::format!("{} B", b); }
    if b < 1024 * 1024 { return alloc::format!("{:.1} KB", b as f32 / 1024.0); }
    if b < 1024 * 1024 * 1024 { return alloc::format!("{:.1} MB", b as f32 / (1024.0 * 1024.0)); }
    alloc::format!("{:.1} GB", b as f32 / (1024.0 * 1024.0 * 1024.0))
}

fn join_path(dir: &str, name: &str) -> String {
    if dir.ends_with('/') { alloc::format!("{}{}", dir, name) } else { alloc::format!("{}/{}", dir, name) }
}

fn parent_dir(p: &str) -> String {
    let t = p.trim_end_matches('/');
    match t.rfind('/') { Some(0) | None => "/".into(), Some(i) => t[..i].into() }
}

/// Runs one [`Application`] as a session [`Client`].
pub struct AppHost {
    app: Box<dyn Application>,
    st: HostState,
    started: bool,
    arg: Option<String>,
    info: AppInfo,
}

impl AppHost {
    pub fn new(app: Box<dyn Application>, arg: Option<&str>) -> AppHost {
        let info = app.info();
        AppHost {
            app, started: false, arg: arg.map(String::from), info,
            st: HostState { windows: Vec::new(), dialogs: Vec::new(), timers: Vec::new(), next: 0, quit: false, queued: Vec::new(), icon: info.icon },
        }
    }

    pub fn info(&self) -> AppInfo { self.info }

    fn ctx<'b>(&'b mut self, cx: &'b mut Cx) -> (&'b mut Box<dyn Application>, Ctx<'b>) {
        (&mut self.app, Ctx { st: &mut self.st, text: cx.text, theme: cx.theme, out: cx.out, now: cx.now })
    }

    fn dialog_event(&mut self, id: WinId, ev: &AppEvent, cx: &mut Cx) {
        let Some(di) = self.st.dialogs.iter().position(|d| d.win.id == id) else { return };
        let (did, parent, ok, cancel) = { let d = &self.st.dialogs[di]; (d.id, d.parent, d.ok, d.cancel) };
        let mut result: Option<DialogResult> = None;
        let mut cd: Option<String> = None;
        let mut choose: Option<usize> = None;
        match ev {
            AppEvent::Action(Action::Clicked(n)) if *n == ok => {
                if let DialogKind::OpenFile { list, .. } = &self.st.dialogs[di].kind {
                    choose = self.st.dialogs[di].win.ui.selected(*list);
                } else { result = Some(DialogResult::Ok); }
            }
            AppEvent::Action(Action::Clicked(n)) if Some(*n) == cancel => result = Some(DialogResult::Cancel),
            AppEvent::CloseRequested => result = Some(DialogResult::Cancel),
            AppEvent::Key(Event::KeyDown { key: Key::Escape, .. }) => result = Some(DialogResult::Cancel),
            AppEvent::Key(Event::KeyDown { key: Key::Enter, .. }) if cancel.is_none() => result = Some(DialogResult::Ok),
            AppEvent::Action(Action::Activated(_, i)) => choose = Some(*i),
            AppEvent::Action(Action::Clicked(n)) => {
                if let DialogKind::OpenFile { up, dir, .. } = &self.st.dialogs[di].kind {
                    if n == up { cd = Some(parent_dir(dir)); }
                }
            }
            AppEvent::Key(Event::KeyDown { key: Key::Backspace, .. }) => {
                if let DialogKind::OpenFile { dir, .. } = &self.st.dialogs[di].kind { cd = Some(parent_dir(dir)); }
            }
            _ => {}
        }
        if let Some(i) = choose {
            if let DialogKind::OpenFile { dir, items, .. } = &self.st.dialogs[di].kind {
                if let Some(e) = items.get(i) {
                    let p = join_path(dir, &e.name);
                    if e.is_dir { cd = Some(p); } else { result = Some(DialogResult::Path(p)); }
                }
            }
        }
        let (app, mut c) = self.ctx(cx);
        if let Some(d) = cd { c.dialog_cd(did, &d); }
        if let Some(r) = result {
            c.close_dialog(did);
            app.event(&mut c, parent, &AppEvent::Dialog(did, r));
        }
    }
}

impl Client for AppHost {
    fn app_id(&self) -> &str { self.info.id }

    fn window_mut(&mut self, id: WinId) -> Option<&mut ClientWindow> {
        if let Some(w) = self.st.windows.iter_mut().find(|w| w.id == id) { return Some(w); }
        self.st.dialogs.iter_mut().find(|d| d.win.id == id).map(|d| &mut d.win)
    }

    fn window_ids(&self) -> Vec<WinId> {
        let mut v: Vec<WinId> = self.st.windows.iter().filter(|w| !w.destroyed).map(|w| w.id).collect();
        v.extend(self.st.dialogs.iter().filter(|d| !d.win.destroyed).map(|d| d.win.id));
        v
    }

    fn update(&mut self, id: WinId, events: &[AppEvent], cx: &mut Cx) {
        if self.st.dialogs.iter().any(|d| d.win.id == id) {
            for e in events { self.dialog_event(id, e, cx); }
            return;
        }
        let (app, mut c) = self.ctx(cx);
        for e in events { app.event(&mut c, id, e); }
    }

    fn tick(&mut self, cx: &mut Cx) {
        let now = cx.now;
        if !self.started {
            self.started = true;
            let arg = self.arg.take();
            let (app, mut c) = self.ctx(cx);
            app.start(&mut c, arg.as_deref());
        }
        // Timers.
        let mut fired = Vec::new();
        for t in self.st.timers.iter_mut() {
            if now >= t.due {
                fired.push(t.id);
                match t.period { Some(p) => t.due = now + p, None => t.due = u64::MAX }
            }
        }
        self.st.timers.retain(|t| t.due != u64::MAX);
        let queued = core::mem::take(&mut self.st.queued);
        let (app, mut c) = self.ctx(cx);
        for id in fired { app.event(&mut c, 0, &AppEvent::Timer(id)); }
        for (w, e) in queued { app.event(&mut c, w, &e); }
        app.tick(&mut c);
        self.st.windows.retain(|w| !w.destroyed);
        self.st.dialogs.retain(|d| !d.win.destroyed);
    }

    fn alive(&self) -> bool {
        !self.started || (!self.st.quit && self.st.windows.iter().any(|w| !w.destroyed))
    }
}
