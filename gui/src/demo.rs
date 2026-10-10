// SPDX-License-Identifier: AGPL-3.0-only
//! The reference desktop for host mockups: static Terminal, Settings and Files
//! windows driven through the real session loop, compositor and protocol.
//! (The in-OS desktop runs live applications; see src/userspace/axon/desktop.)

use alloc::vec;
use alloc::vec::Vec;

use alloc::boxed::Box;
use alloc::collections::VecDeque;

use crate::color::Color;
use crate::desktop::{DockItem, ShellStatus};
use crate::geom::{Insets, Rect};
use crate::icons::Icon;
use crate::menu::MenuItem;
use crate::proto::WinId;
use crate::session::Session;
use crate::text::TextEngine;
use crate::theme::Theme;
use crate::ui::{Align, Axis, BoxStyle, ButtonKind, Column, Length, ListItem, NodeId, Span, TextRole, Ui};
use crate::window::{AppEvent, Client, ClientWindow, Cx};

pub const TERMINAL: usize = 0;
pub const SETTINGS: usize = 1;
pub const FILES: usize = 2;

pub struct SettingsIds {
    pub sidebar: NodeId,
    pub headline: NodeId,
    pub device: NodeId,
    pub ostp: NodeId,
    pub updates: NodeId,
    pub motion: NodeId,
    pub seconds: NodeId,
    pub status: NodeId,
    pub revert: NodeId,
    pub apply: NodeId,
}

pub struct FilesIds {
    pub back: NodeId,
    pub forward: NodeId,
    pub path: NodeId,
    pub search: NodeId,
    pub list: NodeId,
    pub status: NodeId,
}

const TERM_BG: Color = Color::hex(0x0E0F11);

fn sp(text: &str, color: Color) -> Span { Span { text: text.into(), color } }

fn prompt(theme: &Theme, cmd: &str) -> Vec<Span> {
    let c = &theme.color;
    vec![sp("ospab@aeterna", c.accent_text), sp(":", c.text_secondary), sp("~", c.text), sp("$ ", c.text_secondary), sp(cmd, c.text)]
}

fn terminal_lines(theme: &Theme) -> Vec<Vec<Span>> {
    let c = &theme.color;
    let out = |s: &str| vec![sp(s, c.text)];
    let dim = |s: &str| vec![sp(s, c.text_secondary)];
    vec![
        prompt(theme, "uname -a"),
        out("ospab.os 1.1.0 AETERNA x86_64 build 214 (c1e3d2d) 2026-10-10"),
        prompt(theme, "ls /"),
        vec![sp("bin  boot  doom  ", c.accent_text), sp("etc  home  ", c.accent_text), sp("init.cfg  ", c.text), sp("tmp  usr  var", c.accent_text)],
        prompt(theme, "ostp status"),
        vec![sp("tunnel  ", c.text_secondary), sp("up", c.success), sp("   203.0.113.7:443   rtt 18 ms   rx 41.2 MB", c.text)],
        prompt(theme, "tomato install grape"),
        dim("\u{2192} resolving grape 0.4.2 \u{2026} ok"),
        dim("\u{2192} verifying signature (ed25519) \u{2026} ok"),
        vec![sp("done", c.success), sp("  installed grape 0.4.2 (212 KiB)", c.text)],
        prompt(theme, "cat /etc/motd"),
        out("Добро пожаловать в ospab.os — тихая, быстрая, своя система."),
        prompt(theme, ""),
    ]
}

fn build_terminal(theme: &Theme, lines: Vec<Vec<Span>>) -> (Ui, NodeId) {
    let mut ui = Ui::new(Axis::Column, TERM_BG);
    let root = ui.root();
    let t = ui.terminal(root, lines);
    ui.padding(t, Insets::xy(16, 12));
    let _ = theme;
    (ui, t)
}

fn setting_row(ui: &mut Ui, parent: NodeId, title: &str, detail: &str, on: bool) -> NodeId {
    let row = ui.row(parent);
    ui.size(row, Length::Fill(1), Length::Px(58));
    ui.align(row, Align::Start, Align::Center);
    ui.gap(row, 16);
    let col = ui.column(row);
    ui.width(col, Length::Fill(1));
    ui.gap(col, 2);
    ui.label(col, title, TextRole::Strong);
    ui.label(col, detail, TextRole::Secondary);
    ui.toggle(row, on)
}

fn build_settings(theme: &Theme) -> (Ui, SettingsIds) {
    let c = &theme.color;
    let mut ui = Ui::new(Axis::Row, c.bg1);
    let root = ui.root();
    // Sidebar.
    let side = ui.container(root, Axis::Column, BoxStyle { bg: Some(c.surface), border: None, radius: 0 });
    ui.size(side, Length::Px(200), Length::Fill(1));
    ui.padding(side, Insets::new(10, 12, 10, 10));
    ui.gap(side, 10);
    let search = ui.text_field(side, "", "Search settings");
    ui.width(search, Length::Fill(1));
    let items = vec![
        ListItem::new(&["General"]).icon(Icon::Settings, None),
        ListItem::new(&["Display"]).icon(Icon::Display, None),
        ListItem::new(&["Network"]).icon(Icon::Network, None),
        ListItem::new(&["Sound"]).icon(Icon::Sound, None),
        ListItem::new(&["Keyboard"]).icon(Icon::Keyboard, None),
        ListItem::new(&["Privacy"]).icon(Icon::Lock, None),
        ListItem::new(&["About"]).icon(Icon::Info, None),
    ];
    let sidebar = ui.list(side, vec![Column::new("", Length::Fill(1))], false, items, 30);
    ui.set_selected(sidebar, Some(0));
    let sep = ui.separator(root);
    ui.size(sep, Length::Px(1), Length::Fill(1));
    // Content.
    let content = ui.column(root);
    ui.size(content, Length::Fill(1), Length::Fill(1));
    ui.padding(content, Insets::new(28, 20, 28, 20));
    ui.gap(content, 16);
    let headline = ui.label(content, "General", TextRole::Headline);
    let name_row = ui.row(content);
    ui.align(name_row, Align::Start, Align::Center);
    ui.gap(name_row, 12);
    let l = ui.label(name_row, "Device name", TextRole::Secondary);
    ui.width(l, Length::Px(110));
    let device = ui.text_field(name_row, "aeterna", "Name on the network");
    ui.width(device, Length::Fill(1));

    let card = ui.container(content, Axis::Column, BoxStyle { bg: Some(c.surface), border: Some(c.hairline), radius: theme.radius.lg });
    ui.padding(card, Insets::xy(16, 0));
    let ostp = setting_row(&mut ui, card, "Route through OSTP", "Send all traffic through the ospab tunnel", true);
    ui.separator(card);
    let updates = setting_row(&mut ui, card, "Automatic updates", "tomato checks tmt.ospab.org once a day", false);
    ui.separator(card);
    let motion = setting_row(&mut ui, card, "Reduce motion", "Turn off window and control animations", false);
    ui.separator(card);
    let lang = ui.row(card);
    ui.size(lang, Length::Fill(1), Length::Px(46));
    ui.align(lang, Align::Start, Align::Center);
    ui.gap(lang, 8);
    let ll = ui.label(lang, "Language", TextRole::Strong);
    ui.width(ll, Length::Fill(1));
    ui.label(lang, "Русский", TextRole::Secondary);
    ui.icon(lang, Icon::ChevronRight, 14, None);

    let seconds = ui.checkbox(content, "Show seconds in the top bar", false);
    ui.spacer(content);
    let actions = ui.row(content);
    ui.align(actions, Align::Start, Align::Center);
    ui.gap(actions, 8);
    let status = ui.label(actions, "", TextRole::Secondary);
    ui.width(status, Length::Fill(1));
    let revert = ui.button(actions, "Revert", ButtonKind::Secondary);
    let apply = ui.button(actions, "Apply", ButtonKind::Primary);
    (ui, SettingsIds { sidebar, headline, device, ostp, updates, motion, seconds, status, revert, apply })
}

struct FileEntry {
    name: &'static str,
    size: &'static str,
    date: &'static str,
    icon: Icon,
}

const FILES_HOME: &[FileEntry] = &[
    FileEntry { name: "aeterna", size: "—", date: "Today, 14:02", icon: Icon::Folder },
    FileEntry { name: "liboos", size: "—", date: "Today, 11:47", icon: Icon::Folder },
    FileEntry { name: "oos-ui", size: "—", date: "Today, 13:58", icon: Icon::Folder },
    FileEntry { name: "ostp-nostd", size: "—", date: "Yesterday, 22:15", icon: Icon::Folder },
    FileEntry { name: "Черновики", size: "—", date: "8 Oct 2026", icon: Icon::Folder },
    FileEntry { name: "build.sh", size: "9.4 KB", date: "Today, 10:31", icon: Icon::FileCode },
    FileEntry { name: "Cargo.toml", size: "1.2 KB", date: "Today, 13:40", icon: Icon::FileCode },
    FileEntry { name: "ROADMAP.md", size: "6.8 KB", date: "Yesterday, 19:04", icon: Icon::File },
    FileEntry { name: "desktop-mockup.png", size: "214 KB", date: "Today, 14:05", icon: Icon::FileImage },
    FileEntry { name: "doom1.wad", size: "4.2 MB", date: "2 Oct 2026", icon: Icon::FileArchive },
    FileEntry { name: "inter-subset.ttf", size: "54 KB", date: "Today, 12:09", icon: Icon::File },
    FileEntry { name: "kernel-panic-log.txt", size: "3.1 KB", date: "1 Oct 2026", icon: Icon::File },
    FileEntry { name: "ospab-os-v2-214.iso", size: "38.6 MB", date: "Today, 09:12", icon: Icon::FileArchive },
    FileEntry { name: "Заметки по IPC.md", size: "11 KB", date: "6 Oct 2026", icon: Icon::File },
    FileEntry { name: "wallpaper-none.txt", size: "12 B", date: "30 Sep 2026", icon: Icon::File },
    FileEntry { name: "xhci-notes.md", size: "4.0 KB", date: "29 Sep 2026", icon: Icon::File },
];

fn file_items(theme: &Theme) -> Vec<ListItem> {
    FILES_HOME.iter().map(|f| {
        let ic = if f.icon == Icon::Folder { Some(theme.color.accent_text) } else { None };
        ListItem::new(&[f.name, f.size, f.date]).icon(f.icon, ic)
    }).collect()
}

fn build_files(theme: &Theme) -> (Ui, FilesIds) {
    let c = &theme.color;
    let mut ui = Ui::new(Axis::Column, c.bg1);
    let root = ui.root();
    let bar = ui.row(root);
    ui.size(bar, Length::Fill(1), Length::Px(46));
    ui.padding(bar, Insets::xy(10, 9));
    ui.gap(bar, 2);
    ui.align(bar, Align::Start, Align::Center);
    let back = ui.icon_button(bar, Icon::ChevronLeft);
    let forward = ui.icon_button(bar, Icon::ChevronRight);
    ui.set_enabled(forward, false);
    let path = ui.label(bar, "/home/ospab/projects", TextRole::Strong);
    ui.width(path, Length::Fill(1));
    ui.padding(path, Insets::new(8, 0, 8, 0));
    let search = ui.text_field(bar, "", "Search");
    ui.width(search, Length::Px(170));
    ui.separator(root);
    let cols = vec![Column::new("Name", Length::Fill(1)), Column::new("Size", Length::Px(84)).right(), Column::new("Modified", Length::Px(140))];
    let list = ui.list(root, cols, true, file_items(theme), 28);
    ui.set_selected(list, Some(2));
    ui.separator(root);
    let st = ui.row(root);
    ui.size(st, Length::Fill(1), Length::Px(28));
    ui.padding(st, Insets::xy(14, 0));
    ui.align(st, Align::Start, Align::Center);
    let status = ui.label(st, "16 items  ·  2.1 GB free", TextRole::Caption);
    (ui, FilesIds { back, forward, path, search, list, status })
}

/// A window with static content (closes on request).
pub struct UiApp {
    pub win: ClientWindow,
}

impl Client for UiApp {
    fn window_mut(&mut self, id: WinId) -> Option<&mut ClientWindow> { if id == self.win.id { Some(&mut self.win) } else { None } }
    fn window_ids(&self) -> Vec<WinId> { if self.win.destroyed { Vec::new() } else { vec![self.win.id] } }
    fn update(&mut self, _id: WinId, events: &[AppEvent], cx: &mut Cx) {
        for e in events {
            if *e == AppEvent::CloseRequested { self.win.destroy(cx.out); }
        }
    }
    fn alive(&self) -> bool { !self.win.destroyed }
}

pub fn dock_items() -> Vec<DockItem> {
    let d = |n: &str, i: Icon, r: bool| DockItem { name: n.into(), icon: i, running: r };
    vec![d("Terminal", Icon::Terminal, true), d("Files", Icon::Folder, true), d("Editor", Icon::FileCode, false),
         d("Settings", Icon::Settings, true), d("DOOM", Icon::Grid, false)]
}

pub fn launcher_items() -> Vec<MenuItem> {
    vec![
        MenuItem::new("Terminal").icon(Icon::Terminal),
        MenuItem::new("Files").icon(Icon::Folder),
        MenuItem::new("Text Editor").icon(Icon::FileCode),
        MenuItem::new("Settings").icon(Icon::Settings),
        MenuItem::new("DOOM").icon(Icon::Grid),
        MenuItem::separator(),
        MenuItem::new("About ospab.os").icon(Icon::Info),
        MenuItem::new("Log out").icon(Icon::Power),
    ]
}

/// Build the mockup session at `width`x`height` (designed for 1280x800).
pub fn build_session(width: i32, height: i32, text: &mut TextEngine, theme: &Theme) -> (Session, [WinId; 3]) {
    let mut s = Session::new(width, height);
    s.desktop.dock = dock_items();
    s.desktop.launcher_items = launcher_items();
    s.desktop.set_status(ShellStatus { clock: "Сб 10 окт.  14:32".into(), net: "10.0.2.15".into(), net_up: true, ostp: true, volume: Some(70) }, theme);
    let lines = terminal_lines(theme);
    let n = lines.len();
    let (mut tui, term) = build_terminal(theme, lines.clone());
    tui.set_terminal(term, lines, Some((n - 1, 17)));
    let (sui, _) = build_settings(theme);
    let (fui, _) = build_files(theme);
    let mut out = VecDeque::new();
    let sw = ClientWindow::new(&mut out, "Settings", Icon::Settings, 700, 500, (480, 320), true, sui);
    let fw = ClientWindow::new(&mut out, "Files", Icon::Folder, 620, 440, (360, 240), true, fui);
    let tw = ClientWindow::new(&mut out, "Terminal — plum", Icon::Terminal, 720, 400, (360, 200), true, tui);
    let ids = [tw.id, sw.id, fw.id];
    s.add_app(Box::new(UiApp { win: sw }), VecDeque::new());
    s.add_app(Box::new(UiApp { win: fw }), VecDeque::new());
    s.add_app(Box::new(UiApp { win: tw }), out);
    s.pump(0, text, theme);
    let sx = |x: i32| x * width / 1280;
    let sy = |y: i32| y * height / 800;
    let place = [(ids[0], sx(250), sy(318)), (ids[1], sx(80), sy(58)), (ids[2], sx(610), sy(128))];
    for (id, x, y) in place {
        if let Some(w) = s.desktop.windows.iter_mut().find(|w| w.id == id) { w.rect.x = x; w.rect.y = y; }
    }
    s.desktop.invalidate_all();
    s.desktop.cursor = crate::geom::Point::new(sx(700), sy(250));
    (s, ids)
}

#[allow(dead_code)]
fn _unused(_: Rect) {}
