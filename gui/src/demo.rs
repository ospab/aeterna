// SPDX-License-Identifier: AGPL-3.0-only
//! The reference desktop: Terminal, Settings and Files windows on the shell
//! layer.  Used by the host PNG mockups (`examples/mockups.rs`) and by the
//! in-OS `guidemo` command, so both show exactly the same pixels.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::color::Color;
use crate::desktop::{Desktop, ShellAction};
use crate::event::{Event, Key};
use crate::geom::{Insets, Rect};
use crate::icons::Icon;
use crate::menu::MenuItem;
use crate::text::TextEngine;
use crate::theme::Theme;
use crate::ui::{Action, Align, Axis, BoxStyle, ButtonKind, Column, Length, ListItem, NodeId, Span, TextRole, Ui};
use crate::window::Window;

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

pub struct Demo {
    pub desktop: Desktop,
    pub settings: SettingsIds,
    pub files: FilesIds,
    pub term: NodeId,
    term_lines: Vec<Vec<Span>>,
    term_input: String,
    path: Vec<String>,
    saved_name: String,
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

impl Demo {
    pub fn new(width: i32, height: i32, text: &mut TextEngine, theme: &Theme) -> Demo {
        let mut d = Desktop::new(width, height);
        d.launcher_items = vec![
            MenuItem::new("Terminal").icon(Icon::Terminal).shortcut("Ctrl T"),
            MenuItem::new("Files").icon(Icon::Folder),
            MenuItem::new("Settings").icon(Icon::Settings).shortcut("Ctrl ,"),
            MenuItem::separator(),
            MenuItem::new("About ospab.os").icon(Icon::Info),
            MenuItem::separator(),
            MenuItem::new("Restart…").icon(Icon::Power).disabled(),
            MenuItem::new("Shut down…").disabled(),
        ];
        d.set_clock("Сб 10 окт.  14:32", theme);

        // Positions are relative to a 1280x800 layout and scaled to fit.
        let sx = |x: i32| x * width / 1280;
        let sy = |y: i32| y * height / 800;
        let lines = terminal_lines(theme);
        let n = lines.len();
        let (tui, term) = build_terminal(theme, lines.clone());
        let (sui, settings) = build_settings(theme);
        let (fui, files) = build_files(theme);
        let mut tw = Window::new("Terminal — plum", Icon::Terminal, Rect::new(sx(250), sy(330), 720.min(width - 20), 400.min(height - 60)), tui);
        tw.ui.set_terminal(term, lines.clone(), Some((n - 1, 17)));
        d.add_window(tw);
        d.add_window(Window::new("Settings", Icon::Settings, Rect::new(sx(80), sy(64), 700.min(width - 20), 500.min(height - 60)), sui));
        d.add_window(Window::new("Files", Icon::Folder, Rect::new(sx(610), sy(140), 620.min(width - 20), 440.min(height - 60)), fui));
        // Stack: Settings at the back, Files, then the focused Terminal.
        d.order = vec![SETTINGS, FILES, TERMINAL];
        d.focus_window(TERMINAL, text, theme);
        d.cursor = crate::geom::Point::new(sx(700), sy(250));
        Demo {
            desktop: d, settings, files, term, term_lines: lines, term_input: String::new(),
            path: vec!["/home/ospab/projects".into()], saved_name: "aeterna".into(),
        }
    }

    pub fn open_launcher(&mut self, text: &mut TextEngine, theme: &Theme) {
        let (x, y) = (20, 10);
        self.desktop.handle(&Event::PointerMove { x, y }, text, theme);
        self.desktop.handle(&Event::PointerDown { x, y, button: crate::event::MouseButton::Left }, text, theme);
    }

    fn term_refresh(&mut self, theme: &Theme) {
        let mut lines = self.term_lines.clone();
        let last = lines.len() - 1;
        lines[last] = prompt(theme, &self.term_input);
        let col = 17 + self.term_input.chars().count();
        self.desktop.windows[TERMINAL].ui.set_terminal(self.term, lines, Some((last, col)));
    }

    /// Route an input event (screen coordinates).
    pub fn handle(&mut self, ev: &Event, text: &mut TextEngine, theme: &Theme) {
        if let Event::KeyDown { key, text: ch, .. } = *ev {
            if self.desktop.focused() == Some(TERMINAL) {
                match key {
                    Key::Backspace => { self.term_input.pop(); }
                    Key::Enter => {
                        let cmd = core::mem::take(&mut self.term_input);
                        let last = self.term_lines.len() - 1;
                        self.term_lines[last] = prompt(theme, &cmd);
                        if !cmd.trim().is_empty() {
                            let c = &theme.color;
                            self.term_lines.push(vec![sp("guidemo: ", c.text_secondary), sp(&format!("“{}” would run in plum — press Esc to return to the console", cmd.trim()), c.text)]);
                        }
                        self.term_lines.push(prompt(theme, ""));
                        if self.term_lines.len() > 200 { self.term_lines.remove(0); }
                    }
                    _ => {
                        if let Some(c) = ch { if !c.is_control() && self.term_input.len() < 60 { self.term_input.push(c); } }
                    }
                }
                self.term_refresh(theme);
                return;
            }
        }
        self.desktop.handle(ev, text, theme);
    }

    fn process_actions(&mut self, text: &mut TextEngine, theme: &Theme) {
        for a in core::mem::take(&mut self.desktop.actions) {
            let ShellAction::Launch(i) = a;
            match i {
                0 => self.desktop.focus_window(TERMINAL, text, theme),
                1 => self.desktop.focus_window(FILES, text, theme),
                2 => self.desktop.focus_window(SETTINGS, text, theme),
                _ => {}
            }
        }
        let s = &self.settings;
        let acts = self.desktop.windows[SETTINGS].ui.drain_actions();
        for a in acts {
            let ui = &mut self.desktop.windows[SETTINGS].ui;
            match a {
                Action::Clicked(id) if id == s.apply => {
                    self.saved_name = String::from(ui.text(s.device));
                    let msg = format!("Saved · device is now “{}”", self.saved_name);
                    ui.set_text(s.status, &msg);
                    ui.set_label_color(s.status, Some(theme.color.success));
                }
                Action::Clicked(id) if id == s.revert => {
                    let name = self.saved_name.clone();
                    ui.set_text(s.device, &name);
                    ui.set_checked(s.ostp, true);
                    ui.set_checked(s.updates, false);
                    ui.set_checked(s.motion, false);
                    ui.set_checked(s.seconds, false);
                    ui.set_text(s.status, "Reverted");
                    ui.set_label_color(s.status, None);
                }
                Action::Toggled(..) | Action::TextChanged(_) => {
                    ui.set_text(s.status, "Unsaved changes");
                    ui.set_label_color(s.status, Some(theme.color.warning));
                }
                Action::Submitted(id) if id == s.device => {
                    self.saved_name = String::from(ui.text(s.device));
                    ui.set_text(s.status, "Saved");
                    ui.set_label_color(s.status, Some(theme.color.success));
                }
                Action::Selected(id, i) if id == s.sidebar => {
                    const NAMES: [&str; 7] = ["General", "Display", "Network", "Sound", "Keyboard", "Privacy", "About"];
                    ui.set_text(s.headline, NAMES[i.min(6)]);
                }
                _ => {}
            }
        }
        let f = &self.files;
        let acts = self.desktop.windows[FILES].ui.drain_actions();
        for a in acts {
            let ui = &mut self.desktop.windows[FILES].ui;
            match a {
                Action::Activated(id, i) if id == f.list => {
                    let e = &FILES_HOME[i.min(FILES_HOME.len() - 1)];
                    if e.icon == Icon::Folder {
                        let p = format!("{}/{}", self.path.last().unwrap(), e.name);
                        ui.set_text(f.path, &p);
                        self.path.push(p);
                    } else {
                        let msg = format!("{}  ·  {}", e.name, e.size);
                        ui.set_text(f.status, &msg);
                    }
                }
                Action::Selected(id, i) if id == f.list => {
                    let e = &FILES_HOME[i.min(FILES_HOME.len() - 1)];
                    let msg = format!("“{}” selected  ·  16 items  ·  2.1 GB free", e.name);
                    ui.set_text(f.status, &msg);
                }
                Action::Clicked(id) if id == f.back => {
                    if self.path.len() > 1 { self.path.pop(); }
                    let p = self.path.last().unwrap().clone();
                    ui.set_text(f.path, &p);
                }
                _ => {}
            }
        }
        let _ = self.desktop.windows[TERMINAL].ui.drain_actions();
    }

    /// Advance time, apply application logic and composite. Returns the
    /// screen rectangles to present.
    pub fn frame(&mut self, now_ms: u64, text: &mut TextEngine, theme: &Theme) -> Vec<Rect> {
        self.desktop.tick(now_ms, theme);
        self.process_actions(text, theme);
        self.desktop.render(text, theme)
    }
}
