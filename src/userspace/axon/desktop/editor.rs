/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Text Editor — a plain-text editor on the oos-ui application API.
Ctrl+S saves, Ctrl+W closes (asks first when there are unsaved changes).
*/

use alloc::string::String;

use oos_ui::app::prelude::*;
use oos_ui::app::{DialogId, DialogResult};

pub struct Editor {
    path: Option<String>,
    saved: String,
    win: WinId,
    editor: NodeId,
    status: NodeId,
    save_btn: NodeId,
    timer: u32,
    dirty: bool,
    close_dialog: Option<DialogId>,
}

impl Editor {
    pub fn new() -> Editor {
        Editor { path: None, saved: String::new(), win: 0, editor: 0, status: 0, save_btn: 0, timer: 0, dirty: false, close_dialog: None }
    }

    fn name(&self) -> &str {
        self.path.as_deref().and_then(|p| p.rsplit('/').next()).unwrap_or("Untitled")
    }

    fn save(&mut self, cx: &mut Ctx) {
        let Some(path) = self.path.clone() else {
            cx.alert(self.win, "Save", "This document has no file name. Open a file from Files to edit it.");
            return;
        };
        let text = cx.ui(self.win).map(|u| u.editor_text(self.editor)).unwrap_or_default();
        if cx.platform().write_file(&path, text.as_bytes()) {
            self.saved = text;
        } else {
            cx.alert(self.win, "Save failed", "The file could not be written.");
        }
        self.sync(cx);
    }

    /// Refresh dirty flag, title and status line.
    fn sync(&mut self, cx: &mut Ctx) {
        let (win, ed, st) = (self.win, self.editor, self.status);
        let Some(ui) = cx.ui(win) else { return };
        let text = ui.editor_text(ed);
        let dirty = text != self.saved;
        let (row, col) = ui.editor_pos(ed);
        let lines = text.lines().count().max(1);
        let msg = alloc::format!("Ln {}, Col {}    {} lines    {} bytes{}", row + 1, col + 1, lines, text.len(), if dirty { "    modified" } else { "" });
        ui.set_text(st, &msg);
        let save = self.save_btn;
        ui.set_enabled(save, dirty && self.path.is_some());
        if dirty != self.dirty {
            self.dirty = dirty;
            let t = alloc::format!("{}{} — Text Editor", if dirty { "• " } else { "" }, self.name());
            cx.set_title(win, &t);
        }
    }
}

impl Application for Editor {
    fn info(&self) -> AppInfo { AppInfo::new("org.ospab.editor", "Text Editor", Icon::FileCode) }

    fn start(&mut self, cx: &mut Ctx, arg: Option<&str>) {
        let mut body = String::new();
        if let Some(p) = arg {
            self.path = Some(p.into());
            if let Some(d) = cx.platform().read_file(p) { body = String::from_utf8_lossy(&d).into_owned(); }
        }
        self.saved = body.replace('\r', "");
        let c = cx.theme().color;
        let mut ui = Ui::new(Axis::Column, c.bg1);
        let root = ui.root();
        let bar = ui.row(root);
        ui.size(bar, Length::Fill(1), Length::Px(44));
        ui.padding(bar, Insets::xy(12, 8));
        ui.align(bar, Align::Start, Align::Center);
        ui.gap(bar, 8);
        self.save_btn = ui.button(bar, "Save", ButtonKind::Primary);
        let p = self.path.clone().unwrap_or_else(|| "No file".into());
        let l = ui.label(bar, &p, TextRole::Secondary);
        ui.width(l, Length::Fill(1));
        ui.separator(root);
        self.editor = ui.editor(root, &self.saved);
        ui.separator(root);
        let foot = ui.row(root);
        ui.size(foot, Length::Fill(1), Length::Px(28));
        ui.padding(foot, Insets::xy(14, 5));
        ui.align(foot, Align::Start, Align::Center);
        self.status = ui.label(foot, "", TextRole::Caption);
        ui.set_focus(Some(self.editor));
        let title = alloc::format!("{} — Text Editor", self.name());
        self.win = cx.open_window(WindowSpec::new(&title, 700, 480).min_size(360, 240), ui);
        self.timer = cx.set_timer(300, true);
        self.sync(cx);
    }

    fn event(&mut self, cx: &mut Ctx, win: WinId, ev: &AppEvent) {
        match ev {
            AppEvent::CloseRequested if win == self.win => {
                self.sync(cx);
                if self.dirty && self.close_dialog.is_none() {
                    self.close_dialog = Some(cx.confirm(win, "Discard changes?", "The document has unsaved changes.", "Discard", true));
                } else if !self.dirty { cx.close_window(win); }
            }
            AppEvent::Dialog(id, res) if Some(*id) == self.close_dialog => {
                self.close_dialog = None;
                if *res == DialogResult::Ok { cx.close_window(self.win); }
            }
            AppEvent::Action(Action::Clicked(n)) if *n == self.save_btn => self.save(cx),
            AppEvent::Timer(_) => self.sync(cx),
            AppEvent::Key(Event::KeyDown { key: Key::Char('s'), mods, .. }) if mods.ctrl => self.save(cx),
            AppEvent::Key(Event::KeyDown { key: Key::Char('w'), mods, .. }) if mods.ctrl => {
                self.event(cx, win, &AppEvent::CloseRequested);
            }
            _ => {}
        }
    }
}
