/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Files — a small file browser written only against the oos-ui application API
(Platform::list_dir / mkdir / remove) so it can run unchanged as a ring-3 app.
*/

use alloc::string::String;
use alloc::vec::Vec;

use oos_ui::app::prelude::*;
use oos_ui::app::{fmt_size, DialogId, DialogResult};

pub struct Files {
    dir: String,
    back: Vec<String>,
    forward: Vec<String>,
    items: Vec<oos_ui::app::DirItem>,
    pending_delete: Option<(DialogId, String)>,
    // widgets
    win: WinId,
    b_back: NodeId,
    b_fwd: NodeId,
    b_up: NodeId,
    b_new: NodeId,
    path: NodeId,
    list: NodeId,
    status: NodeId,
}

impl Files {
    pub fn new(start: &str) -> Files {
        Files {
            dir: start.into(), back: Vec::new(), forward: Vec::new(), items: Vec::new(), pending_delete: None,
            win: 0, b_back: 0, b_fwd: 0, b_up: 0, b_new: 0, path: 0, list: 0, status: 0,
        }
    }

    fn join(&self, name: &str) -> String {
        if self.dir.ends_with('/') { alloc::format!("{}{}", self.dir, name) } else { alloc::format!("{}/{}", self.dir, name) }
    }

    fn parent(&self) -> String {
        let t = self.dir.trim_end_matches('/');
        match t.rfind('/') { Some(0) | None => "/".into(), Some(i) => t[..i].into() }
    }

    /// Read the directory and refill the list.
    fn refresh(&mut self, cx: &mut Ctx) {
        let mut v = cx.platform().list_dir(&self.dir).unwrap_or_default();
        v.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        let accent = cx.theme().color.accent_text;
        let rows: Vec<ListItem> = v.iter().map(|e| {
            let size = if e.is_dir { String::from("—") } else { fmt_size(e.size) };
            let kind = if e.is_dir { "Folder" } else { kind_of(&e.name) };
            let it = ListItem::new(&[&e.name, &size, kind]);
            if e.is_dir { it.icon(Icon::Folder, Some(accent)) } else { it.icon(icon_of(&e.name), None) }
        }).collect();
        let n = v.len();
        self.items = v;
        let (win, list, path, status) = (self.win, self.list, self.path, self.status);
        let (can_back, can_fwd, at_root) = (!self.back.is_empty(), !self.forward.is_empty(), self.dir == "/");
        let (b_back, b_fwd, b_up) = (self.b_back, self.b_fwd, self.b_up);
        let dir = self.dir.clone();
        if let Some(ui) = cx.ui(win) {
            if let Some(l) = ui.list_items_mut(list) { *l = rows; }
            ui.set_selected(list, if n == 0 { None } else { Some(0) });
            ui.set_text(path, &dir);
            ui.set_text(status, &alloc::format!("{} item{}", n, if n == 1 { "" } else { "s" }));
            ui.set_enabled(b_back, can_back);
            ui.set_enabled(b_fwd, can_fwd);
            ui.set_enabled(b_up, !at_root);
        }
        let title = alloc::format!("Files — {}", if dir == "/" { "/" } else { dir.rsplit('/').next().unwrap_or("/") });
        cx.set_title(win, &title);
    }

    fn go(&mut self, cx: &mut Ctx, to: &str, record: bool) {
        if cx.platform().list_dir(to).is_none() { return; }
        if record {
            self.back.push(core::mem::replace(&mut self.dir, to.into()));
            self.forward.clear();
        } else {
            self.dir = to.into();
        }
        self.refresh(cx);
    }

    fn open_selected(&mut self, cx: &mut Ctx, i: usize) {
        let Some(e) = self.items.get(i).cloned() else { return };
        let p = self.join(&e.name);
        if e.is_dir { self.go(cx, &p, true); } else { cx.platform().launch("org.ospab.editor", Some(&p)); }
    }
}

fn kind_of(name: &str) -> &'static str {
    match ext(name) {
        "txt" | "md" | "cfg" | "toml" | "log" | "conf" => "Text",
        "rs" | "c" | "h" | "sh" | "py" => "Source",
        "png" | "jpg" | "bmp" => "Image",
        "tmt" | "tar" | "gz" | "zip" => "Archive",
        "" => "File",
        _ => "File",
    }
}

fn icon_of(name: &str) -> Icon {
    match ext(name) {
        "rs" | "c" | "h" | "sh" | "py" | "toml" | "cfg" | "conf" => Icon::FileCode,
        "png" | "jpg" | "bmp" => Icon::FileImage,
        "tmt" | "tar" | "gz" | "zip" => Icon::FileArchive,
        _ => Icon::File,
    }
}

fn ext(name: &str) -> &str { name.rsplit_once('.').map(|(_, e)| e).unwrap_or("") }

impl Application for Files {
    fn info(&self) -> AppInfo { AppInfo::new("org.ospab.files", "Files", Icon::Folder) }

    fn start(&mut self, cx: &mut Ctx, arg: Option<&str>) {
        if let Some(a) = arg { self.dir = a.into(); }
        let c = cx.theme().color;
        let mut ui = Ui::new(Axis::Column, c.bg1);
        let root = ui.root();
        let bar = ui.row(root);
        ui.size(bar, Length::Fill(1), Length::Px(46));
        ui.padding(bar, Insets::xy(10, 8));
        ui.align(bar, Align::Start, Align::Center);
        ui.gap(bar, 6);
        self.b_back = ui.icon_button(bar, Icon::ChevronLeft);
        self.b_fwd = ui.icon_button(bar, Icon::ChevronRight);
        self.b_up = ui.icon_button(bar, Icon::ChevronDown);
        self.path = ui.text_field(bar, &self.dir, "Path");
        ui.width(self.path, Length::Fill(1));
        self.b_new = ui.button(bar, "New folder", ButtonKind::Secondary);
        ui.separator(root);
        self.list = ui.list(root, alloc::vec![
            Column::new("Name", Length::Fill(1)),
            Column::new("Size", Length::Px(96)).right(),
            Column::new("Kind", Length::Px(90)),
        ], true, Vec::new(), 28);
        ui.separator(root);
        let foot = ui.row(root);
        ui.size(foot, Length::Fill(1), Length::Px(30));
        ui.padding(foot, Insets::xy(14, 6));
        ui.align(foot, Align::Start, Align::Center);
        self.status = ui.label(foot, "", TextRole::Caption);
        ui.set_focus(Some(self.list));
        self.win = cx.open_window(WindowSpec::new("Files", 720, 480).min_size(420, 280), ui);
        self.refresh(cx);
    }

    fn event(&mut self, cx: &mut Ctx, win: WinId, ev: &AppEvent) {
        match ev {
            AppEvent::CloseRequested => cx.close_window(win),
            AppEvent::Action(Action::Clicked(n)) => {
                let n = *n;
                if n == self.b_back {
                    if let Some(p) = self.back.pop() {
                        self.forward.push(core::mem::replace(&mut self.dir, p));
                        self.refresh(cx);
                    }
                } else if n == self.b_fwd {
                    if let Some(p) = self.forward.pop() {
                        self.back.push(core::mem::replace(&mut self.dir, p));
                        self.refresh(cx);
                    }
                } else if n == self.b_up {
                    let p = self.parent();
                    if p != self.dir { self.go(cx, &p, true); }
                } else if n == self.b_new {
                    let mut name = String::from("New folder");
                    let mut i = 1;
                    while self.items.iter().any(|e| e.name == name) { i += 1; name = alloc::format!("New folder {}", i); }
                    let p = self.join(&name);
                    if cx.platform().mkdir(&p) { self.refresh(cx); }
                    else { cx.alert(win, "Cannot create folder", "The filesystem refused to create the folder here."); }
                }
            }
            AppEvent::Action(Action::Activated(n, i)) if *n == self.list => self.open_selected(cx, *i),
            AppEvent::Action(Action::Submitted(n)) if *n == self.path => {
                let p = cx.ui(win).map(|u| String::from(u.text(self.path))).unwrap_or_default();
                if !p.is_empty() { self.go(cx, &p, true); }
                if let Some(ui) = cx.ui(win) { ui.set_focus(Some(self.list)); }
            }
            AppEvent::Key(Event::KeyDown { key, mods, .. }) => match key {
                Key::Backspace => { let p = self.parent(); if p != self.dir { self.go(cx, &p, true); } }
                Key::Enter => {
                    let sel = cx.ui(win).and_then(|u| u.selected(self.list));
                    if let Some(i) = sel { self.open_selected(cx, i); }
                }
                Key::Char('r') if mods.ctrl => self.refresh(cx),
                Key::F(5) => self.refresh(cx),
                Key::Delete => {
                    let sel = cx.ui(win).and_then(|u| u.selected(self.list));
                    if let Some(e) = sel.and_then(|i| self.items.get(i)) {
                        let p = self.join(&e.name);
                        let msg = alloc::format!("{} will be deleted. This cannot be undone.", e.name);
                        let id = cx.confirm(win, "Delete?", &msg, "Delete", true);
                        self.pending_delete = Some((id, p));
                    }
                }
                _ => {}
            },
            AppEvent::Dialog(id, res) => {
                if let Some((did, path)) = self.pending_delete.take() {
                    if did == *id && *res == DialogResult::Ok {
                        if !cx.platform().remove(&path) { cx.alert(win, "Cannot delete", "The item could not be removed."); }
                        self.refresh(cx);
                    } else if did != *id { self.pending_delete = Some((did, path)); }
                }
            }
            _ => {}
        }
    }
}
