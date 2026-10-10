/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Terminal — runs the real plum shell in a window.

The window owns a screen of coloured lines (the oos-ui terminal widget) and a
line editor.  Enter hands the line to the session (`Request::Exec`), which
runs it through plum with the console hook installed; whatever the command
prints comes back through `take_output` and is drawn into the window while
the command is still running.  Ctrl+C is seen by the running command through
the keyboard driver, exactly as on the console.
*/

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use oos_ui::app::prelude::*;

use super::{request, take_done, take_output, Request};
use crate::userspace::plum;

const SCROLLBACK: usize = 1500;

pub struct Terminal {
    win: WinId,
    node: NodeId,
    cols: usize,
    rows: usize,
    /// Cursor column in the last line.
    col: usize,
    pending_cr: bool,
    input: String,
    history: Vec<String>,
    hist_pos: usize,
    busy: bool,
    pending_close: bool,
}

impl Terminal {
    pub fn new() -> Terminal {
        Terminal {
            win: 0, node: 0, cols: 80, rows: 24, col: 0, pending_cr: false, input: String::new(),
            history: Vec::new(), hist_pos: 0, busy: false, pending_close: false,
        }
    }

    fn map_color(theme: &Theme, c: u32) -> Color {
        let p = &theme.color;
        match c & 0x00FF_FFFF {
            0xFFFFFF | 0 => p.text,
            0xAAAAAA => p.text_secondary,
            0x00FF00 => p.success,
            0xFF4444 => p.danger_text,
            0xFFFF00 | 0xFFCC00 => p.warning,
            0x5555FF => p.accent_text,
            rgb => Color::hex(rgb),
        }
    }

    /// Append text to the screen, interpreting newline, CR, backspace and form feed.
    fn put(&mut self, ui: &mut Ui, s: &str, color: Color) {
        let node = self.node;
        let Some((lines, cursor)) = ui.terminal_mut(node) else { return };
        if lines.is_empty() { lines.push(Vec::new()); }
        for ch in s.chars() {
            match ch {
                '\n' => { self.pending_cr = false; lines.push(Vec::new()); self.col = 0; }
                '\r' => self.pending_cr = true,
                '\x08' => {
                    if let Some(last) = lines.last_mut() {
                        if let Some(sp) = last.last_mut() {
                            sp.text.pop();
                            if sp.text.is_empty() { last.pop(); }
                            self.col = self.col.saturating_sub(1);
                        }
                    }
                }
                '\x0c' => { lines.clear(); lines.push(Vec::new()); self.col = 0; }
                c if (c as u32) < 0x20 && c != '\t' => {}
                c => {
                    if self.pending_cr { lines.last_mut().unwrap().clear(); self.col = 0; self.pending_cr = false; }
                    let width = if c == '\t' { 8 - self.col % 8 } else { 1 };
                    if self.col + width > self.cols { lines.push(Vec::new()); self.col = 0; }
                    let last = lines.last_mut().unwrap();
                    let mut buf = [0u8; 4];
                    let text: &str = if c == '\t' { &"        "[..width] } else { c.encode_utf8(&mut buf) };
                    match last.last_mut() {
                        Some(sp) if sp.color == color => sp.text.push_str(text),
                        _ => last.push(Span { text: text.into(), color }),
                    }
                    self.col += width;
                }
            }
        }
        if lines.len() > SCROLLBACK { let n = lines.len() - SCROLLBACK; lines.drain(..n); }
        *cursor = Some((lines.len() - 1, self.col));
        ui.set_terminal_scroll(node, 0);
    }

    fn prompt(&mut self, ui: &mut Ui, theme: &Theme) {
        let c = &theme.color;
        // Start on a fresh line if the command left the cursor mid-line.
        if self.col != 0 { self.put(ui, "\n", c.text); }
        let cwd = String::from(plum::cwd());
        self.put(ui, "ospab@aeterna", c.accent_text);
        self.put(ui, ":", c.text_secondary);
        self.put(ui, &cwd, c.text);
        self.put(ui, "$ ", c.text_secondary);
        let line = self.input.clone();
        self.put(ui, &line, c.text);
    }

    fn submit(&mut self, cx: &mut Ctx) {
        let theme = *cx.theme();
        let line = core::mem::take(&mut self.input);
        let win = self.win;
        let (cols, rows) = (self.cols, self.rows);
        let Some(ui) = cx.ui(win) else { return };
        self.put(ui, "\n", theme.color.text);
        let t = line.trim();
        if t.is_empty() { self.prompt(ui, &theme); return; }
        if self.history.last().map(|h| h != t).unwrap_or(true) { self.history.push(String::from(t)); }
        self.hist_pos = self.history.len();
        match t {
            "exit" | "logout" => { self.pending_close = true; }
            "desktop" => { self.put(ui, "desktop: already running\n", theme.color.danger_text); self.prompt(ui, &theme); }
            _ => {
                self.busy = true;
                request(Request::Exec(win, String::from(t), cols, rows));
            }
        }
    }

    fn set_input(&mut self, ui: &mut Ui, s: &str, theme: &Theme) {
        // Erase the old input from the screen, write the new one.
        for _ in 0..self.input.chars().count() { self.put(ui, "\x08", theme.color.text); }
        self.input = String::from(s);
        self.put(ui, s, theme.color.text);
    }

    fn type_text(&mut self, ui: &mut Ui, s: &str, theme: &Theme) {
        for ch in s.chars().filter(|c| !c.is_control()) {
            self.input.push(ch);
            let mut b = [0u8; 4];
            self.put(ui, ch.encode_utf8(&mut b), theme.color.text);
        }
    }
}

impl Application for Terminal {
    fn info(&self) -> AppInfo { AppInfo::new("org.ospab.terminal", "Terminal", Icon::Terminal) }

    fn start(&mut self, cx: &mut Ctx, _arg: Option<&str>) {
        let theme = *cx.theme();
        let mut ui = Ui::new(Axis::Column, Color::hex(0x0E0F11));
        let root = ui.root();
        let t = ui.terminal(root, alloc::vec![Vec::new()]);
        ui.padding(t, Insets::xy(16, 12));
        self.node = t;
        self.win = cx.open_window(WindowSpec::new("Terminal", 760, 460).min_size(320, 200), ui);
        let win = self.win;
        // The widget has no size until the first layout; estimate from the window size.
        let (cw, ch) = cx.mono_cell();
        self.cols = ((760 - 32) / cw.max(1)) as usize;
        self.rows = ((460 - 38 - 24) / ch.max(1)) as usize;
        if let Some(ui) = cx.ui(win) {
            let c = &theme.color;
            self.put(ui, super::ver::OS_VERSION, c.accent_text);
            self.put(ui, "  AETERNA kernel ", c.text_secondary);
            self.put(ui, super::ver::VERSION_STR, c.text_secondary);
            self.put(ui, "\nplum shell. Type help for commands.\n\n", c.text_secondary);
            self.prompt(ui, &theme);
        }
    }

    fn event(&mut self, cx: &mut Ctx, win: WinId, ev: &AppEvent) {
        let theme = *cx.theme();
        match ev {
            AppEvent::CloseRequested => cx.close_window(win),
            AppEvent::Resized(..) => { let (c, r) = cx.grid_size(win, self.node); self.cols = c; self.rows = r; }
            AppEvent::Key(Event::KeyDown { key, mods, text }) if !self.busy => {
                if *key == Key::Enter { self.submit(cx); return; }
                let Some(ui) = cx.ui(win) else { return };
                match (*key, mods.ctrl) {
                    (Key::Backspace, _) => {
                        if self.input.pop().is_some() { self.put(ui, "\x08", theme.color.text); }
                    }
                    (Key::Char('c'), true) => {
                        self.put(ui, "^C\n", theme.color.text_secondary);
                        self.input.clear();
                        self.prompt(ui, &theme);
                    }
                    (Key::Char('l'), true) => {
                        let keep = core::mem::take(&mut self.input);
                        self.put(ui, "\x0c", theme.color.text);
                        self.input = keep;
                        self.prompt(ui, &theme);
                    }
                    (Key::Char('u'), true) => self.set_input(ui, "", &theme),
                    (Key::Char('v'), true) => { let cb = clipboard_get(); self.type_text(ui, &cb, &theme); }
                    (Key::Up, _) => {
                        if self.hist_pos > 0 {
                            self.hist_pos -= 1;
                            let h = self.history[self.hist_pos].clone();
                            self.set_input(ui, &h, &theme);
                        }
                    }
                    (Key::Down, _) => {
                        if self.hist_pos < self.history.len() {
                            self.hist_pos += 1;
                            let h = self.history.get(self.hist_pos).cloned().unwrap_or_default();
                            self.set_input(ui, &h, &theme);
                        }
                    }
                    (Key::PageUp, _) => ui.set_terminal_scroll(self.node, self.rows.saturating_sub(2)),
                    (Key::PageDown, _) => ui.set_terminal_scroll(self.node, 0),
                    (_, false) if text.is_some() => {
                        let c = text.unwrap();
                        let mut b = [0u8; 4];
                        self.type_text(ui, c.encode_utf8(&mut b), &theme);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn tick(&mut self, cx: &mut Ctx) {
        let win = self.win;
        if win == 0 { return; }
        let theme = *cx.theme();
        if self.pending_close { self.pending_close = false; cx.close_window(win); return; }
        if !self.busy {
            // Follow the window size (the widget is laid out by now).
            let (c, r) = cx.grid_size(win, self.node);
            if c >= 20 { self.cols = c; self.rows = r; }
        }
        let out = take_output(win);
        let done = take_done(win);
        if out.is_empty() && done.is_none() { return; }
        let Some(ui) = cx.ui(win) else { return };
        for (s, c) in out {
            let col = Self::map_color(&theme, c);
            self.put(ui, &s, col);
        }
        if let Some(status) = done {
            self.busy = false;
            if status != 0 && status != 130 {
                if self.col != 0 { self.put(ui, "\n", theme.color.text); }
                self.put(ui, &format!("[exit {}]\n", status), theme.color.text_secondary);
            }
            self.prompt(ui, &theme);
        }
    }
}
