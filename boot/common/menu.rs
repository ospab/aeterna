/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
ospab-boot menu: boot menu, command-line editor and message screens.

Written against the `Term` trait (a text-mode screen with VGA/UEFI style attributes:
foreground | background << 4), so the UEFI and BIOS front-ends share it.
*/
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::config::{Config, ConfigError, EntryType, Theme};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    Delete,
    Backspace,
    Enter,
    Esc,
    Char(char),
    Other,
}

pub trait Term {
    /// (columns, rows)
    fn size(&self) -> (usize, usize);
    fn clear(&mut self, attr: u8);
    /// Draw `s` at (row, col); clipped at the right edge. ASCII only.
    fn put(&mut self, row: usize, col: usize, s: &str, attr: u8);
    fn set_cursor(&mut self, row: usize, col: usize, visible: bool);
    /// Wait up to `ms` milliseconds for a key. `None` on timeout.
    fn wait_key(&mut self, ms: u32) -> Option<Key>;
    /// Non-blocking.
    fn poll_key(&mut self) -> Option<Key>;
}

#[derive(Clone, Copy)]
pub struct Palette {
    pub normal: u8,
    pub selected: u8,
    pub title: u8,
    pub dim: u8,
    pub error: u8,
    pub ok: u8,
}

impl Palette {
    pub fn new(theme: Theme) -> Palette {
        match theme {
            Theme::Dark => Palette { normal: 0x07, selected: 0x70, title: 0x0F, dim: 0x08, error: 0x0C, ok: 0x0A },
            Theme::Light => Palette { normal: 0x70, selected: 0x1F, title: 0x71, dim: 0x78, error: 0x74, ok: 0x72 },
            Theme::Mono => Palette { normal: 0x07, selected: 0x70, title: 0x07, dim: 0x07, error: 0x07, ok: 0x07 },
        }
    }
}

/// What the user picked.
pub struct Choice {
    /// Index into `Config::entries`.
    pub index: usize,
    /// Command line to boot with (the entry's, or the edited one).
    pub cmdline: String,
}

fn fill_row(t: &mut dyn Term, row: usize, attr: u8) {
    let (cols, _) = t.size();
    let blanks = " ".repeat(cols);
    t.put(row, 0, &blanks, attr);
}

/// Full-screen message with a title and wrapped lines; waits for a key.
pub fn message(t: &mut dyn Term, pal: &Palette, title: &str, lines: &[String]) {
    t.clear(pal.normal);
    t.set_cursor(0, 0, false);
    t.put(1, 2, title, pal.title);
    for (i, l) in lines.iter().enumerate() {
        t.put(3 + i, 2, l, pal.normal);
    }
    let (_, rows) = t.size();
    t.put(rows - 2, 2, "Press any key.", pal.dim);
    loop {
        if t.wait_key(60_000).is_some() {
            break;
        }
    }
}

/// One-line editor (GRUB style `e`). Returns the edited text, or None on Esc.
pub fn edit_line(t: &mut dyn Term, pal: &Palette, title: &str, initial: &str) -> Option<String> {
    let mut buf: Vec<char> = initial.chars().collect();
    let mut pos = buf.len();
    let (cols, rows) = t.size();
    let width = cols.saturating_sub(6).max(20);
    loop {
        t.clear(pal.normal);
        t.put(1, 2, "Edit the kernel command line", pal.title);
        t.put(2, 2, title, pal.dim);
        t.put(rows - 3, 2, "Enter boot with this line (once, not saved)   Esc cancel   Left/Right/Home/End/Del move", pal.dim);
        // The line may be longer than the screen: show a window that follows the cursor.
        let start = if pos >= width { pos + 1 - width } else { 0 };
        let shown: String = buf.iter().skip(start).take(width).collect();
        t.put(4, 2, "> ", pal.title);
        t.put(4, 4, &shown, pal.normal);
        t.set_cursor(4, 4 + (pos - start), true);
        match t.wait_key(60_000) {
            None => continue,
            Some(Key::Enter) => {
                t.set_cursor(0, 0, false);
                return Some(buf.into_iter().collect());
            }
            Some(Key::Esc) => {
                t.set_cursor(0, 0, false);
                return None;
            }
            Some(Key::Left) => pos = pos.saturating_sub(1),
            Some(Key::Right) => pos = (pos + 1).min(buf.len()),
            Some(Key::Home) => pos = 0,
            Some(Key::End) => pos = buf.len(),
            Some(Key::Backspace) => {
                if pos > 0 {
                    buf.remove(pos - 1);
                    pos -= 1;
                }
            }
            Some(Key::Delete) => {
                if pos < buf.len() {
                    buf.remove(pos);
                }
            }
            Some(Key::Char(c)) if (' '..='~').contains(&c) && buf.len() < crate::config::MAX_CMDLINE => {
                buf.insert(pos, c);
                pos += 1;
            }
            _ => {}
        }
    }
}

pub struct MenuInfo<'a> {
    pub loader: &'a str,
    /// Where the configuration came from, shown at the bottom.
    pub source: &'a str,
    pub errors: &'a [ConfigError],
    /// Index of the entry to preselect.
    pub selected: usize,
}

fn draw(t: &mut dyn Term, pal: &Palette, cfg: &Config, vis: &[usize], sel: usize, top: usize, info: &MenuInfo,
        countdown: Option<u32>, note: &str) {
    let (cols, rows) = t.size();
    t.clear(pal.normal);
    t.set_cursor(0, 0, false);
    t.put(1, 2, "ospab loader", pal.title);
    t.put(1, 2 + 13, info.loader, pal.dim);

    // Space: rows 3.. for entries; footer needs 6 rows; errors extra.
    let err_rows = if info.errors.is_empty() { 0 } else { (info.errors.len().min(5) + 2).min(rows / 3) };
    let list_top = 3;
    let list_rows = rows.saturating_sub(list_top + 6 + err_rows).max(3);
    let width = vis.iter().map(|&i| cfg.entries[i].title.chars().count()).max().unwrap_or(10) + 6;
    let width = width.min(cols.saturating_sub(6));
    for (row, &idx) in vis.iter().enumerate().skip(top).take(list_rows) {
        let attr = if row == sel { pal.selected } else { pal.normal };
        let label = alloc::format!(" {:>2}. {:<w$}", row + 1, cfg.entries[idx].title, w = width);
        t.put(list_top + row - top, 2, &label, attr);
    }
    if top > 0 {
        t.put(list_top, 2 + width + 8, "^ more", pal.dim);
    }
    if top + list_rows < vis.len() {
        t.put(list_top + list_rows - 1, 2 + width + 8, "v more", pal.dim);
    }

    let mut r = list_top + list_rows.min(vis.len()) + 1;
    if !info.errors.is_empty() {
        t.put(r, 2, &alloc::format!("{} configuration error(s) in {}", info.errors.len(), info.source), pal.error);
        r += 1;
        for e in info.errors.iter().take(err_rows.saturating_sub(2).max(1)) {
            let l = if e.line > 0 { alloc::format!("line {}: {}", e.line, e.msg) } else { e.msg.clone() };
            t.put(r, 4, &l, pal.error);
            r += 1;
        }
        if info.errors.len() > err_rows.saturating_sub(2).max(1) {
            t.put(r, 4, "...", pal.error);
        }
    }

    let e = &cfg.entries[vis[sel]];
    t.put(rows - 5, 2, &alloc::format!("type: {}", e.typ.name()), pal.dim);
    if matches!(e.typ, EntryType::Ospab | EntryType::Memtest) {
        t.put(rows - 4, 2, &alloc::format!("cmdline: {}", e.cmdline), pal.dim);
    }
    t.put(rows - 3, 2, "Up/Down select   Enter boot   1-9 boot that entry   e edit command line   Esc stop timer", pal.dim);
    if !note.is_empty() {
        t.put(rows - 2, 2, note, pal.error);
    } else if let Some(s) = countdown {
        t.put(rows - 2, 2, &alloc::format!("Booting the selected entry in {} s", s), pal.normal);
    } else {
        t.put(rows - 2, 2, &alloc::format!("config: {}", info.source), pal.dim);
    }
    let _ = fill_row;
}

/// Show the menu. Returns the chosen entry and command line.
/// `force` shows the menu even for one entry or `timeout = 0` (set on config errors).
pub fn run(t: &mut dyn Term, pal: &Palette, cfg: &Config, info: &MenuInfo) -> Choice {
    let vis: Vec<usize> = (0..cfg.entries.len()).filter(|&i| !cfg.entries[i].hidden || i == info.selected).collect();
    let mut sel = vis.iter().position(|&i| i == info.selected).unwrap_or(0);
    let (_, rows) = t.size();
    let list_rows = rows.saturating_sub(3 + 6 + if info.errors.is_empty() { 0 } else { 7 }).max(3);
    let mut top = 0usize;
    let mut countdown = if info.errors.is_empty() { cfg.timeout } else { None };
    // Drop stale keys (a key held during POST must not choose an entry).
    while t.poll_key().is_some() {}
    let mut note = String::new();
    loop {
        if sel < top {
            top = sel;
        }
        if sel >= top + list_rows {
            top = sel + 1 - list_rows;
        }
        draw(t, pal, cfg, &vis, sel, top, info, countdown, &note);
        note.clear();
        let key = match countdown {
            Some(_) => t.wait_key(1000),
            None => t.wait_key(60_000),
        };
        let Some(key) = key else {
            if let Some(s) = countdown {
                if s <= 1 {
                    return Choice { index: vis[sel], cmdline: cfg.entries[vis[sel]].cmdline.clone() };
                }
                countdown = Some(s - 1);
            }
            continue;
        };
        if key != Key::Other {
            countdown = None; // any key stops the countdown
        }
        match key {
            Key::Enter => return Choice { index: vis[sel], cmdline: cfg.entries[vis[sel]].cmdline.clone() },
            Key::Up => sel = if sel == 0 { vis.len() - 1 } else { sel - 1 },
            Key::Down => sel = (sel + 1) % vis.len(),
            Key::Home => sel = 0,
            Key::End => sel = vis.len() - 1,
            Key::Char(c @ '1'..='9') => {
                let n = c as usize - '1' as usize;
                if n < vis.len() {
                    return Choice { index: vis[n], cmdline: cfg.entries[vis[n]].cmdline.clone() };
                }
            }
            Key::Char('k') => sel = if sel == 0 { vis.len() - 1 } else { sel - 1 },
            Key::Char('j') => sel = (sel + 1) % vis.len(),
            Key::Char('e') | Key::Char('E') => {
                let e = &cfg.entries[vis[sel]];
                if matches!(e.typ, EntryType::Ospab | EntryType::Memtest) {
                    if let Some(line) = edit_line(t, pal, &e.title, &e.cmdline) {
                        return Choice { index: vis[sel], cmdline: line };
                    }
                } else {
                    note = "This entry has no command line to edit.".to_string();
                }
            }
            _ => {}
        }
    }
}
