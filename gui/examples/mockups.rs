// SPDX-License-Identifier: AGPL-3.0-only
//! Render the reference mockups to PNG on the host.
//!
//!   cd gui && cargo +stable run --release --features std --example mockups [outdir]
//!
//! Writes desktop.png, desktop-launcher.png and gallery.png (default outdir:
//! gui/mockups) and prints host render timings.

use std::time::Instant;

use oos_ui::canvas::Canvas;
use oos_ui::color::Color;
use oos_ui::demo::build_session;
use oos_ui::event::{Event, Key, Modifiers, MouseButton};
use oos_ui::fonts::default_text_engine;
use oos_ui::geom::{Insets, Rect};
use oos_ui::icons::Icon;
use oos_ui::menu::MenuItem;
use oos_ui::surface::Surface;
use oos_ui::text::TextEngine;
use oos_ui::theme::{Theme, DARK};
use oos_ui::ui::*;

fn save_png(path: &str, s: &Surface) {
    let mut bytes = Vec::with_capacity((s.width * s.height * 4) as usize);
    for y in 0..s.height {
        for x in 0..s.width {
            let p = s.pixel(x, y);
            let a = p >> 24;
            let un = |c: u32| if a == 0 { 0 } else { ((c * 255 + a / 2) / a).min(255) as u8 };
            bytes.extend_from_slice(&[un((p >> 16) & 0xFF), un((p >> 8) & 0xFF), un(p & 0xFF), a as u8]);
        }
    }
    let f = std::fs::File::create(path).expect("create png");
    let mut enc = png::Encoder::new(std::io::BufWriter::new(f), s.width as u32, s.height as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.set_compression(png::Compression::High);
    enc.write_header().unwrap().write_image_data(&bytes).unwrap();
    println!("wrote {path}");
}

fn desktop(out: &str, text: &mut TextEngine, theme: &Theme) {
    let t0 = Instant::now();
    let (mut s, ids) = build_session(1280, 800, text, theme);
    let build = t0.elapsed();
    let t1 = Instant::now();
    s.frame(0, text, theme);
    let first = t1.elapsed();
    s.desktop.invalidate_all();
    let t2 = Instant::now();
    s.frame(0, text, theme);
    let full = t2.elapsed();
    let t3 = Instant::now();
    let n = 200;
    for i in 0..n {
        s.input(&Event::PointerMove { x: 300 + i, y: 200 + i / 2 }, text, theme);
        s.frame(16 * i as u64, text, theme);
    }
    let mv = t3.elapsed() / n as u32;
    println!("host: build {:?}, first frame {:?}, recomposite {:?}, cursor-move frame {:?}", build, first, full, mv);

    let fr = s.desktop.window(ids[2]).unwrap().rect;
    s.input(&Event::PointerMove { x: fr.x + 220, y: fr.y + 46 + 28 + 4 + 28 + 14 }, text, theme);
    s.frame(0, text, theme);
    save_png(&format!("{out}/desktop.png"), &s.desktop.back);

    // Launcher open, Settings raised.
    let sr = s.desktop.window(ids[1]).unwrap().rect;
    s.input(&Event::PointerDown { x: sr.x + 300, y: sr.y + 15, button: MouseButton::Left }, text, theme);
    s.frame(5_000, text, theme);
    s.input(&Event::PointerUp { x: sr.x + 300, y: sr.y + 15, button: MouseButton::Left }, text, theme);
    s.frame(5_100, text, theme);
    s.desktop.open_launcher(text, theme);
    s.input(&Event::PointerMove { x: 60, y: 30 + 6 + 28 + 14 }, text, theme);
    s.frame(10_000, text, theme);
    save_png(&format!("{out}/desktop-launcher.png"), &s.desktop.back);

    // Alt+Tab switcher over the dock hover.
    s.input(&Event::KeyDown { key: Key::Escape, mods: Modifiers::NONE, text: None }, text, theme);
    let alt = Modifiers { alt: true, ..Modifiers::NONE };
    s.input(&Event::KeyDown { key: Key::Tab, mods: alt, text: None }, text, theme);
    s.input(&Event::PointerMove { x: 640 - 26, y: 800 - 40 }, text, theme);
    s.frame(11_000, text, theme);
    save_png(&format!("{out}/desktop-switcher.png"), &s.desktop.back);
}

fn section(ui: &mut Ui, parent: NodeId, title: &str) -> NodeId {
    let col = ui.column(parent);
    ui.gap(col, 10);
    ui.label(col, title, TextRole::Caption);
    let row = ui.row(col);
    ui.gap(row, 10);
    ui.align(row, Align::Start, Align::Center);
    row
}

fn gallery(out: &str, text: &mut TextEngine, theme: &Theme) {
    let (w, h) = (1100, 820);
    let c = &theme.color;
    let mut ui = Ui::new(Axis::Column, c.bg1);
    let root = ui.root();
    ui.padding(root, Insets::all(32));
    ui.gap(root, 22);
    ui.align(root, Align::Start, Align::Start);
    let head = ui.column(root);
    ui.gap(head, 4);
    ui.label(head, "oos-ui widget gallery", TextRole::Headline);
    ui.label(head, "Dark minimalism · Inter and JetBrains Mono · software rendered, no GPU", TextRole::Secondary);

    let r = section(&mut ui, root, "BUTTONS — normal · hover · pressed · focus · disabled");
    let b = |ui: &mut Ui, l: &str, k: ButtonKind, f: u8, en: bool| {
        let id = ui.button(r, l, k);
        ui.force_state(id, f);
        ui.set_enabled(id, en);
        id
    };
    b(&mut ui, "Apply", ButtonKind::Primary, 0, true);
    b(&mut ui, "Apply", ButtonKind::Primary, FORCE_HOVER, true);
    b(&mut ui, "Apply", ButtonKind::Primary, FORCE_HOVER | FORCE_PRESSED, true);
    b(&mut ui, "Apply", ButtonKind::Primary, FORCE_FOCUS, true);
    b(&mut ui, "Cancel", ButtonKind::Secondary, 0, true);
    b(&mut ui, "Cancel", ButtonKind::Secondary, FORCE_HOVER, true);
    b(&mut ui, "Cancel", ButtonKind::Secondary, FORCE_HOVER | FORCE_PRESSED, true);
    b(&mut ui, "Delete", ButtonKind::Danger, 0, true);
    b(&mut ui, "More", ButtonKind::Ghost, FORCE_HOVER, true);
    b(&mut ui, "Disabled", ButtonKind::Secondary, 0, false);
    let ib = ui.icon_button(r, Icon::Search);
    ui.force_state(ib, FORCE_HOVER);
    ui.icon_button(r, Icon::Settings);

    let r = section(&mut ui, root, "TEXT FIELDS — placeholder · focused with caret · selection · disabled");
    let f1 = ui.text_field(r, "", "Search files");
    ui.width(f1, Length::Px(200));
    let f2 = ui.text_field(r, "ospab-aeterna", "");
    ui.width(f2, Length::Px(200));
    ui.force_state(f2, FORCE_FOCUS);
    let f3 = ui.text_field(r, "Привет, мир — hello", "");
    ui.width(f3, Length::Px(220));
    ui.force_state(f3, FORCE_FOCUS);
    ui.set_selection(f3, 0, 6);
    let f4 = ui.text_field(r, "read-only value", "");
    ui.width(f4, Length::Px(180));
    ui.set_enabled(f4, false);

    let r = section(&mut ui, root, "SELECTION — checkbox · toggle (off · on · focus · disabled) · progress");
    ui.checkbox(r, "Unchecked", false);
    ui.checkbox(r, "Checked", true);
    let cb = ui.checkbox(r, "Focused", true);
    ui.force_state(cb, FORCE_FOCUS);
    let cd = ui.checkbox(r, "Disabled", false);
    ui.set_enabled(cd, false);
    let sp = ui.spacer(r);
    ui.size(sp, Length::Px(16), Length::Px(1));
    ui.toggle(r, false);
    ui.toggle(r, true);
    let tf = ui.toggle(r, true);
    ui.force_state(tf, FORCE_FOCUS);
    let td = ui.toggle(r, false);
    ui.set_enabled(td, false);
    let pg = ui.progress(r, 0.62);
    ui.width(pg, Length::Px(140));

    // List + menu + type scale side by side.
    let row = ui.row(root);
    ui.gap(row, 28);
    ui.size(row, Length::Fill(1), Length::Px(300));
    let lc = ui.column(row);
    ui.width(lc, Length::Px(420));
    ui.gap(lc, 10);
    ui.label(lc, "LIST VIEW — header · hover · selection · overlay scroll bar", TextRole::Caption);
    let card = ui.container(lc, Axis::Column, BoxStyle { bg: Some(c.surface), border: Some(c.hairline), radius: theme.radius.lg });
    ui.size(card, Length::Fill(1), Length::Fill(1));
    ui.padding(card, Insets::xy(0, 4));
    let cols = vec![Column::new("Name", Length::Fill(1)), Column::new("Size", Length::Px(80)).right()];
    let names = ["Documents", "Изображения", "kernel.elf", "notes.md", "screenshot.png", "archive.tar", "build.log", "music", "readme.txt", "Cargo.lock", "init.cfg", "zzz.bin"];
    let items: Vec<ListItem> = names.iter().enumerate().map(|(i, n)| {
        let folder = i == 0 || i == 1 || i == 7;
        let it = ListItem::new(&[n, if folder { "—" } else { "12 KB" }]);
        if folder { it.icon(Icon::Folder, Some(c.accent_text)) } else { it.icon(Icon::File, None) }
    }).collect();
    let list = ui.list(card, cols, true, items, 28);
    ui.set_selected(list, Some(2));
    ui.force_state(list, FORCE_FOCUS | FORCE_HOVER);

    let mc = ui.column(row);
    ui.width(mc, Length::Px(210));
    ui.gap(mc, 10);
    ui.label(mc, "MENU / POPOVER", TextRole::Caption);
    let mb = ui.button(mc, "Options", ButtonKind::Secondary);
    ui.width(mb, Length::Px(110));

    let tc = ui.column(row);
    ui.width(tc, Length::Fill(1));
    ui.gap(tc, 6);
    ui.label(tc, "TYPE SCALE", TextRole::Caption);
    ui.label(tc, "Headline 20 — Системные настройки", TextRole::Headline);
    ui.label(tc, "Title 15 semibold — Network", TextRole::Title);
    ui.label(tc, "Body 13 — The quick brown fox jumps over the lazy dog", TextRole::Body);
    ui.label(tc, "Strong 13 — Съешь же ещё этих мягких булок", TextRole::Strong);
    ui.label(tc, "Secondary 13 — tomato checks tmt.ospab.org daily", TextRole::Secondary);
    ui.label(tc, "Caption 11 — 16 items · 2.1 GB free", TextRole::Caption);
    ui.label(tc, "Mono 13 — fn main() -> ! { loop {} } 0O1lI", TextRole::Mono);
    let p = ui.paragraph(tc, "Wrapping: long text is broken at spaces to fit its box, and a single label can also be cut with an ellipsis when it would overflow its column width.", TextRole::Secondary);
    ui.width(p, Length::Fill(1));
    let el = ui.label(tc, "Ellipsis: /home/ospab/projects/aeterna/core/scheduler/mod.rs and more", TextRole::Body);
    ui.width(el, Length::Px(300));

    // Token swatches.
    let sw = section(&mut ui, root, "COLOUR TOKENS");
    let toks: [(&str, Color); 12] = [
        ("bg0", c.bg0), ("bg1", c.bg1), ("surface", c.surface), ("elevated", c.elevated), ("field", c.field), ("control", c.control),
        ("text", c.text), ("secondary", c.text_secondary), ("accent", c.accent), ("accent text", c.accent_text), ("danger", c.danger), ("success", c.success),
    ];
    for (name, color) in toks {
        let col = ui.column(sw);
        ui.gap(col, 6);
        let chip = ui.container(col, Axis::Stack, BoxStyle { bg: Some(color), border: Some(c.hairline_strong), radius: theme.radius.md });
        ui.size(chip, Length::Px(66), Length::Px(36));
        ui.label(col, name, TextRole::Caption);
    }

    let mut s = Surface::new(w, h);
    ui.layout(text, theme, Rect::from_size(w, h));
    let anchor = ui.node(mb).bounds;
    ui.open_menu(mb, anchor, vec![
        MenuItem::new("New window").icon(Icon::Plus).shortcut("Ctrl N"),
        MenuItem::new("Open…").icon(Icon::Folder).shortcut("Ctrl O"),
        MenuItem::new("Show hidden files").checked(true),
        MenuItem::separator(),
        MenuItem::new("Properties").icon(Icon::Info),
        MenuItem::new("Move to trash").disabled(),
    ], text, theme);
    ui.set_menu_hover(Some(1));
    ui.set_hover_row(list, Some(5));
    {
        let mut cv = Canvas::new(s.view_mut());
        ui.invalidate_all();
        ui.render(&mut cv, text, theme);
    }
    save_png(&format!("{out}/gallery.png"), &s);
}

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/mockups").to_string());
    std::fs::create_dir_all(&out).unwrap();
    let theme = DARK;
    let mut text = default_text_engine();
    desktop(&out, &mut text, &theme);
    gallery(&out, &mut text, &theme);
}
