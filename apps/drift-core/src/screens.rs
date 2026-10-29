// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Menus and station screens: title, main menu, intro, settings, charts, market, equipment, contracts, ending.
use crate::commander::*;
use crate::econ::*;
use crate::galaxy::*;
use crate::game::*;
use crate::gfx::*;
use crate::math::*;
use crate::menus::*;
use crate::raster::Camera;
use crate::story;
use crate::view::*;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

const ECO_COL: [u32; 8] = [
    rgb(214, 170, 90),
    rgb(110, 210, 120),
    rgb(170, 170, 180),
    rgb(240, 120, 80),
    rgb(100, 180, 255),
    rgb(190, 130, 255),
    rgb(255, 130, 200),
    rgb(160, 120, 90),
];

impl Game {
    pub(crate) fn draw_screen(&mut self, c: &mut Canvas, ui: &Ui, _cam: &Camera) {
        match self.screen {
            Screen::Flight => {}
            Screen::Title => self.draw_title(c, ui),
            Screen::MainMenu => self.draw_main_menu(c, ui),
            Screen::Intro => self.draw_intro(c, ui),
            Screen::Settings => self.draw_settings(c, ui),
            Screen::Controls => self.draw_controls(c, ui),
            Screen::Credits => self.draw_credits(c, ui),
            Screen::Load => self.draw_slots(c, ui, false),
            Screen::Save => {
                self.draw_tabs(c, ui);
                self.draw_slots(c, ui, true)
            }
            Screen::Pause => self.draw_pause(c, ui),
            Screen::Briefing => self.draw_briefing(c, ui),
            Screen::Dead => self.draw_dead(c, ui),
            Screen::Ending => self.draw_ending(c, ui),
            Screen::FreePlay => self.draw_freeplay(c, ui),
            _ => {
                self.draw_tabs(c, ui);
                match self.screen {
                    Screen::Status => self.draw_status(c, ui),
                    Screen::GalChart => self.draw_chart(c, ui, false),
                    Screen::LocalChart => self.draw_chart(c, ui, true),
                    Screen::SysInfo => self.draw_sysinfo(c, ui),
                    Screen::Market => self.draw_market(c, ui),
                    Screen::Equipment => self.draw_equipment(c, ui),
                    Screen::Contracts => self.draw_contracts(c, ui),
                    _ => {}
                }
                self.draw_hints(c, ui);
            }
        }
        if self.docked || !matches!(self.screen, Screen::Flight | Screen::Pause) {
            self.draw_log_bottom(c, ui);
        }
    }

    fn draw_log_bottom(&self, c: &mut Canvas, ui: &Ui) {
        if matches!(self.screen, Screen::Title | Screen::MainMenu | Screen::Intro | Screen::Credits | Screen::Ending) {
            return;
        }
        let mut y = c.h as i32 - ui.px(34.0) - ui.fs * 2;
        for l in self.log.iter().rev().take(2) {
            c.text_c(c.w as i32 / 2, y, ui.fs, &l.text, if l.warn { C_AMBER } else { C_ACCENT }, 230);
            y -= ui.fs + 4;
        }
    }

    fn dim(&self, c: &mut Canvas, a: u32) {
        let (w, h) = (c.w as i32, c.h as i32);
        c.rect(0, 0, w, h, rgb(4, 6, 12), a);
    }

    fn footer(&self, c: &mut Canvas, ui: &Ui) {
        let t = format!("\x7f 2026 ospab    AGPL-3.0-only");
        c.text_c(c.w as i32 / 2, c.h as i32 - ui.fs - ui.px(10.0), ui.fs - 2, &t, C_DIM, 200);
    }

    fn menu_list(&self, c: &mut Canvas, ui: &Ui, items: &[&str], y0: i32, enabled: &dyn Fn(usize) -> bool) {
        let cx = c.w as i32 / 2;
        let fs = ui.fs + ui.px(4.0);
        let lh = fs * 2;
        for (i, it) in items.iter().enumerate() {
            let y = y0 + i as i32 * lh;
            let sel = i == self.sel;
            let en = enabled(i);
            let col = if !en { rgb(70, 82, 104) } else if sel { C_ACCENT } else { C_TEXT };
            if sel {
                let w = (it.len() as i32 + 6) * fs;
                c.rect(cx - w / 2, y - fs / 3, w, fs + fs * 2 / 3, rgb(20, 46, 56), 200);
                c.rect(cx - w / 2, y - fs / 3, 3, fs + fs * 2 / 3, C_ACCENT, 255);
            }
            c.text_c(cx, y, fs, it, col, 255);
        }
    }

    // ------------------------------------------------------------------ title and menus

    fn draw_title(&mut self, c: &mut Canvas, ui: &Ui) {
        self.dim(c, 70);
        let cx = c.w as i32 / 2;
        let big = ui.px(86.0);
        // letter-spaced title with a glow
        let letters = "DRIFT";
        let adv = big + big / 3;
        let x0 = cx - (adv * 5) / 2 + (adv - big) / 2;
        let y = c.h as i32 / 3 - big / 2;
        for (i, ch) in letters.chars().enumerate() {
            let s: String = ch.into();
            c.text(x0 + i as i32 * adv + 3, y + 4, big, &s, rgb(10, 40, 50), 160);
            c.text(x0 + i as i32 * adv, y, big, &s, C_ACCENT, 255);
        }
        c.rect(cx - adv * 5 / 2, y + big + ui.px(10.0), adv * 5, 2, C_ACCENT, 160);
        c.text_c(cx, y + big + ui.px(22.0), ui.fs + 3, "A SPACE TRADING AND COMBAT GAME", C_TEXT, 230);
        let blink = ((self.ui_t * 1.6) as i32) % 2 == 0;
        if blink {
            c.text_c(cx, c.h as i32 * 3 / 4, ui.fs + 4, "PRESS ENTER", C_TEXT, 255);
        }
        self.footer(c, ui);
    }

    fn draw_main_menu(&mut self, c: &mut Canvas, ui: &Ui) {
        self.dim(c, 110);
        let cx = c.w as i32 / 2;
        c.text_c(cx, ui.px(60.0), ui.px(40.0), "DRIFT", C_ACCENT, 255);
        let has_save = self.latest_slot().is_some();
        let panel_w = ui.px(360.0);
        panel(c, cx - panel_w / 2, ui.px(150.0), panel_w, ui.px(290.0), 170);
        self.menu_list(c, ui, &MAIN_ITEMS, ui.px(178.0), &|i| i != 1 || has_save);
        if let Some(i) = self.latest_slot() {
            if let Some(s) = &self.slots[i] {
                let t = format!("Last: {} - {} - {} cr", s.name, self.gal_name_of(s), s.credits);
                c.text_c(cx, ui.px(458.0), ui.fs - 1, &t, C_DIM, 255);
            }
        }
        c.text_c(cx, c.h as i32 - ui.px(60.0), ui.fs - 1, "Up/Down: select   Enter: confirm   Esc: back", C_DIM, 230);
        self.footer(c, ui);
    }

    fn gal_name_of(&self, s: &Commander) -> String {
        if s.galaxy as usize == self.gal.index {
            self.gal.sys[s.system as usize].name.clone()
        } else {
            format!("galaxy {}", s.galaxy + 1)
        }
    }

    fn draw_intro(&mut self, c: &mut Canvas, ui: &Ui) {
        self.dim(c, 150);
        let cx = c.w as i32 / 2;
        let page = self.page.min(story::INTRO.len() - 1);
        let w = ui.px(640.0).min(c.w as i32 - 40);
        let cols = (w / ui.fs) as usize - 2;
        let lines = wrap(story::INTRO[page], cols);
        let y0 = c.h as i32 / 2 - (lines.len() as i32 * ui.lh) / 2;
        let fade = clamp(self.ui_t * 1.5, 0.0, 1.0);
        for (i, l) in lines.iter().enumerate() {
            c.text_c(cx, y0 + i as i32 * ui.lh, ui.fs + 1, l, C_TEXT, (fade * 255.0) as u32);
        }
        c.text_c(cx, c.h as i32 - ui.px(70.0), ui.fs - 1, &format!("{} / {}   Enter: next   Esc: skip", page + 1, story::INTRO.len()), C_DIM, 230);
    }

    fn draw_settings(&mut self, c: &mut Canvas, ui: &Ui) {
        self.dim(c, 190);
        let cx = c.w as i32 / 2;
        c.text_c(cx, ui.px(50.0), ui.px(28.0), "SETTINGS", C_ACCENT, 255);
        let on = |b: bool| if b { "On" } else { "Off" };
        let q = ["Low", "Medium", "High"][self.settings.quality as usize % 3];
        let rows = [
            format!("Invert pitch:       {}", on(self.settings.invert_pitch)),
            format!("Bloom:              {}", on(self.settings.bloom)),
            format!("Retro wireframe:    {}", on(self.settings.retro)),
            format!("3D resolution:      {}", q),
            String::from("Controls and key map"),
            String::from("Back"),
        ];
        let items: Vec<&str> = rows.iter().map(|s| s.as_str()).collect();
        let pw = ui.px(520.0);
        panel(c, cx - pw / 2, ui.px(110.0), pw, ui.px(300.0), 170);
        self.menu_list(c, ui, &items, ui.px(138.0), &|_| true);
        c.text_c(cx, ui.px(430.0), ui.fs - 1, "Left/Right or Enter changes a value. There is no audio in this version.", C_DIM, 230);
    }

    fn draw_controls(&mut self, c: &mut Canvas, ui: &Ui) {
        self.dim(c, 215);
        let cx = c.w as i32 / 2;
        c.text_c(cx, ui.px(24.0), ui.px(24.0), "KEY MAP", C_ACCENT, 255);
        let left = [
            ("Flight", ""),
            ("Left / Right", "roll"),
            ("Up / Down", "pitch (Down climbs)"),
            ("A / Z", "throttle up / down"),
            ("Space", "fire lasers (view's mount)"),
            ("T / Y", "lock target / clear lock"),
            ("M", "fire missile (needs lock)"),
            ("C", "release chaff"),
            ("J (hold)", "in-system jump (no mass lock)"),
            ("H", "hyperspace to chart target"),
            ("G", "galactic drive"),
            ("D", "docking computer on/off"),
            ("E", "eject in escape capsule"),
            ("P or Esc", "pause menu"),
        ];
        let right = [
            ("Screens", ""),
            ("F1", "front view / launch"),
            ("F2 F3 F4", "rear, left, right view"),
            ("F5", "status"),
            ("F6", "galactic chart"),
            ("F7", "local chart"),
            ("F8", "system data"),
            ("F9", "market (docked)"),
            ("F10", "equipment (docked)"),
            ("F11", "contracts (docked)"),
            ("F12", "save (docked)"),
            ("Chart: arrows", "move, Enter picks target, Home"),
            ("Market: B S", "buy / sell (Shift: 10 / all)"),
            ("Equipment", "Enter buy, Del remove laser"),
            ("Tab", "this screen"),
        ];
        let col_w = ui.px(430.0);
        let x1 = cx - col_w - ui.px(10.0);
        let x2 = cx + ui.px(10.0);
        for (x, list) in [(x1, &left[..]), (x2, &right[..])] {
            panel(c, x, ui.px(64.0), col_w, ui.px(410.0), 175);
            for (i, (k, v)) in list.iter().enumerate() {
                let y = ui.px(80.0) + i as i32 * (ui.lh + ui.px(4.0));
                if v.is_empty() {
                    c.text(x + ui.px(14.0), y, ui.fs, k, C_ACCENT, 255);
                } else {
                    c.text(x + ui.px(14.0), y, ui.fs - 1, k, C_AMBER, 255);
                    c.text(x + ui.px(150.0), y, ui.fs - 1, v, C_TEXT, 255);
                }
            }
        }
        c.text_c(cx, c.h as i32 - ui.px(46.0), ui.fs - 1, "Esc or Enter: back", C_DIM, 230);
    }

    fn draw_credits(&mut self, c: &mut Canvas, ui: &Ui) {
        self.dim(c, 200);
        let cx = c.w as i32 / 2;
        let off = (self.credits_y * ui.s) as i32;
        let mut y = c.h as i32 + ui.px(40.0) - off;
        for (i, (a, b)) in story::CREDITS.iter().enumerate() {
            if i == 0 {
                c.text_c(cx, y, ui.px(60.0), a, C_ACCENT, 255);
                y += ui.px(140.0);
            } else if b.is_empty() {
                c.text_c(cx, y + ui.px(60.0), ui.fs + 2, &a.replace("Copyright (c)", "\x7f"), C_TEXT, 255);
                y += ui.px(120.0);
            } else {
                c.text_c(cx, y, ui.fs - 1, a, C_DIM, 255);
                c.text_c(cx, y + ui.lh + 2, ui.fs + 4, b, C_TEXT, 255);
                y += ui.px(90.0);
            }
        }
        c.text_c(cx, c.h as i32 - ui.px(30.0), ui.fs - 2, "Esc: skip", C_DIM, 160);
    }

    fn draw_slots(&mut self, c: &mut Canvas, ui: &Ui, save: bool) {
        self.dim(c, if save { 170 } else { 200 });
        let cx = c.w as i32 / 2;
        let ty = if save { ui.px(70.0) } else { ui.px(40.0) };
        c.text_c(cx, ty, ui.px(26.0), if save { "SAVE COMMANDER" } else { "LOAD COMMANDER" }, C_ACCENT, 255);
        let pw = ui.px(640.0);
        for i in 0..SAVE_SLOTS {
            let y = ty + ui.px(52.0) + i as i32 * ui.px(66.0);
            let sel = i == self.sel;
            panel(c, cx - pw / 2, y, pw, ui.px(58.0), if sel { 230 } else { 160 });
            if sel {
                c.rect(cx - pw / 2, y, 3, ui.px(58.0), C_ACCENT, 255);
            }
            c.text(cx - pw / 2 + ui.px(16.0), y + ui.px(10.0), ui.fs + 2, &format!("Slot {}", i + 1), if sel { C_ACCENT } else { C_TEXT }, 255);
            match &self.slots[i] {
                Some(s) => {
                    let loc = self.gal_name_of(s);
                    c.text(cx - pw / 2 + ui.px(110.0), y + ui.px(10.0), ui.fs, &format!("{}  {}", s.name, s.rank()), C_TEXT, 255);
                    c.text(cx - pw / 2 + ui.px(110.0), y + ui.px(10.0) + ui.lh, ui.fs - 1, &format!("{}  {} cr  {} kills  {}", loc, s.credits, s.kills, fmt_time(s.play_seconds)), C_DIM, 255);
                    if s.story.free_play {
                        c.text_r(cx + pw / 2 - ui.px(14.0), y + ui.px(10.0), ui.fs - 1, "COMPLETED", C_GREEN, 255);
                    } else {
                        c.text_r(cx + pw / 2 - ui.px(14.0), y + ui.px(10.0), ui.fs - 1, &format!("Chapter {}", s.story.chapter.min(6) + 1), C_DIM, 255);
                    }
                }
                None => {
                    c.text(cx - pw / 2 + ui.px(110.0), y + ui.px(20.0), ui.fs, "(empty)", C_DIM, 255);
                }
            }
        }
        c.text_c(cx, ty + ui.px(52.0) + SAVE_SLOTS as i32 * ui.px(66.0) + ui.px(12.0), ui.fs - 1, if save { "Enter: save   Esc: back" } else { "Enter: load   1-5: pick   Esc: back" }, C_DIM, 230);
    }

    fn draw_pause(&mut self, c: &mut Canvas, ui: &Ui) {
        let cx = c.w as i32 / 2;
        let pw = ui.px(380.0);
        panel(c, cx - pw / 2, ui.px(140.0), pw, ui.px(260.0), 215);
        c.text_c(cx, ui.px(160.0), ui.px(22.0), "PAUSED", C_ACCENT, 255);
        self.menu_list(c, ui, &PAUSE_ITEMS, ui.px(214.0), &|_| true);
    }

    fn draw_briefing(&mut self, c: &mut Canvas, ui: &Ui) {
        self.dim(c, 190);
        let cx = c.w as i32 / 2;
        let pw = ui.px(700.0).min(c.w as i32 - 30);
        if let Some(b) = &self.brief {
            let cols = (pw / ui.fs) as usize - 4;
            let mut lines: Vec<String> = Vec::new();
            for p in &b.body {
                lines.extend(wrap(p, cols));
                lines.push(String::new());
            }
            let ph = ui.px(110.0) + lines.len() as i32 * ui.lh;
            let y0 = (c.h as i32 - ph) / 2;
            panel(c, cx - pw / 2, y0, pw, ph, 225);
            c.rect(cx - pw / 2, y0, pw, 3, C_ACCENT, 255);
            c.text(cx - pw / 2 + ui.px(20.0), y0 + ui.px(18.0), ui.fs + 5, &b.title, C_ACCENT, 255);
            for (i, l) in lines.iter().enumerate() {
                let col = if l.starts_with("Reward:") { C_AMBER } else { C_TEXT };
                c.text(cx - pw / 2 + ui.px(20.0), y0 + ui.px(60.0) + i as i32 * ui.lh, ui.fs, l, col, 255);
            }
            c.text_r(cx + pw / 2 - ui.px(16.0), y0 + ph - ui.px(26.0), ui.fs - 1, "Enter: continue", C_DIM, 255);
        }
    }

    fn draw_dead(&mut self, c: &mut Canvas, ui: &Ui) {
        self.dim(c, 215);
        let cx = c.w as i32 / 2;
        c.text_c(cx, ui.px(70.0), ui.px(48.0), "GAME OVER", C_RED, 255);
        if let Some(s) = &self.stats {
            c.text_c(cx, ui.px(130.0), ui.fs + 2, s.why, C_TEXT, 255);
            let pw = ui.px(420.0);
            panel(c, cx - pw / 2, ui.px(170.0), pw, ui.px(150.0), 190);
            let rows = [
                ("Kills", format!("{}  ({})", s.kills, RANKS[rank_of(s.kills)].0)),
                ("Credits", format!("{}", s.credits)),
                ("Jumps", format!("{}", s.jumps)),
                ("Time played", fmt_time(s.seconds)),
            ];
            for (i, (a, b)) in rows.iter().enumerate() {
                let y = ui.px(188.0) + i as i32 * (ui.lh + 6);
                c.text(cx - pw / 2 + ui.px(24.0), y, ui.fs, a, C_DIM, 255);
                c.text_r(cx + pw / 2 - ui.px(24.0), y, ui.fs, b, C_TEXT, 255);
            }
        }
        self.menu_list(c, ui, &["Load last save", "Main menu"], ui.px(350.0), &|_| true);
    }

    fn draw_ending(&mut self, c: &mut Canvas, ui: &Ui) {
        // a letterboxed cinematic over the orbiting camera
        let bar = c.h as i32 / 7;
        c.rect(0, 0, c.w as i32, bar, rgb(0, 0, 0), 255);
        c.rect(0, c.h as i32 - bar, c.w as i32, bar, rgb(0, 0, 0), 255);
        let cx = c.w as i32 / 2;
        let page = self.page.min(story::ENDING.len() - 1);
        let w = ui.px(720.0).min(c.w as i32 - 40);
        let cols = (w / (ui.fs + 1)) as usize - 2;
        let lines = wrap(story::ENDING[page], cols);
        let fade = clamp(self.ending_t * 1.2, 0.0, 1.0);
        let y0 = c.h as i32 - bar - lines.len() as i32 * ui.lh - ui.px(14.0);
        c.rect(0, y0 - ui.px(10.0), c.w as i32, bar + lines.len() as i32 * ui.lh + ui.px(24.0), rgb(0, 0, 0), 110);
        for (i, l) in lines.iter().enumerate() {
            c.text_c(cx, y0 + i as i32 * ui.lh, ui.fs + 1, l, C_TEXT, (fade * 255.0) as u32);
        }
        c.text_c(cx, bar / 2 - ui.fs / 2, ui.fs, "THE LANES ARE OPEN", C_ACCENT, 230);
        c.text_r(c.w as i32 - ui.px(14.0), c.h as i32 - ui.fs - 6, ui.fs - 2, "Enter", C_DIM, 200);
    }

    fn draw_freeplay(&mut self, c: &mut Canvas, ui: &Ui) {
        self.dim(c, 210);
        let cx = c.w as i32 / 2;
        c.text_c(cx, ui.px(90.0), ui.px(32.0), "CAMPAIGN COMPLETE", C_GREEN, 255);
        c.text_c(cx, ui.px(150.0), ui.fs + 2, "Continue in free play? Your commander is saved and marked as completed.", C_TEXT, 255);
        self.menu_list(c, ui, &["Yes, keep flying", "No, return to the main menu"], ui.px(230.0), &|_| true);
    }

    // ------------------------------------------------------------------ station screens

    fn draw_tabs(&self, c: &mut Canvas, ui: &Ui) {
        let h = ui.px(30.0);
        c.rect(0, 0, c.w as i32, h, C_PANEL, 215);
        c.rect(0, h, c.w as i32, 1, C_BORDER, 255);
        let tabs: [(&str, Screen, bool); 9] = [
            (if self.docked { "F1 Launch" } else { "F1 View" }, Screen::Flight, true),
            ("F5 Status", Screen::Status, true),
            ("F6 Galaxy", Screen::GalChart, true),
            ("F7 Local", Screen::LocalChart, true),
            ("F8 System", Screen::SysInfo, true),
            ("F9 Market", Screen::Market, self.docked),
            ("F10 Equip", Screen::Equipment, self.docked),
            ("F11 Contracts", Screen::Contracts, self.docked),
            ("F12 Save", Screen::Save, self.docked),
        ];
        let mut x = ui.px(10.0);
        for (t, s, en) in tabs {
            let w = (t.len() as i32 + 2) * (ui.fs - 2);
            let cur = s == self.screen;
            if cur {
                c.rect(x, 2, w, h - 2, rgb(20, 46, 56), 255);
                c.rect(x, h - 2, w, 2, C_ACCENT, 255);
            }
            c.text(x + (ui.fs - 2), (h - ui.fs + 2) / 2, ui.fs - 2, t, if cur { C_ACCENT } else if en { C_TEXT } else { rgb(70, 82, 104) }, 255);
            x += w + 2;
        }
        if c.w as i32 > ui.px(1500.0) {
            let right = format!("{}  {} cr", self.sys().name, self.cmdr.credits);
            c.text_r(c.w as i32 - ui.px(12.0), (h - ui.fs + 1) / 2, ui.fs - 1, &right, C_DIM, 255);
        }
    }

    fn draw_hints(&self, c: &mut Canvas, ui: &Ui) {
        let t = match self.screen {
            Screen::Market => "Up/Down select   B or Enter buy   S sell   Shift: x10 / sell all   Esc back",
            Screen::Equipment => "Up/Down select   Enter buy   Del remove laser   Esc back",
            Screen::GalChart | Screen::LocalChart => "Arrows move   Enter set destination   Home: your system   Esc back",
            Screen::Contracts => "Up/Down select   Enter accept   Esc back",
            Screen::SysInfo => "Arrows browse systems   Esc back",
            Screen::Status => "F6 chart   F9 market   F10 equipment   F11 contracts   Tab key map",
            _ => "",
        };
        c.text_c(c.w as i32 / 2, c.h as i32 - ui.fs - ui.px(10.0), ui.fs - 1, t, C_DIM, 220);
    }

    fn content_rect(&self, c: &Canvas, ui: &Ui) -> (i32, i32, i32, i32) {
        let m = ui.px(18.0);
        (m, ui.px(30.0) + m, c.w as i32 - 2 * m, c.h as i32 - ui.px(30.0) - 2 * m - ui.px(30.0))
    }

    fn kv(&self, c: &mut Canvas, ui: &Ui, x: i32, y: &mut i32, w: i32, k: &str, v: &str, vc: u32) {
        c.text(x, *y, ui.fs, k, C_DIM, 255);
        c.text_r(x + w, *y, ui.fs, v, vc, 255);
        *y += ui.lh;
    }

    fn draw_status(&mut self, c: &mut Canvas, ui: &Ui) {
        let (x0, y0, w, h) = self.content_rect(c, ui);
        let pw = (w - 2 * ui.px(12.0)) / 3;
        let cm = &self.cmdr;
        // commander
        let px = x0;
        panel(c, px, y0, pw, h, 185);
        let mut y = y0 + ui.px(14.0);
        let ix = px + ui.px(16.0);
        let iw = pw - ui.px(32.0);
        c.text(ix, y, ui.fs + 4, "COMMANDER", C_ACCENT, 255);
        y += ui.lh + ui.px(8.0);
        self.kv(c, ui, ix, &mut y, iw, "Name", &cm.name, C_TEXT);
        let r = rank_of(cm.kills);
        self.kv(c, ui, ix, &mut y, iw, "Rank", RANKS[r].0, C_ACCENT);
        let next = if r + 1 < RANKS.len() { format!("{} ({})", RANKS[r + 1].0, RANKS[r + 1].1 - cm.kills) } else { String::from("top rank") };
        self.kv(c, ui, ix, &mut y, iw, "Next rank", &next, C_DIM);
        self.kv(c, ui, ix, &mut y, iw, "Kills", &format!("{}", cm.kills), C_TEXT);
        let (lt, lc) = match cm.legal() {
            Legal::Clean => ("Clean", C_GREEN),
            Legal::Offender => ("Offender", C_AMBER),
            Legal::Fugitive => ("Fugitive", C_RED),
        };
        self.kv(c, ui, ix, &mut y, iw, "Legal status", lt, lc);
        self.kv(c, ui, ix, &mut y, iw, "Credits", &format!("{}", cm.credits), C_AMBER);
        self.kv(c, ui, ix, &mut y, iw, "Jumps made", &format!("{}", cm.jumps), C_TEXT);
        self.kv(c, ui, ix, &mut y, iw, "Time played", &fmt_time(cm.play_seconds), C_TEXT);
        self.kv(c, ui, ix, &mut y, iw, "Contracts done", &format!("{}", cm.missions_done), C_TEXT);
        y += ui.lh;
        let s = self.sys();
        self.kv(c, ui, ix, &mut y, iw, "Location", &s.name, C_TEXT);
        self.kv(c, ui, ix, &mut y, iw, "Galaxy", &format!("{}", cm.galaxy + 1), C_TEXT);
        // ship
        let px = x0 + pw + ui.px(12.0);
        panel(c, px, y0, pw, h, 185);
        let mut y = y0 + ui.px(14.0);
        let ix = px + ui.px(16.0);
        c.text(ix, y, ui.fs + 4, "TERN \"MOTH LARK\"", C_ACCENT, 255);
        y += ui.lh + ui.px(8.0);
        self.kv(c, ui, ix, &mut y, iw, "Fuel", &format!("{:.1} / {:.1} LY", cm.fuel as f32 / 10.0, MAX_FUEL_TENTHS as f32 / 10.0), C_AMBER);
        self.kv(c, ui, ix, &mut y, iw, "Hold", &format!("{} / {} t", cm.hold_used(), cm.hold_capacity()), C_TEXT);
        self.kv(c, ui, ix, &mut y, iw, "Missiles", &format!("{} / {}", cm.missiles, MISSILE_MAX), C_TEXT);
        for m in 0..4 {
            let broken = cm.damaged & (1 << (12 + m)) != 0;
            self.kv(c, ui, ix, &mut y, iw, &format!("{} laser", MOUNT_NAMES[m]), &format!("{}{}", LASER_NAMES[cm.lasers[m] as usize], if broken { " (damaged)" } else { "" }), if broken { C_RED } else { C_TEXT });
        }
        y += ui.lh / 2;
        let mut any = false;
        for e in EQUIPMENT.iter() {
            if cm.equip & e.flag != 0 {
                let broken = cm.damaged & e.flag != 0;
                c.text(ix, y, ui.fs - 1, &format!("{}{}", e.name, if broken { " (damaged)" } else { "" }), if broken { C_RED } else { C_GREEN }, 255);
                y += ui.lh - 2;
                any = true;
            }
        }
        if !any {
            c.text(ix, y, ui.fs - 1, "No extra equipment fitted", C_DIM, 255);
        }
        // cargo and mission
        let px = x0 + 2 * (pw + ui.px(12.0));
        panel(c, px, y0, pw, h, 185);
        let mut y = y0 + ui.px(14.0);
        let ix = px + ui.px(16.0);
        c.text(ix, y, ui.fs + 4, "CARGO", C_ACCENT, 255);
        y += ui.lh + ui.px(8.0);
        let mut n = 0;
        for (i, k) in COMMODITIES.iter().enumerate() {
            if cm.cargo[i] > 0 {
                self.kv(c, ui, ix, &mut y, iw, k.name, &format!("{} {}", cm.cargo[i], k.unit), if k.illegal { C_RED } else { C_TEXT });
                n += 1;
            }
        }
        if cm.sealed > 0 {
            self.kv(c, ui, ix, &mut y, iw, "Sealed packages", &format!("{}", cm.sealed), C_AMBER);
            n += 1;
        }
        if n == 0 {
            c.text(ix, y, ui.fs - 1, "The hold is empty", C_DIM, 255);
            y += ui.lh;
        }
        y += ui.lh / 2;
        c.text(ix, y, ui.fs + 2, "OBJECTIVE", C_ACCENT, 255);
        y += ui.lh + 4;
        match self.objective_text() {
            Some(o) => {
                for l in wrap(&o, (iw / (ui.fs - 1)) as usize) {
                    c.text(ix, y, ui.fs - 1, &l, C_TEXT, 255);
                    y += ui.lh - 2;
                }
            }
            None => {
                let t = if cm.story.free_play { "Free play. The campaign is complete." } else if self.story_offer_available() { "A new contract is waiting on the contracts board (F11)." } else { "No active objective." };
                for l in wrap(t, (iw / (ui.fs - 1)) as usize) {
                    c.text(ix, y, ui.fs - 1, &l, C_DIM, 255);
                    y += ui.lh - 2;
                }
            }
        }
        for m in cm.missions.iter() {
            y += 4;
            let t = self.side_text(m);
            for l in wrap(&t, (iw / (ui.fs - 1)) as usize) {
                c.text(ix, y, ui.fs - 1, &l, C_AMBER, 255);
                y += ui.lh - 2;
            }
        }
    }

    fn side_text(&self, m: &Mission) -> String {
        let nm = |i: u8| self.gal.sys[i as usize].name.clone();
        match m.kind {
            MISSION_LEDGER => format!("Parcel: deliver to {} ({} cr)", nm(m.a), m.reward),
            _ => {
                if m.stage == 0 {
                    format!("Bounty: destroy the wanted pirate at {} ({} cr)", nm(m.a), m.reward)
                } else {
                    format!("Bounty: report back to {} ({} cr)", nm(m.origin), m.reward)
                }
            }
        }
    }

    fn sys_line(&self, c: &mut Canvas, ui: &Ui, x: i32, y: &mut i32, w: i32, s: &SystemInfo) {
        self.kv(c, ui, x, y, w, "Government", s.govt_name(), C_TEXT);
        self.kv(c, ui, x, y, w, "Economy", s.economy_name(), ECO_COL[s.economy as usize]);
        self.kv(c, ui, x, y, w, "Tech level", &format!("{}", s.tech), C_TEXT);
        self.kv(c, ui, x, y, w, "Law level", &format!("{} / 7", s.law()), if s.law() >= 5 { C_AMBER } else { C_TEXT });
        self.kv(c, ui, x, y, w, "Population", &format!("{:.1} billion", s.pop as f32 / 10.0), C_TEXT);
        self.kv(c, ui, x, y, w, "Gross product", &format!("{} M cr", s.gdp), C_TEXT);
        self.kv(c, ui, x, y, w, "Planet radius", &format!("{} km", s.radius_km), C_TEXT);
    }

    fn draw_sysinfo(&mut self, c: &mut Canvas, ui: &Ui) {
        let (x0, y0, w, h) = self.content_rect(c, ui);
        panel(c, x0, y0, w, h, 185);
        let s = self.gal.sys[self.chart_sel].clone();
        let ix = x0 + ui.px(24.0);
        let mut y = y0 + ui.px(20.0);
        c.text(ix, y, ui.fs * 2, &s.name, C_ACCENT, 255);
        let dist = self.gal.dist_ly(self.cmdr.system as usize, self.chart_sel);
        let here = self.chart_sel == self.cmdr.system as usize;
        let sub = if here { String::from("Your current system") } else { format!("{:.1} LY away, jump cost {:.1} fuel", dist, self.jump_cost(self.chart_sel) as f32 / 10.0) };
        c.text(ix, y + ui.fs * 2 + 6, ui.fs, &sub, C_DIM, 255);
        y += ui.fs * 2 + ui.lh * 2 + 10;
        let iw = (w - ui.px(48.0)).min(ui.px(520.0));
        self.sys_line(c, ui, ix, &mut y, iw, &s);
        y += ui.lh;
        for l in wrap(&s.description(), 60) {
            c.text(ix, y, ui.fs, &l, C_TEXT, 255);
            y += ui.lh;
        }
        // star swatch and planet preview disc
        let cx = x0 + w - ui.px(180.0);
        let cy = y0 + ui.px(150.0);
        let sc = scale_col(rgb((s.star[0] * 255.0) as u8, (s.star[1] * 255.0) as u8, (s.star[2] * 255.0) as u8), 1.0);
        c.disc(cx as f32, cy as f32, ui.px(26.0) as f32, sc, 255);
        c.ring(cx as f32, cy as f32, ui.px(36.0) as f32, 1.0, sc, 120);
        c.text_c(cx, cy + ui.px(48.0), ui.fs - 1, "star", C_DIM, 255);
        let pc = ECO_COL[s.economy as usize];
        c.disc(cx as f32, (cy + ui.px(130.0)) as f32, ui.px(40.0) as f32, scale_col(pc, 0.7), 255);
        c.disc((cx + ui.px(14.0)) as f32, (cy + ui.px(118.0)) as f32, ui.px(26.0) as f32, scale_col(pc, 1.0), 120);
        c.text_c(cx, cy + ui.px(186.0), ui.fs - 1, "world", C_DIM, 255);
    }

    fn draw_chart(&mut self, c: &mut Canvas, ui: &Ui, local: bool) {
        let (x0, y0, w, h) = self.content_rect(c, ui);
        let side = h.min(w * 6 / 10);
        panel(c, x0, y0, side, side, 185);
        let cur = self.cmdr.system as usize;
        let range_ly = (self.cmdr.fuel as f32 / 10.0).min(MAX_JUMP_LY);
        let (cxu, cyu, span) = if local {
            (self.gal.sys[cur].x as f32, self.gal.sys[cur].y as f32, 96.0)
        } else {
            (128.0, 128.0, 256.0)
        };
        let k = side as f32 / span;
        let to = |s: &SystemInfo| -> (f32, f32) { (x0 as f32 + side as f32 * 0.5 + (s.x as f32 - cxu) * k, y0 as f32 + side as f32 * 0.5 + (s.y as f32 - cyu) * k) };
        let inside = |p: (f32, f32)| p.0 > x0 as f32 + 3.0 && p.0 < (x0 + side) as f32 - 3.0 && p.1 > y0 as f32 + 3.0 && p.1 < (y0 + side) as f32 - 3.0;
        // jump range circle around the current system
        let (px, py) = to(&self.gal.sys[cur]);
        let rr = range_ly * 6.0 * k;
        if local {
            c.ring(px, py, rr, 1.0, rgb(60, 130, 140), 150);
        } else {
            c.ring(px, py, rr, 1.0, rgb(60, 130, 140), 150);
        }
        for (i, s) in self.gal.sys.iter().enumerate() {
            let p = to(s);
            if !inside(p) {
                continue;
            }
            let d = self.gal.dist_ly(cur, i);
            let col = ECO_COL[s.economy as usize];
            let in_range = d <= range_ly + 0.01;
            let a = if in_range { 255 } else { 150 };
            c.disc(p.0, p.1, if local { ui.px(3.2) as f32 } else { 1.6 * ui.s }, col, a);
            if local && in_range && i != cur {
                c.line(px, py, p.0, p.1, rgb(40, 70, 82), 90);
            }
            if local && i != cur {
                c.text(p.0 as i32 + ui.px(6.0), p.1 as i32 - ui.fs / 2, ui.fs - 3, &s.name, if in_range { C_TEXT } else { C_DIM }, 200);
            }
        }
        // markers
        c.ring(px, py, ui.px(7.0) as f32, 1.5, C_ACCENT, 255);
        let hub = if self.cmdr.story.active && self.cmdr.galaxy == 0 { Some(self.cmdr.story.hub as usize) } else { None };
        if let Some(h) = hub {
            let p = to(&self.gal.sys[h]);
            if inside(p) {
                c.ring(p.0, p.1, ui.px(5.0) as f32, 1.0, C_GREEN, 200);
            }
        }
        if let Some(d) = self.dest {
            let p = to(&self.gal.sys[d]);
            if inside(p) {
                c.ring(p.0, p.1, ui.px(9.0) as f32, 1.5, C_AMBER, 255);
            }
        }
        let sp = to(&self.gal.sys[self.chart_sel]);
        let q = ui.px(10.0) as f32;
        c.line(sp.0 - q, sp.1, sp.0 - q / 2.0, sp.1, C_TEXT, 255);
        c.line(sp.0 + q / 2.0, sp.1, sp.0 + q, sp.1, C_TEXT, 255);
        c.line(sp.0, sp.1 - q, sp.0, sp.1 - q / 2.0, C_TEXT, 255);
        c.line(sp.0, sp.1 + q / 2.0, sp.0, sp.1 + q, C_TEXT, 255);
        c.text(x0 + 8, y0 + 6, ui.fs - 1, if local { "LOCAL CHART" } else { "GALACTIC CHART" }, C_DIM, 255);
        // info panel
        let ix0 = x0 + side + ui.px(12.0);
        let iw = w - side - ui.px(12.0);
        panel(c, ix0, y0, iw, side, 185);
        let s = self.gal.sys[self.chart_sel].clone();
        let ix = ix0 + ui.px(16.0);
        let mut y = y0 + ui.px(14.0);
        c.text(ix, y, ui.fs + 5, &s.name, C_ACCENT, 255);
        y += ui.lh + ui.px(10.0);
        let d = self.gal.dist_ly(cur, self.chart_sel);
        let cost = self.jump_cost(self.chart_sel);
        let in_range = d <= MAX_JUMP_LY + 0.01 && cost <= self.cmdr.fuel;
        self.kv(c, ui, ix, &mut y, iw - ui.px(32.0), "Distance", &format!("{:.1} LY", d), C_TEXT);
        self.kv(c, ui, ix, &mut y, iw - ui.px(32.0), "Fuel needed", &format!("{:.1}", cost as f32 / 10.0), if cost <= self.cmdr.fuel { C_TEXT } else { C_RED });
        let st = if self.chart_sel == cur { "here" } else if in_range { "in range" } else if d > MAX_JUMP_LY { "out of range" } else { "not enough fuel" };
        self.kv(c, ui, ix, &mut y, iw - ui.px(32.0), "Jump", st, if in_range { C_GREEN } else { C_AMBER });
        y += ui.lh / 2;
        self.sys_line(c, ui, ix, &mut y, iw - ui.px(32.0), &s);
        y += ui.lh / 2;
        if let Some(d) = self.dest {
            c.text(ix, y, ui.fs, &format!("Destination: {}", self.gal.sys[d].name), C_AMBER, 255);
            y += ui.lh;
        }
        c.text(ix, y, ui.fs - 1, "Press H in flight to jump.", C_DIM, 255);
        y += ui.lh;
        // legend
        y += ui.lh / 2;
        for (i, name) in ECONOMIES.iter().enumerate() {
            let lx = ix + (i as i32 % 2) * (iw / 2 - ui.px(8.0));
            let ly = y + (i as i32 / 2) * (ui.lh - 2);
            c.disc((lx + 4) as f32, (ly + ui.fs / 2) as f32, 3.0, ECO_COL[i], 255);
            c.text(lx + 14, ly, ui.fs - 3, name, C_DIM, 255);
        }
    }

    fn draw_market(&mut self, c: &mut Canvas, ui: &Ui) {
        let (x0, y0, w, h) = self.content_rect(c, ui);
        panel(c, x0, y0, w, h, 190);
        let s = self.sys().clone();
        let ix = x0 + ui.px(18.0);
        c.text(ix, y0 + ui.px(12.0), ui.fs + 4, &format!("{} market", s.name), C_ACCENT, 255);
        c.text_r(x0 + w - ui.px(18.0), y0 + ui.px(12.0), ui.fs, &format!("{} cr    hold {}/{}", self.cmdr.credits, self.cmdr.hold_used(), self.cmdr.hold_capacity()), C_AMBER, 255);
        let cols = [0, 270, 340, 430, 520, 600];
        let hy = y0 + ui.px(12.0) + ui.lh + ui.px(8.0);
        for (i, t) in ["Commodity", "Unit", "Price", "vs base", "Stock", "In hold"].iter().enumerate() {
            c.text(ix + ui.px(cols[i] as f32), hy, ui.fs - 1, t, C_DIM, 255);
        }
        c.rect(ix, hy + ui.fs + 2, w - ui.px(36.0), 1, C_BORDER, 255);
        for (i, k) in COMMODITIES.iter().enumerate() {
            let y = hy + ui.lh + 4 + i as i32 * (ui.lh + 2);
            let sel = i == self.sel;
            if sel {
                c.rect(ix - 6, y - 3, w - ui.px(24.0), ui.lh, rgb(20, 46, 56), 230);
                c.rect(ix - 6, y - 3, 3, ui.lh, C_ACCENT, 255);
            }
            let stock = self.market.stock[i];
            let col = if k.illegal { C_RED } else if stock == 0 { C_DIM } else { C_TEXT };
            let name = if k.illegal { format!("{} *", k.name) } else { String::from(k.name) };
            c.text(ix + ui.px(cols[0] as f32), y, ui.fs, &name, col, 255);
            c.text(ix + ui.px(cols[1] as f32), y, ui.fs, k.unit, C_DIM, 255);
            c.text(ix + ui.px(cols[2] as f32), y, ui.fs, &format!("{}", self.market.price[i]), C_TEXT, 255);
            let pct = self.market.price[i] * 100 / k.base - 100;
            c.text(ix + ui.px(cols[3] as f32), y, ui.fs, &format!("{:+}%", pct), if pct <= -10 { C_GREEN } else if pct >= 10 { C_AMBER } else { C_DIM }, 255);
            c.text(ix + ui.px(cols[4] as f32), y, ui.fs, &format!("{}", stock), if stock == 0 { C_DIM } else { C_TEXT }, 255);
            c.text(ix + ui.px(cols[5] as f32), y, ui.fs, &format!("{}", self.cmdr.cargo[i]), if self.cmdr.cargo[i] > 0 { C_GREEN } else { C_DIM }, 255);
        }
        let y = hy + ui.lh + 4 + NCOM as i32 * (ui.lh + 2) + 6;
        let k = &COMMODITIES[self.sel];
        c.text(ix, y, ui.fs - 1, &format!("Sell price {} cr. * marks illegal goods: customs here are level {} of 7.", self.market.sell_price(self.sel), s.law()), C_DIM, 255);
        let _ = k;
    }

    fn draw_equipment(&mut self, c: &mut Canvas, ui: &Ui) {
        let (x0, y0, w, h) = self.content_rect(c, ui);
        panel(c, x0, y0, w, h, 190);
        let ix = x0 + ui.px(18.0);
        c.text(ix, y0 + ui.px(12.0), ui.fs + 4, &format!("Equipment - tech level {}", self.sys().tech), C_ACCENT, 255);
        c.text_r(x0 + w - ui.px(18.0), y0 + ui.px(12.0), ui.fs, &format!("{} cr", self.cmdr.credits), C_AMBER, 255);
        let rows = self.equipment_rows();
        let mut y = y0 + ui.px(12.0) + ui.lh + ui.px(12.0);
        for (i, r) in rows.iter().enumerate() {
            let sel = i == self.sel;
            if sel {
                c.rect(ix - 6, y - 3, w - ui.px(24.0), ui.lh, rgb(20, 46, 56), 230);
                c.rect(ix - 6, y - 3, 3, ui.lh, C_ACCENT, 255);
            }
            let (st, col) = match r.status {
                EqState::Ok => (format!("{} cr", r.price), C_TEXT),
                EqState::Poor => (format!("{} cr", r.price), C_RED),
                EqState::Locked(t) => (format!("needs TL {}", t), rgb(80, 92, 114)),
                EqState::Done(t) => (String::from(t), C_GREEN),
            };
            let tc = if matches!(r.status, EqState::Locked(_)) { rgb(80, 92, 114) } else { C_TEXT };
            c.text(ix, y, ui.fs, &r.text, tc, 255);
            c.text_r(x0 + w - ui.px(24.0), y, ui.fs, &st, col, 255);
            y += ui.lh + 1;
        }
        // description of the selected equipment
        if let Some(r) = rows.get(self.sel) {
            if let EqAct::Equip(f) = r.act {
                if let Some(e) = EQUIPMENT.iter().find(|e| e.flag == f) {
                    c.text(ix, y + 6, ui.fs - 1, e.desc, C_DIM, 255);
                }
            }
        }
    }

    fn draw_contracts(&mut self, c: &mut Canvas, ui: &Ui) {
        let (x0, y0, w, h) = self.content_rect(c, ui);
        panel(c, x0, y0, w, h, 190);
        let ix = x0 + ui.px(18.0);
        let iw = w - ui.px(36.0);
        c.text(ix, y0 + ui.px(12.0), ui.fs + 4, &format!("Contracts - {}", self.sys().name), C_ACCENT, 255);
        let mut y = y0 + ui.px(12.0) + ui.lh + ui.px(14.0);
        // story slot
        let rowh = ui.lh * 4 + ui.px(8.0);
        let st = self.cmdr.story.clone();
        for i in 0..3usize {
            let sel = i == self.sel;
            c.rect(ix - 8, y - 4, iw + 16, rowh, if sel { rgb(20, 46, 56) } else { rgb(14, 20, 30) }, 230);
            if sel {
                c.rect(ix - 8, y - 4, 3, rowh, C_ACCENT, 255);
            }
            if i == 0 {
                c.text(ix, y, ui.fs - 1, "MAIN STORY", C_AMBER, 255);
                if st.chapter >= CHAPTERS {
                    c.text(ix, y + ui.lh, ui.fs + 1, "Campaign complete", C_GREEN, 255);
                } else if st.active {
                    let d = story::chapter(st.chapter);
                    c.text(ix, y + ui.lh, ui.fs + 1, &format!("Chapter {}: {} (active)", st.chapter + 1, d.title), C_TEXT, 255);
                    if let Some(o) = self.objective_text() {
                        c.text(ix, y + ui.lh * 2, ui.fs - 1, &o, C_ACCENT, 255);
                    }
                } else if st.chapter >= 1 && self.cmdr.galaxy == 0 {
                    let d = story::chapter(st.chapter);
                    c.text(ix, y + ui.lh, ui.fs + 1, &format!("Chapter {}: {}", st.chapter + 1, d.title), C_TEXT, 255);
                    let ok = story::gate_ok(&d.gate, &self.cmdr);
                    let line = if ok { format!("Reward {} cr. Press Enter to accept.", d.reward) } else { story::gate_text(&d.gate) };
                    c.text(ix, y + ui.lh * 2, ui.fs - 1, &line, if ok { C_GREEN } else { C_AMBER }, 255);
                } else {
                    c.text(ix, y + ui.lh, ui.fs, "No story contract available here", C_DIM, 255);
                }
            } else {
                let offers = self.side_offers();
                match offers.get(i - 1) {
                    Some(m) => {
                        let taken = self.cmdr.missions.iter().any(|x| x.kind == m.kind && x.seed == m.seed && x.origin == m.origin);
                        c.text(ix, y, ui.fs - 1, if m.kind == MISSION_LEDGER { "PARCEL RUN" } else { "WANTED" }, C_AMBER, 255);
                        let line = self.side_text(m);
                        c.text(ix, y + ui.lh, ui.fs, &line, if taken { C_DIM } else { C_TEXT }, 255);
                        let hint = if taken { "Accepted" } else if m.kind == MISSION_LEDGER { "Needs one free hold slot. Raiders may track the parcel." } else { "A pirate captain is hiding in that system." };
                        c.text(ix, y + ui.lh * 2, ui.fs - 1, hint, if taken { C_GREEN } else { C_DIM }, 255);
                    }
                    None => {
                        c.text(ix, y + ui.lh, ui.fs, "No contract offered", C_DIM, 255);
                    }
                }
            }
            y += rowh + ui.px(8.0);
        }
        // active list
        c.text(ix, y, ui.fs, "Active contracts", C_ACCENT, 255);
        y += ui.lh;
        if self.cmdr.missions.is_empty() {
            c.text(ix, y, ui.fs - 1, "None. You can carry two at a time.", C_DIM, 255);
        }
        for m in self.cmdr.missions.iter() {
            let t = self.side_text(m);
            c.text(ix, y, ui.fs - 1, &t, C_TEXT, 255);
            y += ui.lh;
        }
    }
}

pub fn fmt_time(s: u32) -> String {
    format!("{}h {:02}m", s / 3600, (s / 60) % 60)
}
