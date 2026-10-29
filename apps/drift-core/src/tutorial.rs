// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! The interactive tutorial: each step waits for the player to do what it asks.
use crate::commander::*;
use crate::econ::*;
use crate::game::*;
use crate::gfx::*;
use crate::math::*;
use crate::menus::*;
use crate::models::*;
use crate::sim::*;
use crate::view::*;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// (short name, title, prompt). `[Key]` in a prompt is drawn as a key cap.
pub const STEP_DASHBOARD: usize = 4;

pub const STEPS: [(&str, &str, &str); 13] = [
    ("Launch", "Launch", "You are docked. Press [F1] to launch from the station."),
    ("Steer", "Steer", "Roll with [Left] and [Right], pitch with [Up] and [Down]. Hold each for a moment."),
    ("Throttle", "Throttle", "Press [A] to speed up and [Z] to slow down. Raise the throttle above 60 percent."),
    ("Views", "Look around", "Press [F2] for the rear view, then [F1] to look forward again. [F3] and [F4] show the sides."),
    ("Dashboard", "Dashboard", "The panel at the bottom is your dashboard. Left: Shield fwd and aft, Energy, Fuel, Cabin temp, Laser temp, Altitude. Right: Speed, Throttle, Roll, Pitch, Missiles. Bars turn amber, then red, when low or hot. Press [Enter] to go on."),
    ("Compass", "Compass", "The compass above the scanner points to the station (green dot). Turn until the dot is in the middle of the circle."),
    ("Target", "Target", "A training drone appeared ahead. The scanner shows contacts as dots with height sticks. Face the drone and press [T] to lock it."),
    ("Fire", "Fire", "Press [Space] to fire the front laser and destroy the drone. [M] fires a missile at a locked target."),
    ("Beacon", "Beacon", "Fly to the cyan beacon. When it is off screen, its marker shows the direction."),
    ("Jump", "In-system jump", "You were moved into open space. Hold [J] to jump towards the station. The jump stops by itself near the station (mass lock)."),
    ("Dock", "Dock", "Fly nose first through the slot. Follow the guide: centre the cross, match the slot roll, stay under 150 m/s. Press [D] and the docking computer flies for you."),
    ("Trade", "Trade", "Press [F9] for the market and buy one unit of any cargo with [B]."),
    ("Refuel", "Refuel", "Press [F10] for equipment, select Refuel and press [Enter]."),
];

impl Game {
    pub fn start_tutorial(&mut self, practice: bool) {
        if practice {
            self.cmdr = Commander::new("Rook");
            let sys = start_system(&self.gal) as u8;
            self.cmdr.system = sys;
            self.cmdr.story.sys = [sys; 3];
            self.cmdr.story.hub = sys;
        }
        self.cmdr.fuel = 40;
        self.cmdr.equip |= EQ_DOCKCOMP;
        self.enter_station(Arrival::Hyper);
        self.started = true;
        self.log.clear();
        self.tut = Some(Tut { step: 0, practice, roll_t: 0.0, pitch_t: 0.0, saw_rear: false, drone: 0, drone_dead: false, jumped: false, flash: 0.0 });
        self.screen = Screen::Status;
        self.sel = 0;
        self.say("Flight school started. Press X to skip it at any time.");
    }

    pub fn skip_tutorial_choice(&mut self) {
        self.cmdr.story.chapter = 1;
        self.cmdr.story.active = false;
        self.tut = None;
        self.screen = Screen::Status;
        self.sel = 0;
        self.started = true;
        self.say("Tutorial skipped. New contracts are on the board (F11).");
    }

    pub fn tut_finish(&mut self, skipped: bool) {
        let practice = self.tut.as_ref().map_or(false, |t| t.practice);
        self.tut = None;
        self.cmdr.equip &= !EQ_DOCKCOMP;
        self.world.beacon = None;
        for s in self.world.ships.iter_mut() {
            if s.tag == 30 {
                s.dead = true;
            }
        }
        if practice {
            self.started = false;
            self.docked = true;
            self.goto(Screen::MainMenu);
            return;
        }
        if skipped {
            self.cmdr.story.chapter = 1;
            self.cmdr.story.active = false;
            self.say("Tutorial skipped. New contracts are on the board (F11).");
        } else {
            self.complete_chapter();
        }
    }

    fn tut_advance(&mut self) {
        let done = {
            let t = self.tut.as_mut().unwrap();
            t.step += 1;
            t.flash = 1.0;
            t.step >= STEPS.len()
        };
        if done {
            self.tut_finish(false);
        } else {
            self.tut_enter();
        }
    }

    /// Set the scene for the current step (also after a relaunch).
    pub fn tut_enter(&mut self) {
        let step = match &self.tut {
            Some(t) => t.step,
            None => return,
        };
        if self.docked {
            return;
        }
        let p = self.world.p.pos;
        let o = self.world.p.o;
        match step {
            6 | 7 => {
                if self.tut.as_ref().map_or(false, |t| t.drone != 0 && self.world.find(t.drone).is_some()) {
                    return;
                }
                if self.tut.as_ref().map_or(false, |t| t.drone_dead) {
                    return;
                }
                // keep the drone well clear of the station so no shot can hit it
                let mut pos = p + o.f * 1000.0 + o.r * 900.0;
                if let Some((sp, _)) = self.world.station_frame() {
                    for cand in [o.r * 900.0, -o.r * 900.0, o.u * 900.0, -o.u * 900.0] {
                        let c = p + o.f * 1000.0 + cand;
                        if (c - sp).len() > 3500.0 && (p - sp).len() > 0.0 {
                            pos = c;
                            break;
                        }
                    }
                }
                let i = self.world.add_ship(Kind::Jackal, pos, Orient::look(-o.f, o.u), Faction::Neutral);
                let s = &mut self.world.ships[i];
                s.ai = Ai::Drift;
                s.want = 0.0;
                s.speed = 0.0;
                s.energy = 40.0;
                s.shield_f = 0.0;
                s.shield_a = 0.0;
                s.tag = 30;
                let id = s.id;
                self.tut.as_mut().unwrap().drone = id;
            }
            8 => {
                self.world.beacon = Some(p + o.f * 3500.0 + o.r * 1200.0 + o.u * 300.0);
            }
            9 => {
                if let Some((sp, fr)) = self.world.station_frame() {
                    let pos = sp + fr.f * 30000.0 + fr.r * 5000.0;
                    self.world.p.pos = pos;
                    self.world.p.prev_pos = pos;
                    self.world.p.o = Orient::look(sp - pos, v3(0.0, 1.0, 0.0));
                    self.world.p.speed = 0.0;
                    self.world.p.throttle = 0.0;
                    self.world.ships.retain(|s| s.tag == 30 || !matches!(s.fac, Faction::Civil | Faction::Police));
                }
            }
            _ => {}
        }
    }

    pub(crate) fn tut_update(&mut self) {
        let step = match self.tut.as_mut() {
            Some(t) => {
                t.flash = max(0.0, t.flash - DT);
                t.step
            }
            None => return,
        };
        if !self.started || matches!(self.screen, Screen::Pause) {
            return;
        }
        self.world.spawn_timer = 99.0;
        let flying_screen = self.screen == Screen::Flight && !self.docked;
        let hl = self.input.h(Act::Left) || self.input.h(Act::Right);
        let hp = self.input.h(Act::Up) || self.input.h(Act::Down);
        let view = self.view;
        let t = self.tut.as_mut().unwrap();
        if flying_screen && step == 1 {
            if hl {
                t.roll_t += DT;
            }
            if hp {
                t.pitch_t += DT;
            }
        }
        if flying_screen && step == 3 && view == 1 {
            t.saw_rear = true;
        }
        let saw_rear = t.saw_rear;
        let (roll_t, pitch_t) = (t.roll_t, t.pitch_t);
        let drone = t.drone;
        let drone_dead = t.drone_dead;
        let jumped = t.jumped;
        let p = &self.world.p;
        let enter = self.input.p(Act::Enter);
        let ok = match step {
            0 => !self.docked,
            1 => roll_t >= 0.8 && pitch_t >= 0.8,
            2 => !self.docked && p.throttle > 0.6,
            3 => flying_screen && saw_rear && view == 0,
            4 => enter && flying_screen,
            5 => match self.world.station_frame() {
                Some((sp, _)) => !self.docked && p.o.f.dot((sp - p.pos).norm()) > 0.96,
                None => true,
            },
            6 => drone != 0 && p.lock == drone,
            7 => drone_dead || (drone != 0 && self.world.find(drone).is_none()),
            8 => match self.world.beacon {
                Some(b) => (b - p.pos).len() < 500.0,
                None => true,
            },
            9 => {
                if p.jump_speed > 1500.0 {
                    self.tut.as_mut().unwrap().jumped = true;
                }
                match self.world.station_frame() {
                    Some((sp, _)) => jumped && (sp - p.pos).len() < 9500.0,
                    None => true,
                }
            }
            10 => self.docked,
            11 => self.cmdr.cargo.iter().any(|&c| c > 0),
            _ => self.cmdr.fuel >= MAX_FUEL_TENTHS,
        };
        if ok {
            if step == 8 {
                self.world.beacon = None;
            }
            self.tut_advance();
        }
    }

    // ------------------------------------------------------------------ drawing

    fn tut_prompt(&self, step: usize) -> String {
        let docked_early = self.docked && step >= 1 && step <= 9;
        if docked_early {
            return String::from(self.t("You are docked. Press [F1] to launch and carry on."));
        }
        String::from(self.step_text(step).2)
    }

    /// Height of the docked tutorial strip.
    pub fn tut_strip_height(&self, c: &Canvas, ui: &Ui) -> i32 {
        if self.tut.is_none() || self.screen == Screen::Flight || self.screen == Screen::Pause || !matches!(self.screen, Screen::Status | Screen::GalChart | Screen::LocalChart | Screen::SysInfo | Screen::Market | Screen::Equipment | Screen::Contracts | Screen::Save) {
            return 0;
        }
        let w = c.w as i32 - ui.px(36.0);
        let cols = (w / ui.fs.max(1)).max(20) as usize;
        let step = self.tut.as_ref().unwrap().step;
        let lines = wrap_rich(&self.tut_prompt(step), cols).len() as i32;
        ui.px(14.0) + (ui.fs + 5) * (1 + lines)
    }

    pub(crate) fn draw_tutorial(&self, c: &mut Canvas, ui: &Ui) {
        let t = match &self.tut {
            Some(t) => t,
            None => return,
        };
        if !matches!(self.screen, Screen::Flight | Screen::Status | Screen::GalChart | Screen::LocalChart | Screen::SysInfo | Screen::Market | Screen::Equipment | Screen::Contracts | Screen::Save) {
            return;
        }
        let fs = ui.fs;
        let step = t.step.min(STEPS.len() - 1);
        let title = format!("{} {}/{}  {}", self.t("TUTORIAL"), step + 1, STEPS.len(), self.step_text(step).1);
        let flash = (t.flash * 160.0) as u32;
        let prompt = self.tut_prompt(step);
        if self.screen == Screen::Flight {
            let pw = ui.px(300.0).max(fs * 24).min(c.w as i32 * 2 / 5);
            let px = c.w as i32 - pw - ui.px(12.0);
            let top = ui.px(12.0) + (fs + 4) * 3 + 6 + fs * 6 + ui.px(14.0);
            let cols = ((pw - 16) / (fs - 1)).max(8) as usize;
            let lines = wrap_rich(&prompt, cols);
            let ncol_rows = (STEPS.len() as i32 + 1) / 2;
            let ph = 8 + fs + 6 + lines.len() as i32 * (fs + 3) + 8 + ncol_rows * (fs + 2) + fs + 10;
            let py = top;
            panel(c, px, py, pw, ph, 215);
            c.rect(px, py, pw, 3, C_ACCENT, 255);
            if flash > 0 {
                c.rect(px, py, pw, ph, C_GREEN, flash / 4);
            }
            let tsz = (fs - 1).min((pw - 16) / (title.chars().count() as i32).max(1)).max(6);
            c.text(px + 8, py + 8, tsz, &title, C_ACCENT, 255);
            let mut y = py + 8 + fs + 6;
            for l in &lines {
                self.rich(c, px + 8, y, fs - 1, l, C_TEXT);
                y += fs + 3;
            }
            y += 8;
            self.checklist(c, ui, px + 8, y, pw - 16, step, 2);
            c.text(px + 8, py + ph - fs - 6, fs - 3, &format!("[X] {}", self.t("skip tutorial")), C_DIM, 255);
        } else {
            let sh = self.tut_strip_height(c, ui);
            if sh == 0 {
                return;
            }
            let m = ui.px(18.0);
            let y0 = c.h as i32 - ui.fs - ui.px(10.0) - 4 - sh;
            panel(c, m, y0, c.w as i32 - 2 * m, sh, 225);
            c.rect(m, y0, c.w as i32 - 2 * m, 3, C_ACCENT, 255);
            if flash > 0 {
                c.rect(m, y0, c.w as i32 - 2 * m, sh, C_GREEN, flash / 4);
            }
            let tsz = fs.min((c.w as i32 / 2) / (title.chars().count() as i32).max(1)).max(6);
            c.text(m + 10, y0 + 8, tsz, &title, C_ACCENT, 255);
            c.text_r(c.w as i32 - m - 10, y0 + 8, fs - 2, &format!("[X] {}", self.t("skip tutorial")), C_DIM, 255);
            let cols = ((c.w as i32 - 2 * m - 20) / fs).max(20) as usize;
            let mut y = y0 + 8 + fs + 5;
            for l in wrap_rich(&prompt, cols) {
                self.rich(c, m + 10, y, fs, &l, C_TEXT);
                y += fs + 5;
            }
        }
    }

    fn checklist(&self, c: &mut Canvas, ui: &Ui, x: i32, y: i32, w: i32, step: usize, cols: i32) {
        let fs = ui.fs;
        let rows = (STEPS.len() as i32 + cols - 1) / cols;
        for i in 0..STEPS.len() {
            let (col, row) = (i as i32 / rows, i as i32 % rows);
            let cx = x + col * (w / cols);
            let cy = y + row * (fs + 2);
            let r = (fs / 3).max(3) as f32;
            let (mx, my) = (cx as f32 + r, cy as f32 + (fs - 2) as f32 / 2.0);
            if i < step {
                c.ring(mx, my, r, 1.0, C_GREEN, 255);
                c.line(mx - r * 0.5, my, mx - r * 0.1, my + r * 0.45, C_GREEN, 255);
                c.line(mx - r * 0.1, my + r * 0.45, mx + r * 0.55, my - r * 0.5, C_GREEN, 255);
            } else if i == step {
                c.disc(mx, my, r * 0.8, C_ACCENT, 255);
            } else {
                c.ring(mx, my, r, 1.0, C_DIM, 160);
            }
            let col_t = if i < step { C_GREEN } else if i == step { C_TEXT } else { C_DIM };
            c.text(cx + (r as i32) * 2 + 5, cy, fs - 3, self.step_text(i).0, col_t, 255);
        }
    }

    /// One wrapped line of tutorial text; `[Key]` tokens become key caps.
    fn rich(&self, c: &mut Canvas, x: i32, y: i32, size: i32, line: &str, col: u32) {
        let mut cx = x;
        for tok in line.split(' ') {
            if tok.starts_with('[') {
                if let Some(e) = tok.find(']') {
                    let key = &tok[1..e];
                    let rest = &tok[e + 1..];
                    let w = (key.chars().count() as i32 + 1) * size;
                    c.rect(cx, y - 2, w, size + 4, rgb(24, 40, 56), 255);
                    c.rect_outline(cx, y - 2, w, size + 4, 1, C_ACCENT, 255);
                    c.text(cx + size / 2, y, size, key, C_AMBER, 255);
                    cx += w + 2;
                    if !rest.is_empty() {
                        cx += c.text(cx, y, size, rest, col, 255);
                    }
                    cx += size;
                    continue;
                }
            }
            cx += c.text(cx, y, size, tok, col, 255) + size;
        }
    }

    pub(crate) fn draw_tutorial_ask(&mut self, c: &mut Canvas, ui: &Ui) {
        c.rect(0, 0, c.w as i32, c.h as i32, rgb(4, 6, 12), 190);
        let cx = c.w as i32 / 2;
        c.text_c(cx, ui.px(80.0), ui.px(30.0), self.t("FLIGHT SCHOOL"), C_ACCENT, 255);
        let w = ui.px(640.0).min(c.w as i32 - 40);
        let cols = (w / (ui.fs + 1)) as usize;
        let text = self.t("A short interactive tutorial teaches steering, throttle, targeting, weapons, the scanner, jumping, docking and trading. Each step waits for you to do it. You can skip it at any time with X.");
        let mut y = ui.px(140.0);
        for l in crate::view::wrap(text, cols) {
            c.text_c(cx, y, ui.fs + 1, &l, C_TEXT, 255);
            y += ui.lh;
        }
        let a = self.t("Start the tutorial");
        let b = self.t("Skip the tutorial");
        self.menu_list(c, ui, &[a, b], ui.px(260.0), &|_| true);
    }
}

/// Width of a token as `Game::rich` draws it, in units of the glyph size (key caps are wider).
fn tok_units(w: &str) -> usize {
    if let Some(e) = w.find(']') {
        if w.starts_with('[') {
            let key = w[1..e].chars().count();
            let rest = w[e + 1..].chars().count();
            return key + 1 + rest + 1; // cap, trailing punctuation and the 2px gap rounded up
        }
    }
    w.chars().count()
}

/// Word-wrap measured in glyph units, key caps included; `cols` is the real inner width in glyphs.
pub fn wrap_rich(text: &str, cols: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0usize;
    for w in text.split(' ') {
        let ww = tok_units(w);
        if cur_w > 0 && cur_w + 1 + ww > cols {
            lines.push(core::mem::take(&mut cur));
            cur_w = 0;
        }
        if cur_w > 0 {
            cur.push(' ');
            cur_w += 1;
        }
        cur.push_str(w);
        cur_w += ww;
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

const _UNUSED: usize = MAIN_ITEMS.len() + STATION_HALF_LEN as usize;
