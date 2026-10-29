// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Keyboard handling for menus and screens.
use crate::commander::*;
use crate::econ::*;
use crate::game::*;
use crate::galaxy::MAX_JUMP_LY;
use crate::story;

pub const MAIN_ITEMS: [&str; 7] = ["New Game", "Tutorial", "Continue", "Load Game", "Settings", "Credits", "Quit"];
pub const PAUSE_ITEMS: [&str; 4] = ["Resume", "Settings", "Save (docked only)", "Quit to menu"];
pub const SETTINGS_ROWS: usize = 10;
pub const CREDITS_LEN: f32 = 700.0;

fn nav(sel: &mut usize, n: usize, up: bool, down: bool) {
    if n == 0 {
        return;
    }
    if up {
        *sel = (*sel + n - 1) % n;
    }
    if down {
        *sel = (*sel + 1) % n;
    }
}

impl Game {
    pub fn goto(&mut self, s: Screen) {
        self.screen = s;
        self.sel = 0;
        self.page = 0;
    }

    pub(crate) fn ui_input(&mut self) {
        if self.input.p(Act::Skip) && self.tut.is_some() && self.started && !matches!(self.screen, Screen::Pause | Screen::Settings | Screen::Controls) {
            self.tut_finish(true);
            return;
        }
        if self.screen != Screen::Flight && (self.input.p(Act::Up) || self.input.p(Act::Down) || self.input.p(Act::Left) || self.input.p(Act::Right)) {
            self.synth.trigger(crate::audio::Sfx::Click, 0.0, 0.7);
        }
        if self.screen != Screen::Flight && self.input.p(Act::Enter) {
            self.synth.trigger(crate::audio::Sfx::Select, 0.0, 0.8);
        }
        let up = self.input.p(Act::Up);
        let down = self.input.p(Act::Down);
        let left = self.input.p(Act::Left);
        let right = self.input.p(Act::Right);
        let enter = self.input.p(Act::Enter) || self.input.p(Act::Fire) && !self.flying_screen();
        let back = self.input.p(Act::Back);
        match self.screen {
            Screen::Title => {
                if enter || back || self.input.p(Act::Pause) {
                    self.goto(Screen::MainMenu);
                }
            }
            Screen::MainMenu => {
                nav(&mut self.sel, MAIN_ITEMS.len(), up, down);
                if enter {
                    match self.sel {
                        0 => self.new_game(),
                        1 => self.start_tutorial(true),
                        2 => {
                            if let Some(s) = self.latest_slot() {
                                self.load_slot(s);
                            }
                        }
                        3 => self.goto(Screen::Load),
                        4 => {
                            self.settings_from = Screen::MainMenu;
                            self.goto(Screen::Settings);
                        }
                        5 => {
                            self.after_credits = Screen::MainMenu;
                            self.credits_y = 0.0;
                            self.goto(Screen::Credits);
                        }
                        _ => self.quit = true,
                    }
                }
                if back {
                    self.goto(Screen::Title);
                }
            }
            Screen::Intro => {
                if enter {
                    self.page += 1;
                    self.ui_t = 0.0;
                    if self.page >= story::INTRO.len() {
                        self.goto(Screen::TutorialAsk);
                    }
                }
                if back {
                    self.goto(Screen::TutorialAsk);
                }
            }
            Screen::Settings => {
                nav(&mut self.sel, SETTINGS_ROWS, up, down);
                let toggle = enter || left || right;
                if toggle {
                    let dir: i32 = if left { -1 } else { 1 };
                    match self.sel {
                        0 => self.settings.invert_pitch = !self.settings.invert_pitch,
                        1 => self.settings.bloom = !self.settings.bloom,
                        2 => self.settings.retro = !self.settings.retro,
                        3 => self.settings.quality = ((self.settings.quality as i32 + dir).rem_euclid(3)) as u8,
                        4 => {
                            let l = if self.settings.lang == crate::i18n::Lang::En { crate::i18n::Lang::Ru } else { crate::i18n::Lang::En };
                            self.settings.lang = l;
                        }
                        5 | 6 | 7 => {
                            let d = if left { -1 } else { 1 };
                            let r = match self.sel {
                                5 => &mut self.settings.vol_master,
                                6 => &mut self.settings.vol_sfx,
                                _ => &mut self.settings.vol_music,
                            };
                            *r = (*r as i32 + d).clamp(0, 10) as u8;
                            self.synth.trigger(crate::audio::Sfx::Select, 0.0, 0.8);
                        }
                        8 => {
                            if enter {
                                self.goto_keep(Screen::Controls);
                            }
                        }
                        _ => {
                            if enter {
                                self.io.push(Io::WriteSettings(self.settings.to_bytes()));
                                let s = self.settings_from;
                                self.goto(s);
                                return;
                            }
                        }
                    }
                    if self.sel < 8 {
                        self.io.push(Io::WriteSettings(self.settings.to_bytes()));
                    }
                }
                if back {
                    self.io.push(Io::WriteSettings(self.settings.to_bytes()));
                    let s = self.settings_from;
                    self.goto(s);
                }
            }
            Screen::Controls => {
                if left || right {
                    self.page = 1 - self.page.min(1);
                }
                if back || enter || self.input.p(Act::Help) {
                    let s = if self.settings_from == Screen::Controls { Screen::MainMenu } else { self.settings_from };
                    self.goto(s);
                }
            }
            Screen::Credits => {
                if back || enter || self.credits_y > CREDITS_LEN * 2.0 + 700.0 {
                    let s = self.after_credits;
                    self.goto(s);
                }
            }
            Screen::Load => {
                nav(&mut self.sel, SAVE_SLOTS, up, down);
                for n in 1..=5u8 {
                    if self.input.p(Act::digit(n)) {
                        self.sel = n as usize - 1;
                    }
                }
                if enter && !self.load_slot(self.sel) {
                    self.warn("That slot is empty");
                }
                if back {
                    self.goto(Screen::MainMenu);
                }
            }
            Screen::Save => {
                nav(&mut self.sel, SAVE_SLOTS, up, down);
                if enter {
                    let s = self.sel;
                    self.cur_slot = s;
                    self.save_to(s);
                }
                if back {
                    self.leave_to_status();
                }
            }
            Screen::Pause => {
                nav(&mut self.sel, PAUSE_ITEMS.len(), up, down);
                if enter {
                    match self.sel {
                        0 => self.screen = Screen::Flight,
                        1 => {
                            self.settings_from = Screen::Pause;
                            self.goto(Screen::Settings);
                        }
                        2 => self.warn("Dock at a station to save"),
                        _ => {
                            self.started = false;
                            self.goto(Screen::MainMenu);
                        }
                    }
                }
                if back || self.input.p(Act::Pause) {
                    self.screen = Screen::Flight;
                }
            }
            Screen::Briefing => {
                if enter || back {
                    let n = self.brief_next;
                    self.brief = None;
                    if self.screen == Screen::Briefing {
                        self.screen = n;
                        if n != Screen::Briefing {
                            self.sel = 0;
                        }
                    }
                }
            }
            Screen::TutorialAsk => {
                nav(&mut self.sel, 2, up, down);
                if enter {
                    if self.sel == 0 {
                        self.start_tutorial(false);
                    } else {
                        self.skip_tutorial_choice();
                    }
                }
            }
            Screen::Dead => {
                nav(&mut self.sel, 2, up, down);
                if enter {
                    if self.sel == 0 {
                        if let Some(s) = self.latest_slot() {
                            self.load_slot(s);
                        } else {
                            self.warn("No saved commander");
                        }
                    } else {
                        self.goto(Screen::MainMenu);
                    }
                }
            }
            Screen::Ending => {
                if enter {
                    self.page += 1;
                    self.ending_t = 0.0;
                    if self.page >= story::ENDING.len() {
                        self.after_credits = Screen::FreePlay;
                        self.credits_y = 0.0;
                        self.goto(Screen::Credits);
                    }
                }
            }
            Screen::FreePlay => {
                nav(&mut self.sel, 2, up, down);
                if enter {
                    self.cmdr.story.free_play = true;
                    self.cmdr.story.chapter = CHAPTERS;
                    self.cmdr.story.active = false;
                    let slot = self.cur_slot;
                    self.docked = true;
                    self.save_to(slot);
                    if self.sel == 0 {
                        self.screen = Screen::Status;
                        self.sel = 0;
                    } else {
                        self.goto(Screen::MainMenu);
                    }
                }
            }
            _ => self.game_screens_input(up, down, left, right, enter, back),
        }
    }

    fn flying_screen(&self) -> bool {
        matches!(self.screen, Screen::Flight)
    }

    fn goto_keep(&mut self, s: Screen) {
        let from = self.settings_from;
        self.screen = s;
        self.settings_from = from;
        self.page = 0;
    }

    fn leave_to_status(&mut self) {
        self.screen = if self.docked { Screen::Status } else { Screen::Flight };
        self.sel = 0;
    }

    fn game_screens_input(&mut self, up: bool, down: bool, left: bool, right: bool, enter: bool, back: bool) {
        if !self.started {
            return;
        }
        let i = self.input.clone();
        // screen switching
        let mut target: Option<Screen> = None;
        if i.p(Act::F1) {
            if self.docked {
                self.launch();
                return;
            }
            self.view = 0;
            target = Some(Screen::Flight);
        }
        if !self.docked {
            if i.p(Act::F2) {
                self.view = 1;
                target = Some(Screen::Flight);
            }
            if i.p(Act::F3) {
                self.view = 2;
                target = Some(Screen::Flight);
            }
            if i.p(Act::F4) {
                self.view = 3;
                target = Some(Screen::Flight);
            }
        }
        if i.p(Act::F5) {
            target = Some(Screen::Status);
        }
        if i.p(Act::F6) {
            target = Some(Screen::GalChart);
        }
        if i.p(Act::F7) {
            target = Some(Screen::LocalChart);
        }
        if i.p(Act::F8) {
            target = Some(Screen::SysInfo);
        }
        let dock_only = [(Act::F9, Screen::Market), (Act::F10, Screen::Equipment), (Act::F11, Screen::Contracts), (Act::F12, Screen::Save)];
        for (a, s) in dock_only {
            if i.p(a) {
                if self.docked {
                    target = Some(s);
                } else {
                    self.warn("Available only while docked");
                }
            }
        }
        if i.p(Act::Help) {
            self.settings_from = self.screen;
            self.screen = Screen::Controls;
            self.page = 0;
            return;
        }
        if let Some(t) = target {
            if t != self.screen {
                self.screen = t;
                self.sel = 0;
            }
            return;
        }
        match self.screen {
            Screen::Flight => {
                let i = self.input.clone();
                if i.p(Act::Pause) || back {
                    self.screen = Screen::Pause;
                    self.sel = 0;
                    return;
                }
                if i.p(Act::Hyper) {
                    self.try_hyper();
                }
                if i.p(Act::GalDrive) {
                    self.try_galdrive();
                }
                if i.p(Act::Eject) {
                    if self.cmdr.equip & EQ_CAPSULE != 0 && self.dying <= 0.0 {
                        self.world.kill_player("You ejected in the escape capsule.");
                        self.world.events.clear();
                        self.death_why = "You ejected in the escape capsule.";
                        self.dying = 1.2;
                    } else if self.cmdr.equip & EQ_CAPSULE == 0 {
                        self.warn("No escape capsule fitted");
                    }
                }
            }
            Screen::Status | Screen::SysInfo => {
                if back && !self.docked {
                    self.screen = Screen::Flight;
                }
                if self.screen == Screen::SysInfo {
                    self.chart_move(up, down, left, right);
                }
            }
            Screen::GalChart | Screen::LocalChart => {
                self.chart_move(up, down, left, right);
                if self.input.p(Act::Home) {
                    self.chart_sel = self.cmdr.system as usize;
                }
                if enter {
                    let d = self.chart_sel;
                    if d == self.cmdr.system as usize {
                        self.dest = None;
                        self.say("Destination cleared");
                    } else {
                        let dist = self.gal.dist_ly(self.cmdr.system as usize, d);
                        self.dest = Some(d);
                        if dist > MAX_JUMP_LY {
                            self.warn("Selected, but out of jump range");
                        } else if self.jump_cost(d) > self.cmdr.fuel {
                            self.warn("Selected, but you need more fuel");
                        } else {
                            let t = alloc::format!("Destination set: {}", self.gal.sys[d].name);
                            self.say(&t);
                        }
                    }
                }
                if back {
                    self.leave_to_status();
                }
            }
            Screen::Market => {
                nav(&mut self.sel, NCOM, up, down);
                let shift = self.input.h(Act::Shift);
                let sel = self.sel;
                if self.input.p(Act::Buy) || enter {
                    self.buy(sel, if shift { 10 } else { 1 });
                }
                if self.input.p(Act::Sell) {
                    if shift {
                        let n = self.cmdr.cargo[sel] as i32;
                        self.sell(sel, n);
                    } else {
                        self.sell(sel, 1);
                    }
                }
                if back {
                    self.leave_to_status();
                }
            }
            Screen::Equipment => {
                let rows = self.equipment_rows();
                nav(&mut self.sel, rows.len(), up, down);
                if enter {
                    let r = rows[self.sel.min(rows.len() - 1)].clone();
                    self.equip_act(&r);
                }
                if self.input.p(Act::Del) || self.input.p(Act::Sell) {
                    if let EqAct::Laser(m) = rows[self.sel.min(rows.len() - 1)].act {
                        self.remove_laser(m as usize);
                    }
                }
                if back {
                    self.leave_to_status();
                }
            }
            Screen::Contracts => {
                nav(&mut self.sel, 3, up, down);
                if enter {
                    if self.sel == 0 {
                        self.story_accept();
                    } else {
                        let s = self.sel - 1;
                        self.side_accept(s);
                    }
                }
                if back {
                    self.leave_to_status();
                }
            }
            _ => {}
        }
        let _ = (left, right);
    }

    fn chart_move(&mut self, up: bool, down: bool, left: bool, right: bool) {
        let (dx, dy) = ((right as i32) - (left as i32), (down as i32) - (up as i32));
        if dx != 0 || dy != 0 {
            self.chart_sel = self.gal.step(self.chart_sel, dx, dy);
        }
    }
}
