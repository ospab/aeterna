// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! The game: state machine, menus, trading, hyperspace, campaign and side contracts.
use crate::commander::*;
use crate::econ::*;
use crate::galaxy::*;
use crate::math::*;
use crate::models;
use crate::raster::*;
use crate::sim::*;
use crate::space::*;
use crate::story;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub const NACT: usize = 48;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Act {
    Left,
    Right,
    Up,
    Down,
    Faster,
    Slower,
    Fire,
    Missile,
    Target,
    Untarget,
    Chaff,
    Jump,
    Hyper,
    GalDrive,
    Dock,
    Pause,
    Help,
    Enter,
    Back,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    Buy,
    Sell,
    Shift,
    Home,
    Eject,
    Del,
    N1,
    N2,
    N3,
    N4,
    N5,
}

impl Act {
    pub fn idx(self) -> usize {
        self as usize
    }
    pub fn digit(n: u8) -> Act {
        match n {
            1 => Act::N1,
            2 => Act::N2,
            3 => Act::N3,
            4 => Act::N4,
            _ => Act::N5,
        }
    }
}

#[derive(Clone)]
pub struct Input {
    pub held: [bool; NACT],
    pub pressed: [bool; NACT],
}

impl Input {
    pub fn new() -> Input {
        Input { held: [false; NACT], pressed: [false; NACT] }
    }
    pub fn key(&mut self, a: Act, down: bool) {
        let i = a.idx();
        if down && !self.held[i] {
            self.pressed[i] = true;
        }
        self.held[i] = down;
    }
    pub fn end_frame(&mut self) {
        self.pressed = [false; NACT];
    }
    pub fn h(&self, a: Act) -> bool {
        self.held[a.idx()]
    }
    pub fn p(&self, a: Act) -> bool {
        self.pressed[a.idx()]
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Settings {
    pub invert_pitch: bool,
    pub bloom: bool,
    pub retro: bool,
    /// 0 low, 1 medium, 2 high internal 3D resolution.
    pub quality: u8,
}

impl Settings {
    pub fn default_settings() -> Settings {
        Settings { invert_pitch: false, bloom: true, retro: false, quality: 1 }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        alloc::vec![b'D', b'C', 1, self.invert_pitch as u8, self.bloom as u8, self.retro as u8, self.quality]
    }
    pub fn from_bytes(b: &[u8]) -> Option<Settings> {
        if b.len() < 7 || b[0] != b'D' || b[1] != b'C' || b[2] != 1 || b[6] > 2 {
            return None;
        }
        Some(Settings { invert_pitch: b[3] != 0, bloom: b[4] != 0, retro: b[5] != 0, quality: b[6] })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    Title,
    MainMenu,
    Intro,
    Settings,
    Controls,
    Credits,
    Load,
    Save,
    Flight,
    Pause,
    Status,
    GalChart,
    LocalChart,
    SysInfo,
    Market,
    Equipment,
    Contracts,
    Briefing,
    Dead,
    Ending,
    FreePlay,
}

pub enum Io {
    WriteSlot { slot: usize, data: Vec<u8> },
    WriteSettings(Vec<u8>),
}

pub struct LogLine {
    pub text: String,
    pub age: f32,
    pub warn: bool,
}

pub struct Brief {
    pub title: String,
    pub body: Vec<String>,
    pub reward: i64,
}

#[derive(Clone, Copy)]
pub struct Hyper {
    pub t: f32,
    pub dest: usize,
    pub galaxy_jump: bool,
    pub free: bool,
}

pub struct DeathStats {
    pub kills: u32,
    pub credits: i64,
    pub jumps: u32,
    pub seconds: u32,
    pub why: &'static str,
}

pub struct Game {
    pub cmdr: Commander,
    pub gal: Galaxy,
    pub market: Market,
    pub world: World,
    pub screen: Screen,
    pub docked: bool,
    pub settings: Settings,
    pub input: Input,
    pub sel: usize,
    pub chart_sel: usize,
    pub dest: Option<usize>,
    pub log: Vec<LogLine>,
    pub brief: Option<Brief>,
    pub brief_next: Screen,
    pub hyper: Option<Hyper>,
    pub pocket_dest: Option<usize>,
    pub acc: f32,
    pub io: Vec<Io>,
    pub slots: [Option<Commander>; SAVE_SLOTS],
    pub quit: bool,
    pub view: u8,
    pub ui_t: f32,
    pub page: usize,
    pub settings_from: Screen,
    pub dying: f32,
    pub death_why: &'static str,
    pub stats: Option<DeathStats>,
    pub(crate) fuel_acc: f32,
    pub(crate) heat_acc: f32,
    pub(crate) rng: Rng,
    pub(crate) sealed_story: u8,
    pub(crate) meshes: Vec<Mesh>,
    pub(crate) sky: Sky,
    pub(crate) ptex: PlanetTex,
    pub(crate) scene: Scene,
    pub(crate) tmp: Vec<V3>,
    pub(crate) save_msg: Option<String>,
    pub(crate) tab_flash: f32,
    pub(crate) ending_t: f32,
    pub(crate) credits_y: f32,
    pub(crate) after_credits: Screen,
    pub(crate) started: bool,
    pub cur_slot: usize,
}

pub fn start_system(g: &Galaxy) -> usize {
    let mut best = 0;
    let mut bs = f32::MAX;
    for (i, s) in g.sys.iter().enumerate() {
        if s.tech < 5 || s.economy == 7 {
            continue;
        }
        let near = (0..SYSTEMS).filter(|&j| j != i && g.dist_ly(i, j) <= MAX_JUMP_LY).count();
        if near < 5 {
            continue;
        }
        let (dx, dy) = (s.x as f32 - 128.0, s.y as f32 - 128.0);
        let d = dx * dx + dy * dy;
        if d < bs {
            bs = d;
            best = i;
        }
    }
    best
}

impl Game {
    pub fn new(seed: u64) -> Game {
        let gal = Galaxy::generate(0);
        let cmdr = Commander::new("Rook");
        let sys = start_system(&gal);
        let sinfo = gal.sys[sys].clone();
        let mut world = World::new(seed);
        let mut c = cmdr.clone();
        c.system = sys as u8;
        world.setup(&sinfo, Arrival::Hyper, &c);
        let market = Market::generate(&sinfo, 1);
        let ptex = PlanetTex::generate(sinfo.seed, sinfo.planet, 256, 0.8);
        let sky = Sky::generate(sinfo.seed);
        Game {
            cmdr: c,
            gal,
            market,
            world,
            screen: Screen::Title,
            docked: true,
            settings: Settings::default_settings(),
            input: Input::new(),
            sel: 0,
            chart_sel: sys,
            dest: None,
            log: Vec::new(),
            brief: None,
            brief_next: Screen::Status,
            hyper: None,
            pocket_dest: None,
            acc: 0.0,
            io: Vec::new(),
            slots: [None, None, None, None, None],
            quit: false,
            view: 0,
            ui_t: 0.0,
            page: 0,
            settings_from: Screen::MainMenu,
            dying: 0.0,
            death_why: "",
            stats: None,
            fuel_acc: 0.0,
            heat_acc: 0.0,
            rng: Rng::new(seed ^ 0xBEEF),
            sealed_story: 0,
            meshes: models::build_all(),
            sky,
            ptex,
            scene: Scene::new(640, 360),
            tmp: Vec::new(),
            save_msg: None,
            tab_flash: 0.0,
            ending_t: 0.0,
            credits_y: 0.0,
            after_credits: Screen::MainMenu,
            started: false,
            cur_slot: 0,
        }
    }

    // ------------------------------------------------------------------ io

    pub fn take_io(&mut self) -> Vec<Io> {
        core::mem::take(&mut self.io)
    }
    pub fn provide_slot(&mut self, slot: usize, data: Option<&[u8]>) {
        if slot < SAVE_SLOTS {
            self.slots[slot] = data.and_then(Commander::from_bytes);
        }
    }
    pub fn provide_settings(&mut self, data: &[u8]) {
        if let Some(s) = Settings::from_bytes(data) {
            self.settings = s;
        }
    }
    pub fn sys(&self) -> &SystemInfo {
        &self.gal.sys[self.cmdr.system as usize]
    }

    pub fn say(&mut self, t: &str) {
        self.log.push(LogLine { text: String::from(t), age: 0.0, warn: false });
        if self.log.len() > 6 {
            self.log.remove(0);
        }
    }
    pub fn warn(&mut self, t: &str) {
        self.log.push(LogLine { text: String::from(t), age: 0.0, warn: true });
        if self.log.len() > 6 {
            self.log.remove(0);
        }
    }

    // ------------------------------------------------------------------ game start / load

    pub fn new_game(&mut self) {
        self.cmdr = Commander::new("Rook");
        let sys = start_system(&self.gal) as u8;
        self.cmdr.system = sys;
        self.cmdr.story = Story { chapter: 0, stage: 0, active: true, progress: 0, sys: [sys, sys, sys], hub: sys, intro_seen: true, free_play: false };
        self.enter_station(Arrival::Hyper);
        self.log.clear();
        self.screen = Screen::Intro;
        self.page = 0;
        self.ui_t = 0.0;
        self.started = true;
        self.dying = 0.0;
        self.stats = None;
    }

    pub fn load_slot(&mut self, slot: usize) -> bool {
        let c = match self.slots.get(slot).and_then(|s| s.clone()) {
            Some(c) => c,
            None => return false,
        };
        if self.gal.index != c.galaxy as usize {
            self.gal = Galaxy::generate(c.galaxy as usize);
        }
        self.cmdr = c;
        self.cur_slot = slot;
        self.enter_station(Arrival::Hyper);
        self.log.clear();
        self.screen = Screen::Status;
        self.started = true;
        self.dying = 0.0;
        self.stats = None;
        self.say("Commander loaded");
        true
    }

    pub fn latest_slot(&self) -> Option<usize> {
        let mut best: Option<(usize, u32)> = None;
        for (i, s) in self.slots.iter().enumerate() {
            if let Some(c) = s {
                if best.map_or(true, |(_, t)| c.play_seconds >= t) {
                    best = Some((i, c.play_seconds));
                }
            }
        }
        best.map(|b| b.0)
    }

    fn load_assets_for_system(&mut self) {
        let s = self.gal.sys[self.cmdr.system as usize].clone();
        let lights = clamp(s.pop as f32 / 150.0, 0.2, 1.0);
        self.ptex = PlanetTex::generate(s.seed, s.planet, 256, lights);
        self.sky = Sky::generate(s.seed);
        self.market = Market::generate(&s, self.cmdr.market_tick);
    }

    /// Put the player in the station of the current system (docked), with a showcase world behind.
    fn enter_station(&mut self, arrival: Arrival) {
        self.load_assets_for_system();
        let s = self.gal.sys[self.cmdr.system as usize].clone();
        self.world.setup(&s, arrival, &self.cmdr);
        self.world.ships.retain(|x| matches!(x.fac, Faction::Civil | Faction::Police));
        self.docked = true;
        self.hyper = None;
        self.pocket_dest = None;
        self.chart_sel = self.cmdr.system as usize;
        self.dest = None;
        self.sel = 0;
    }

    // ------------------------------------------------------------------ names

    fn names(&self) -> [String; 4] {
        let n = |i: u8| self.gal.sys[i as usize].name.clone();
        let st = &self.cmdr.story;
        [n(st.sys[0]), n(st.sys[1]), n(st.sys[2]), n(st.hub)]
    }

    pub fn objective_text(&self) -> Option<String> {
        let st = &self.cmdr.story;
        if !st.active || self.cmdr.galaxy != 0 {
            return None;
        }
        let n = self.names();
        let t = match (st.chapter, st.stage) {
            (0, 0) => String::from("Fly to the beacon"),
            (0, _) => String::from("Dock at the station"),
            (1, _) => format!("Deliver the ledger to {}", n[0]),
            (2, 0) => format!("Salvage cargo at {} ({}/3)", n[1], st.progress),
            (3, 0) => format!("Destroy Dann Corvane at {}", n[1]),
            (4, 0) => format!("Meet the Vael envoy at {}", n[1]),
            (5, 0) => format!("Destroy the raiders at {} ({}/5)", n[2], st.progress),
            (6, _) => format!("Destroy the Cinder Sovereign at {}", n[2]),
            _ => format!("Report to {}", n[3]),
        };
        Some(t)
    }

    // ------------------------------------------------------------------ update

    pub fn update(&mut self, dt: f32) {
        let dt = dt.min(0.25);
        self.ui_t += dt;
        for l in self.log.iter_mut() {
            l.age += dt;
        }
        self.log.retain(|l| l.age < 9.0);
        self.tab_flash = max(0.0, self.tab_flash - dt);
        self.ui_input();
        self.acc += dt;
        let mut first = true;
        let mut guard = 0;
        while self.acc >= DT && guard < 6 {
            self.acc -= DT;
            guard += 1;
            self.tick(first);
            first = false;
        }
        if self.acc > DT * 6.0 {
            self.acc = 0.0;
        }
        self.input.end_frame();
    }

    fn flying(&self) -> bool {
        !self.docked && self.started && !matches!(self.screen, Screen::Title | Screen::MainMenu | Screen::Intro | Screen::Load | Screen::Credits | Screen::Dead | Screen::Ending | Screen::FreePlay)
    }

    fn controls(&self, first: bool) -> Controls {
        let i = &self.input;
        let mut c = Controls::default();
        c.roll = (i.h(Act::Right) as i32 - i.h(Act::Left) as i32) as f32;
        let mut p = (i.h(Act::Down) as i32 - i.h(Act::Up) as i32) as f32;
        if self.settings.invert_pitch {
            p = -p;
        }
        c.pitch = p;
        c.throttle_up = i.h(Act::Faster);
        c.throttle_down = i.h(Act::Slower);
        c.fire = i.h(Act::Fire);
        c.jump = i.h(Act::Jump);
        c.view = self.view;
        if first {
            c.missile = i.p(Act::Missile);
            c.lock = i.p(Act::Target);
            c.unlock = i.p(Act::Untarget);
            c.chaff = i.p(Act::Chaff);
            c.dock_toggle = i.p(Act::Dock);
        }
        c
    }

    fn tick(&mut self, first: bool) {
        let active_flight = self.flying() && matches!(self.screen, Screen::Flight | Screen::Status | Screen::GalChart | Screen::LocalChart | Screen::SysInfo | Screen::Briefing | Screen::Market | Screen::Equipment | Screen::Contracts | Screen::Save);
        if self.screen == Screen::Pause {
            return;
        }
        if active_flight && self.dying <= 0.0 {
            let mut ctl = if self.screen == Screen::Flight && self.hyper.as_ref().map_or(true, |h| h.t > 1.2) { self.controls(first) } else { Controls::default() };
            ctl.view = self.view;
            if self.hyper.is_some() {
                ctl.jump = false;
            }
            self.world.step(&ctl, &self.cmdr);
            self.flight_tick();
        } else if self.dying > 0.0 {
            let ctl = Controls::default();
            self.world.step(&ctl, &self.cmdr);
            self.dying -= DT;
            if self.dying <= 0.0 {
                self.finish_death();
            }
        } else {
            // showcase
            self.world.p.speed = 0.0;
            self.world.p.throttle = 0.0;
            let ctl = Controls::default();
            self.world.step(&ctl, &self.cmdr);
            self.world.events.clear();
            self.world.p.alive = true;
            self.world.p.energy = self.world.p.energy_max;
        }
        if self.screen == Screen::Ending {
            self.ending_t += DT;
        }
        if self.screen == Screen::Credits {
            self.credits_y += DT * 38.0;
        }
        self.process_events();
        if !self.docked && self.screen != Screen::Pause {
            self.heat_acc += DT;
            if self.heat_acc >= 1.0 {
                self.heat_acc -= 1.0;
                self.cmdr.play_seconds += 1;
                if self.cmdr.heat > 0 && self.cmdr.play_seconds % 25 == 0 {
                    self.cmdr.heat -= 1;
                }
            }
        }
    }

    fn flight_tick(&mut self) {
        // hyperspace countdown and tunnel
        if let Some(mut h) = self.hyper {
            h.t -= DT;
            if h.t <= 0.0 {
                self.hyper = None;
                self.complete_hyper(h);
            } else {
                self.hyper = Some(h);
            }
        }
        // campaign waypoints and contact
        let st = self.cmdr.story.clone();
        if st.active && self.cmdr.galaxy == 0 {
            if st.chapter == 0 && st.stage == 0 {
                if let Some(b) = self.world.beacon {
                    if (b - self.world.p.pos).len() < 500.0 {
                        self.world.beacon = None;
                        self.cmdr.story.stage = 1;
                        self.say("Beacon calibrated. Return to the station and dock.");
                    }
                }
            }
            if st.chapter == 4 && st.stage == 0 {
                let pp = self.world.p.pos;
                let near = self.world.ships.iter().any(|s| s.tag == 5 && (s.pos - pp).len() < 1300.0);
                if near {
                    self.world.contact_t += DT;
                    if self.world.contact_t > 6.0 {
                        self.world.contact_t = -1000.0;
                        self.cmdr.story.stage = 1;
                        self.say("Contact: the Vael envoy answers the Venn Key");
                        self.warn("Hostile contacts inbound");
                        for _ in 0..3 {
                            self.world.spawn_hostile_group_member(Kind::Jackal, Faction::Pirate, 4500.0);
                        }
                    }
                } else if self.world.contact_t > 0.0 {
                    self.world.contact_t = max(0.0, self.world.contact_t - DT);
                }
            }
        }
    }

    // ------------------------------------------------------------------ events

    fn process_events(&mut self) {
        let evs = core::mem::take(&mut self.world.events);
        for e in evs {
            match e {
                Ev::Msg(s) => self.say(&s),
                Ev::Warn(s) => self.warn(&s),
                Ev::Crime(n) => {
                    let before = self.cmdr.legal();
                    self.cmdr.heat = (self.cmdr.heat + n).min(250);
                    if self.cmdr.legal() != before && self.cmdr.legal() != Legal::Clean {
                        let t = if self.cmdr.legal() == Legal::Fugitive { "You are now a Fugitive" } else { "You are now an Offender" };
                        self.warn(t);
                    }
                }
                Ev::Kill { fac, kind, bounty, tag } => {
                    if matches!(fac, Faction::Pirate | Faction::Alien | Faction::Hunter) {
                        self.cmdr.kills += 1;
                        if bounty > 0 {
                            self.cmdr.credits += bounty as i64;
                            let t = format!("{} destroyed: bounty {} cr", spec(kind).name, bounty);
                            self.say(&t);
                        }
                    }
                    self.on_tagged_kill(tag);
                }
                Ev::Scoop { item, tag } => {
                    if tag == 3 {
                        self.on_story_scoop();
                    } else if item >= 0 {
                        let i = item as usize;
                        if self.cmdr.cargo[i] < 250 {
                            self.cmdr.cargo[i] += 1;
                            let t = format!("Scooped: {}", COMMODITIES[i].name);
                            self.say(&t);
                        }
                    }
                }
                Ev::FuelAdd(_) => {
                    self.fuel_acc += DT * 4.0;
                    while self.fuel_acc >= 1.0 {
                        self.fuel_acc -= 1.0;
                        if self.cmdr.fuel < MAX_FUEL_TENTHS {
                            self.cmdr.fuel += 1;
                        }
                    }
                }
                Ev::Docked => self.on_docked(),
                Ev::Died(why) => {
                    if self.dying <= 0.0 {
                        self.dying = 3.0;
                        self.death_why = why;
                    }
                }
                Ev::Damaged(flag) => {
                    if flag == 0xFFFF_FFFF {
                        self.cmdr.missiles = self.cmdr.missiles.saturating_sub(1);
                    } else {
                        let laser_bit = flag >= (1 << 12);
                        let present = if laser_bit {
                            let m = (flag >> 12).trailing_zeros() as usize;
                            self.cmdr.lasers[m & 3] != LASER_NONE
                        } else {
                            self.cmdr.equip & flag != 0
                        };
                        if present && self.cmdr.damaged & flag == 0 {
                            self.cmdr.damaged |= flag;
                            self.warn("System damaged: repair at a station");
                        }
                    }
                }
                Ev::Rescue(cr) => {
                    self.cmdr.credits += cr;
                    let t = format!("Evacuee rescued: reward {} cr", cr);
                    self.say(&t);
                }
            }
        }
    }

    fn finish_death(&mut self) {
        let has_capsule = self.cmdr.equip & EQ_CAPSULE != 0;
        if has_capsule {
            // the ship is lost, the commander is picked up and re-fitted with a basic ship
            let keep = self.cmdr.clone();
            let mut c = Commander::new(&keep.name);
            c.credits = keep.credits;
            c.kills = keep.kills;
            c.galaxy = keep.galaxy;
            c.system = keep.system;
            c.play_seconds = keep.play_seconds;
            c.market_tick = keep.market_tick + 1;
            c.jumps = keep.jumps;
            c.missions_done = keep.missions_done;
            c.story = keep.story.clone();
            c.heat = keep.heat.min(OFFENDER_HEAT - 1);
            self.cmdr = c;
            if self.cmdr.story.active && self.cmdr.story.chapter == 1 {
                self.cmdr.story.stage = 0;
            }
            self.enter_station(Arrival::Hyper);
            self.screen = Screen::Status;
            self.warn("Escape capsule recovered. The ship, cargo and fittings are lost; a basic ship was issued.");
        } else {
            self.stats = Some(DeathStats { kills: self.cmdr.kills, credits: self.cmdr.credits, jumps: self.cmdr.jumps, seconds: self.cmdr.play_seconds, why: self.death_why });
            self.screen = Screen::Dead;
            self.sel = 0;
            self.started = false;
        }
    }

    // ------------------------------------------------------------------ docking and launching

    fn on_docked(&mut self) {
        if self.docked {
            return;
        }
        self.docked = true;
        self.world.p.dockcomp = false;
        self.world.p.speed = 0.0;
        self.world.ships.retain(|x| matches!(x.fac, Faction::Civil | Faction::Police));
        self.world.bolts.clear();
        self.hyper = None;
        self.pocket_dest = None;
        self.world.beacon = None;
        let law = self.sys().law() as f32;
        // police scan
        let units = self.cmdr.illegal_units();
        if units > 0 {
            let mut chance = law / 8.0;
            if self.cmdr.has(EQ_GHOST) {
                chance *= 0.3;
            }
            if self.rng.chance(chance) {
                for (i, c) in COMMODITIES.iter().enumerate() {
                    if c.illegal {
                        self.cmdr.cargo[i] = 0;
                    }
                }
                let fine = (units as i64 * 150).min(self.cmdr.credits.max(0));
                self.cmdr.credits -= fine;
                self.cmdr.heat += units * 4;
                let t = format!("Customs scan: {} illegal units seized, fine {} cr", units, fine);
                self.warn(&t);
            }
        }
        if self.cmdr.legal() == Legal::Fugitive {
            let fine = (self.cmdr.heat as i64 * 15).min(self.cmdr.credits.max(0));
            self.cmdr.credits -= fine;
            self.cmdr.heat = OFFENDER_HEAT - 1;
            let t = format!("Authorities fine you {} cr; your record is reduced to a warning", fine);
            self.warn(&t);
        }
        self.sel = 0;
        self.screen = Screen::Status;
        self.story_on_dock();
    }

    pub fn launch(&mut self) {
        if !self.docked {
            return;
        }
        let s = self.gal.sys[self.cmdr.system as usize].clone();
        self.world.setup(&s, Arrival::Launch, &self.cmdr);
        self.docked = false;
        self.screen = Screen::Flight;
        self.view = 0;
        self.hyper = None;
        self.acc = 0.0;
        self.story_spawn(true);
        self.say("Launch");
    }

    // ------------------------------------------------------------------ hyperspace

    pub fn jump_cost(&self, dest: usize) -> i32 {
        let d = self.gal.dist_ly(self.cmdr.system as usize, dest);
        ((d * 10.0) + 0.99) as i32
    }

    pub fn try_hyper(&mut self) {
        if self.docked || self.hyper.is_some() {
            return;
        }
        if self.world.pocket {
            if let Some(d) = self.pocket_dest {
                self.say("Re-entering the drift");
                self.hyper = Some(Hyper { t: 3.0, dest: d, galaxy_jump: false, free: true });
            }
            return;
        }
        let dest = match self.dest {
            Some(d) if d != self.cmdr.system as usize => d,
            _ => {
                self.warn("Pick a destination on the galactic chart first (F6)");
                return;
            }
        };
        if self.world.mass_locked() {
            self.warn("Mass lock: cannot start the jump drive here");
            return;
        }
        let cost = self.jump_cost(dest);
        if self.gal.dist_ly(self.cmdr.system as usize, dest) > MAX_JUMP_LY + 0.01 {
            self.warn("Destination is out of jump range");
            return;
        }
        if cost > self.cmdr.fuel {
            self.warn("Not enough fuel for that jump");
            return;
        }
        self.say("Jump drive spooling");
        self.hyper = Some(Hyper { t: 4.0, dest, galaxy_jump: false, free: false });
    }

    pub fn try_galdrive(&mut self) {
        if self.docked || self.hyper.is_some() || self.world.pocket {
            return;
        }
        if !self.cmdr.has(EQ_GALDRIVE) {
            self.warn("No galactic drive");
            return;
        }
        if self.world.mass_locked() {
            self.warn("Mass lock: cannot start the galactic drive here");
            return;
        }
        self.say("Galactic drive spooling");
        self.hyper = Some(Hyper { t: 5.0, dest: 0, galaxy_jump: true, free: true });
    }

    fn complete_hyper(&mut self, h: Hyper) {
        if h.galaxy_jump {
            let next = (self.cmdr.galaxy as usize + 1) % GALAXIES;
            let ng = Galaxy::generate(next);
            let arr = self.gal.galactic_arrival(self.cmdr.system as usize, &ng);
            self.gal = ng;
            self.cmdr.galaxy = next as u8;
            self.cmdr.system = arr as u8;
            self.cmdr.equip &= !EQ_GALDRIVE;
            self.cmdr.jumps += 1;
            self.cmdr.market_tick += 1;
            self.dest = None;
            self.arrive(false, None);
            self.say("Welcome to the next galaxy");
            return;
        }
        if !h.free {
            self.cmdr.fuel -= self.jump_cost(h.dest);
        }
        self.cmdr.jumps += 1;
        self.cmdr.market_tick += 1;
        self.cmdr.heat = (self.cmdr.heat - 3).max(0);
        // drift ambush: a pocket that is not on the chart
        let dsys = self.gal.sys[h.dest].clone();
        let p = 0.05 + (7 - dsys.law() as i32) as f32 * 0.012;
        let allow = !h.free && !(self.cmdr.story.active && self.cmdr.story.chapter == 0);
        if allow && self.rng.chance(p) {
            self.pocket_dest = Some(h.dest);
            self.dest = None;
            self.arrive_pocket();
            return;
        }
        self.cmdr.system = h.dest as u8;
        self.dest = None;
        self.arrive(true, None);
    }

    fn arrive_pocket(&mut self) {
        let s = self.gal.sys[self.cmdr.system as usize].clone();
        self.world.setup(&s, Arrival::Pocket, &self.cmdr);
        self.sky = Sky::generate(self.rng.next_u64());
        self.hyper = None;
        self.warn("Drift ambush: you were pulled into a pocket. Hold on, then press H to re-enter.");
    }

    fn arrive(&mut self, interception: bool, _x: Option<u8>) {
        self.load_assets_for_system();
        let s = self.gal.sys[self.cmdr.system as usize].clone();
        self.world.setup(&s, Arrival::Hyper, &self.cmdr);
        self.hyper = None;
        self.chart_sel = self.cmdr.system as usize;
        let t = format!("Arrived at {}", s.name);
        self.say(&t);
        self.story_spawn(false);
        self.side_spawn();
        if interception && self.cmdr.sealed > 0 && self.rng.chance(0.4) {
            for _ in 0..2 {
                self.world.spawn_hostile_group_member(Kind::Jackal, Faction::Pirate, 5000.0);
            }
            self.warn("Raiders are tracking your package");
        }
    }

    // ------------------------------------------------------------------ story logic

    fn pick_systems(&mut self, from: usize, chapter: u8) -> [u8; 3] {
        let g = &self.gal;
        let near = |c: usize, lo: f32, hi: f32, ex: &[usize], rng: &mut Rng| -> usize {
            let cands: Vec<usize> = (0..SYSTEMS).filter(|&j| j != c && !ex.contains(&j) && g.dist_ly(c, j) >= lo && g.dist_ly(c, j) <= hi).collect();
            if cands.is_empty() {
                (c + 1 + rng.below(100) as usize) % SYSTEMS
            } else {
                cands[rng.below(cands.len() as u32) as usize]
            }
        };
        let mut rng = Rng::new(self.cmdr.rng ^ (chapter as u64 * 0x9E37));
        self.cmdr.rng = rng.next_u64();
        if chapter == 1 {
            let a = near(from, 3.0, 6.5, &[], &mut rng);
            let b = near(a, 4.0, 7.0, &[from, a], &mut rng);
            let c = near(b, 4.0, 7.0, &[from, a, b], &mut rng);
            [a as u8, b as u8, c as u8]
        } else {
            let hub = self.cmdr.story.hub as usize;
            let b = near(hub, 3.0, 7.0, &[], &mut rng);
            let c = near(b, 4.0, 7.0, &[hub, b], &mut rng);
            [hub as u8, b as u8, c as u8]
        }
    }

    pub fn story_offer_available(&self) -> bool {
        let st = &self.cmdr.story;
        !st.active && st.chapter >= 1 && st.chapter < CHAPTERS && self.cmdr.galaxy == 0
    }

    pub fn story_accept(&mut self) {
        if !self.story_offer_available() {
            return;
        }
        let ch = self.cmdr.story.chapter;
        let def = story::chapter(ch);
        if !story::gate_ok(&def.gate, &self.cmdr) {
            self.warn("You are not ready for this contract yet");
            return;
        }
        if ch == 1 && self.cmdr.hold_free() < 1 {
            self.warn("You need one free hold slot for the sealed ledger");
            return;
        }
        let here = self.cmdr.system as usize;
        let sys = self.pick_systems(here, ch);
        let st = &mut self.cmdr.story;
        st.sys = sys;
        st.active = true;
        st.stage = 0;
        st.progress = 0;
        if ch == 1 {
            st.hub = sys[0];
            self.cmdr.sealed += 1;
        }
        let names = self.names();
        let body: Vec<String> = def.accept.iter().map(|t| story::fill(t, &names)).collect();
        self.brief = Some(Brief { title: String::from(def.title), body, reward: def.reward });
        self.brief_next = Screen::Contracts;
        self.screen = Screen::Briefing;
    }

    pub fn show_start_brief(&mut self) {
        let def = story::chapter(0);
        let names = self.names();
        let body: Vec<String> = def.accept.iter().map(|t| story::fill(t, &names)).collect();
        self.brief = Some(Brief { title: String::from(def.title), body, reward: def.reward });
        self.brief_next = Screen::Status;
        self.screen = Screen::Briefing;
    }

    fn complete_chapter(&mut self) {
        let ch = self.cmdr.story.chapter;
        let def = story::chapter(ch);
        self.cmdr.credits += def.reward;
        let names = self.names();
        let mut body: Vec<String> = def.done.iter().map(|t| story::fill(t, &names)).collect();
        body.push(format!("Reward: {} credits", def.reward));
        self.brief = Some(Brief { title: format!("{}: complete", def.title), body, reward: def.reward });
        self.brief_next = Screen::Status;
        self.screen = Screen::Briefing;
        let st = &mut self.cmdr.story;
        st.chapter += 1;
        st.active = false;
        st.stage = 0;
        st.progress = 0;
        if ch == 1 || ch == 0 {
            // the hub is where the ledger went
        }
        self.cmdr.sealed = self.cmdr.sealed.saturating_sub(self.sealed_story.min(self.cmdr.sealed));
        self.sealed_story = 0;
        if ch == 0 {
            self.cmdr.story.hub = self.cmdr.system;
        }
    }

    fn story_on_dock(&mut self) {
        let here = self.cmdr.system;
        let st = self.cmdr.story.clone();
        if st.active && self.cmdr.galaxy == 0 {
            let done = match (st.chapter, st.stage) {
                (0, 1) => here == st.sys[0],
                (1, 0) => {
                    if here == st.sys[0] {
                        self.cmdr.sealed = self.cmdr.sealed.saturating_sub(1);
                        true
                    } else {
                        false
                    }
                }
                (2, 1) | (3, 1) | (4, 1) | (5, 1) => here == st.hub,
                _ => false,
            };
            if done {
                if st.chapter == 2 {
                    self.cmdr.sealed = 0;
                }
                self.complete_chapter();
            }
        }
        // side contracts
        let mut finished: Vec<usize> = Vec::new();
        for (i, m) in self.cmdr.missions.iter().enumerate() {
            let ok = match m.kind {
                MISSION_LEDGER => m.gal == self.cmdr.galaxy && here == m.a,
                MISSION_HUNT => m.stage == 1 && here == m.origin && m.gal == self.cmdr.galaxy,
                _ => false,
            };
            if ok {
                finished.push(i);
            }
        }
        for i in finished.into_iter().rev() {
            let m = self.cmdr.missions.remove(i);
            if m.kind == MISSION_LEDGER {
                self.cmdr.sealed = self.cmdr.sealed.saturating_sub(1);
            }
            self.cmdr.credits += m.reward as i64;
            self.cmdr.missions_done += 1;
            let t = format!("Contract complete: {} cr", m.reward);
            self.say(&t);
        }
    }

    fn on_tagged_kill(&mut self, tag: u8) {
        if tag == 0 {
            return;
        }
        let st = self.cmdr.story.clone();
        if st.active && self.cmdr.galaxy == 0 && st.stage == 0 {
            match (st.chapter, tag) {
                (3, 1) => {
                    self.cmdr.story.stage = 1;
                    self.say("Corvane is down. Report to the broker.");
                }
                (5, 6) => {
                    self.cmdr.story.progress += 1;
                    if self.cmdr.story.progress >= 5 {
                        self.cmdr.story.stage = 1;
                        self.say("The raiders are finished. Report to the broker.");
                    }
                }
                (6, 9) => {
                    self.cmdr.story.stage = 1;
                    self.start_ending();
                }
                _ => {}
            }
        }
        if tag == 11 {
            let g = self.cmdr.galaxy;
            let sysn = self.cmdr.system;
            for m in self.cmdr.missions.iter_mut() {
                if m.kind == MISSION_HUNT && m.stage == 0 && m.gal == g && m.a == sysn {
                    m.stage = 1;
                }
            }
            self.say("Target eliminated. Return to the contract station.");
        }
    }

    fn on_story_scoop(&mut self) {
        let st = self.cmdr.story.clone();
        if st.active && st.chapter == 2 && st.stage == 0 {
            self.cmdr.story.progress += 1;
            self.cmdr.sealed += 1;
            self.sealed_story += 1;
            let t = format!("Recovered cargo {}/3", self.cmdr.story.progress);
            self.say(&t);
            if self.cmdr.story.progress >= 3 {
                self.cmdr.story.stage = 1;
                self.say("All canisters recovered. Return to the broker.");
            }
        }
    }

    /// Spawn campaign content for the current system (after arrival or launch).
    fn story_spawn(&mut self, launched: bool) {
        let st = self.cmdr.story.clone();
        if !st.active || self.cmdr.galaxy != 0 {
            return;
        }
        let here = self.cmdr.system;
        match (st.chapter, st.stage) {
            (0, 0) if launched => {
                if let Some((sp, fr)) = self.world.station_frame() {
                    self.world.beacon = Some(sp + fr.f * 5500.0 + fr.r * 1500.0 + fr.u * 700.0);
                }
                self.say("Fly to the beacon. A and Z set throttle, arrows steer.");
            }
            (2, 0) if here == st.sys[1] && !launched => {
                for _ in 0..(3 - st.progress.min(3)) {
                    let d = self.rng.unit() * 2500.0 + self.world.p.pos + self.world.p.o.f * 3000.0;
                    self.world.spawn_canister(d, 6, 3);
                }
                self.world.spawn_hostile_group_member(Kind::Jackal, Faction::Pirate, 7000.0);
                self.world.spawn_hostile_group_member(Kind::Jackal, Faction::Pirate, 7500.0);
                self.say("Cargo canisters on the scanner");
            }
            (3, 0) if here == st.sys[1] && !launched => {
                self.world.spawn_tagged(Kind::Hyena, 1, 8000.0);
                self.world.spawn_hostile_group_member(Kind::Jackal, Faction::Pirate, 8500.0);
                self.world.spawn_hostile_group_member(Kind::Jackal, Faction::Pirate, 8700.0);
                self.warn("Dann Corvane is here");
            }
            (4, 0) if here == st.sys[1] && !launched => {
                let i = self.world.spawn_hostile_group_member(Kind::Needle, Faction::Neutral, 6000.0);
                let s = &mut self.world.ships[i];
                s.tag = 5;
                s.aggressive = false;
                s.ai = Ai::Cruise;
                s.target = 0;
                s.speed = 0.0;
                s.want = 0.0;
                self.say("A Vael needle holds station nearby");
            }
            (5, 0) if here == st.sys[2] && !launched => {
                for k in 0..5 {
                    let kind = if k < 3 { Kind::Jackal } else { Kind::Hyena };
                    self.world.spawn_tagged(kind, 6, 7000.0 + 400.0 * k as f32);
                }
                self.warn("Syndicate raiders at the anchor");
            }
            (6, 0) if here == st.sys[2] && !launched => {
                let i = self.world.spawn_hostile_group_member(Kind::Brood, Faction::Pirate, 10000.0);
                let s = &mut self.world.ships[i];
                s.tag = 9;
                s.cargo = 14;
                s.energy = 900.0;
                s.energy_max = 900.0;
                s.shield_f = 260.0;
                s.shield_a = 260.0;
                s.shield_max = 260.0;
                for k in 0..4 {
                    self.world.spawn_tagged(Kind::Hyena, 7, 9000.0 + 500.0 * k as f32);
                }
                self.warn("The Cinder Sovereign");
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------ side contracts

    pub fn side_offers(&self) -> Vec<Mission> {
        let s = self.sys();
        let epoch = (self.cmdr.jumps / 3) as u64;
        let mut rng = Rng::new(s.seed ^ epoch.wrapping_mul(0x5851) ^ 0xC0FFEE);
        let me = self.cmdr.system as usize;
        let mut out = Vec::new();
        for k in 0..2u16 {
            let cands: Vec<usize> = (0..SYSTEMS).filter(|&j| j != me && self.gal.dist_ly(me, j) <= 7.0).collect();
            if cands.is_empty() {
                break;
            }
            let a = cands[rng.below(cands.len() as u32) as usize];
            let d = self.gal.dist_ly(me, a);
            let kind = if k == 0 { MISSION_LEDGER } else { MISSION_HUNT };
            let reward = if kind == MISSION_LEDGER { 250 + (d * 90.0) as u32 } else { 700 + (d * 120.0) as u32 };
            out.push(Mission { kind, stage: 0, gal: self.cmdr.galaxy, origin: me as u8, a: a as u8, b: 0, reward, progress: 0, seed: (k * 7 + epoch as u16) });
        }
        out
    }

    pub fn side_accept(&mut self, i: usize) {
        let offers = self.side_offers();
        let m = match offers.get(i) {
            Some(m) => m.clone(),
            None => return,
        };
        if self.cmdr.missions.len() >= 2 {
            self.warn("You can carry two contracts at a time");
            return;
        }
        if self.cmdr.missions.iter().any(|x| x.kind == m.kind && x.seed == m.seed && x.origin == m.origin) {
            self.warn("Already accepted");
            return;
        }
        if m.kind == MISSION_LEDGER {
            if self.cmdr.hold_free() < 1 {
                self.warn("No free hold slot for the parcel");
                return;
            }
            self.cmdr.sealed += 1;
        }
        self.cmdr.missions.push(m);
        self.say("Contract accepted");
    }

    fn side_spawn(&mut self) {
        let here = self.cmdr.system;
        let g = self.cmdr.galaxy;
        let hunts: Vec<u8> = self.cmdr.missions.iter().filter(|m| m.kind == MISSION_HUNT && m.stage == 0 && m.gal == g && m.a == here).map(|m| m.a).collect();
        for _ in hunts {
            self.world.spawn_tagged(Kind::Hyena, 11, 7000.0);
            self.warn("Your bounty target is here");
        }
    }

    // ------------------------------------------------------------------ trading and equipment

    pub fn buy(&mut self, i: usize, n: i32) {
        for _ in 0..n {
            if self.market.stock[i] <= 0 || self.cmdr.hold_free() <= 0 {
                break;
            }
            let price = self.market.price[i] as i64;
            if self.cmdr.credits < price {
                break;
            }
            self.market.buy(i);
            self.cmdr.credits -= price;
            self.cmdr.cargo[i] += 1;
        }
    }

    pub fn sell(&mut self, i: usize, n: i32) {
        for _ in 0..n {
            if self.cmdr.cargo[i] == 0 {
                break;
            }
            let p = self.market.sell(i) as i64;
            self.cmdr.credits += p;
            self.cmdr.cargo[i] -= 1;
        }
    }

    pub fn equipment_rows(&self) -> Vec<EqRow> {
        let tl = self.sys().tech;
        let mut rows = Vec::new();
        let cr = self.cmdr.credits;
        let need = (MAX_FUEL_TENTHS - self.cmdr.fuel).max(0);
        rows.push(EqRow {
            text: format!("Refuel ({} of {} tenths)", self.cmdr.fuel, MAX_FUEL_TENTHS),
            price: (need * FUEL_PRICE_PER_TENTH) as i64,
            status: if need == 0 { EqState::Done("full") } else if cr < (need * FUEL_PRICE_PER_TENTH) as i64 { EqState::Poor } else { EqState::Ok },
            act: EqAct::Fuel,
        });
        rows.push(EqRow {
            text: format!("Missile ({}/{})", self.cmdr.missiles, MISSILE_MAX),
            price: MISSILE_PRICE as i64,
            status: if tl < 2 { EqState::Locked(2) } else if self.cmdr.missiles >= MISSILE_MAX { EqState::Done("full") } else if cr < MISSILE_PRICE as i64 { EqState::Poor } else { EqState::Ok },
            act: EqAct::Missile,
        });
        for m in 0..4 {
            let cur = self.cmdr.lasers[m] as usize;
            let mut nxt = 0usize;
            for off in 1..=4 {
                let t = (cur + off - 1) % 4 + 1;
                if t != cur && LASER_TECH[t] <= tl {
                    nxt = t;
                    break;
                }
            }
            let (text, price, status) = if nxt == 0 {
                (format!("{} laser: {}", MOUNT_NAMES[m], LASER_NAMES[cur]), 0, EqState::Done("-"))
            } else {
                let price = (LASER_PRICE[nxt] - LASER_PRICE[cur] / 2) as i64;
                let broken = self.cmdr.damaged & (1 << (12 + m)) != 0;
                (
                    format!("{} laser: {} -> {}{}", MOUNT_NAMES[m], LASER_NAMES[cur], LASER_NAMES[nxt], if broken { " (damaged)" } else { "" }),
                    price,
                    if cr < price { EqState::Poor } else { EqState::Ok },
                )
            };
            rows.push(EqRow { text, price, status, act: EqAct::Laser(m as u8) });
        }
        let lvl = self.cmdr.hold_level as usize;
        rows.push(if lvl < 2 {
            EqRow {
                text: format!("Hold extension (+{} t)", HOLD_STEP),
                price: HOLD_PRICE[lvl] as i64,
                status: if tl < HOLD_TECH[lvl] { EqState::Locked(HOLD_TECH[lvl]) } else if cr < HOLD_PRICE[lvl] as i64 { EqState::Poor } else { EqState::Ok },
                act: EqAct::Hold,
            }
        } else {
            EqRow { text: String::from("Hold extension"), price: 0, status: EqState::Done("maxed"), act: EqAct::Hold }
        });
        for e in EQUIPMENT.iter() {
            let st = if self.cmdr.equip & e.flag != 0 {
                EqState::Done("fitted")
            } else if tl < e.min_tech {
                EqState::Locked(e.min_tech)
            } else if cr < e.price as i64 {
                EqState::Poor
            } else {
                EqState::Ok
            };
            rows.push(EqRow { text: String::from(e.name), price: e.price as i64, status: st, act: EqAct::Equip(e.flag) });
        }
        let repair = self.repair_cost();
        rows.push(EqRow {
            text: String::from("Repair all damaged systems"),
            price: repair,
            status: if repair == 0 { EqState::Done("none") } else if cr < repair { EqState::Poor } else { EqState::Ok },
            act: EqAct::Repair,
        });
        rows
    }

    pub fn repair_cost(&self) -> i64 {
        self.cmdr.damaged.count_ones() as i64 * 120
    }

    pub fn equip_act(&mut self, row: &EqRow) {
        if !matches!(row.status, EqState::Ok) {
            if let EqState::Locked(t) = row.status {
                let s = format!("Needs tech level {} (this system: {})", t, self.sys().tech);
                self.warn(&s);
            } else if matches!(row.status, EqState::Poor) {
                self.warn("Not enough credits");
            }
            return;
        }
        self.cmdr.credits -= row.price;
        match row.act {
            EqAct::Fuel => self.cmdr.fuel = MAX_FUEL_TENTHS,
            EqAct::Missile => self.cmdr.missiles += 1,
            EqAct::Laser(m) => {
                let m = m as usize;
                let cur = self.cmdr.lasers[m] as usize;
                let tl = self.sys().tech;
                for off in 1..=4 {
                    let t = (cur + off - 1) % 4 + 1;
                    if t != cur && LASER_TECH[t] <= tl {
                        self.cmdr.lasers[m] = t as u8;
                        break;
                    }
                }
                self.cmdr.damaged &= !(1 << (12 + m));
            }
            EqAct::Hold => self.cmdr.hold_level += 1,
            EqAct::Equip(f) => self.cmdr.equip |= f,
            EqAct::Repair => self.cmdr.damaged = 0,
        }
    }

    pub fn remove_laser(&mut self, m: usize) {
        let cur = self.cmdr.lasers[m] as usize;
        if cur != 0 {
            self.cmdr.credits += (LASER_PRICE[cur] / 2) as i64;
            self.cmdr.lasers[m] = 0;
        }
    }

    // ------------------------------------------------------------------ ending

    pub fn start_ending(&mut self) {
        self.cmdr.credits += story::chapter(6).reward;
        self.cmdr.story.chapter = CHAPTERS;
        self.cmdr.story.active = false;
        self.screen = Screen::Ending;
        self.ending_t = 0.0;
        self.page = 0;
        self.docked = true; // freeze the sim; the showcase takes over
        self.world.ships.retain(|x| matches!(x.fac, Faction::Civil | Faction::Police));
        self.world.bolts.clear();
        self.say("The Cinder Sovereign is destroyed");
    }

    pub fn save_to(&mut self, slot: usize) {
        if !self.docked {
            self.warn("You can only save while docked");
            return;
        }
        let data = self.cmdr.to_bytes();
        self.slots[slot] = Commander::from_bytes(&data);
        self.io.push(Io::WriteSlot { slot, data });
        self.save_msg = Some(format!("Saved to slot {}", slot + 1));
        let t = format!("Saved to slot {}", slot + 1);
        self.say(&t);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EqState {
    Ok,
    Poor,
    Locked(u8),
    Done(&'static str),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EqAct {
    Fuel,
    Missile,
    Laser(u8),
    Hold,
    Equip(u32),
    Repair,
}

#[derive(Clone)]
pub struct EqRow {
    pub text: String,
    pub price: i64,
    pub status: EqState,
    pub act: EqAct,
}
