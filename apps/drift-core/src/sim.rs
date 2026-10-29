// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Flight simulation: the player's ship, NPC ships and their AI, weapons, docking, effects.
use crate::commander::*;
use crate::econ::*;
use crate::galaxy::*;
use crate::math::*;
use crate::models::*;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub const DT: f32 = 1.0 / 30.0;
pub const PLAYER_ID: u32 = u32::MAX;
pub const PLAYER_MAX_SPEED: f32 = 360.0;
pub const JUMP_SPEED: f32 = 9000.0;
pub const PLAYER_RADIUS: f32 = 36.0;
pub const SCANNER_RANGE: f32 = 9000.0;
pub const DOCK_MAX_SPEED: f32 = 150.0;
/// Ship half extents used for the slot test (wing tip, canopy).
pub const SHIP_HALF_W: f32 = 54.0;
pub const SHIP_HALF_H: f32 = 15.0;
pub const SUN_DISTANCE: f32 = 220_000.0;
pub const SUN_RADIUS: f32 = 20_000.0;
const MAX_SHIPS: usize = 26;
const MAX_PARTICLES: usize = 700;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Faction {
    Civil,
    Pirate,
    Police,
    Hunter,
    Alien,
    Neutral,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Gull,
    Pelican,
    Jackal,
    Hyena,
    Warden,
    Hound,
    Needle,
    Husk,
    Brood,
    Rock,
    Splinter,
    Canister,
    Capsule,
    Missile,
}

pub struct Spec {
    pub name: &'static str,
    pub mesh: M,
    pub scale: f32,
    pub radius: f32,
    pub speed: f32,
    pub turn: f32,
    pub energy: f32,
    pub shield: f32,
    pub dmg: f32,
    pub interval: f32,
    pub bolt_speed: f32,
    pub missiles: u8,
    pub bounty: u32,
    pub fac: Faction,
}

pub fn spec(k: Kind) -> Spec {
    use Faction::*;
    let s = |name, mesh, radius, speed, turn, energy, shield, dmg, interval, missiles, bounty, fac| Spec {
        name,
        mesh,
        scale: 1.0,
        radius,
        speed,
        turn,
        energy,
        shield,
        dmg,
        interval,
        bolt_speed: 2500.0,
        missiles,
        bounty,
        fac,
    };
    match k {
        Kind::Gull => s("Gull", M::Gull, 44.0, 230.0, 1.0, 60.0, 20.0, 0.0, 9.0, 0, 0, Civil),
        Kind::Pelican => s("Pelican", M::Pelican, 130.0, 160.0, 0.5, 170.0, 60.0, 0.0, 9.0, 0, 0, Civil),
        Kind::Jackal => s("Jackal", M::Jackal, 40.0, 340.0, 2.2, 70.0, 40.0, 10.0, 0.45, 0, 110, Pirate),
        Kind::Hyena => s("Hyena", M::Hyena, 56.0, 290.0, 1.5, 150.0, 70.0, 14.0, 0.30, 1, 280, Pirate),
        Kind::Warden => s("Warden", M::Warden, 48.0, 380.0, 2.0, 130.0, 90.0, 14.0, 0.30, 1, 0, Police),
        Kind::Hound => s("Hound", M::Hound, 52.0, 360.0, 1.9, 120.0, 80.0, 16.0, 0.30, 2, 0, Hunter),
        Kind::Needle => s("Vael Needle", M::Needle, 38.0, 400.0, 2.8, 60.0, 20.0, 9.0, 0.22, 0, 150, Alien),
        Kind::Husk => s("Vael Husk", M::Husk, 44.0, 300.0, 2.0, 130.0, 40.0, 16.0, 0.50, 0, 260, Alien),
        Kind::Brood => s("Vael Brood-ship", M::Brood, 240.0, 150.0, 0.5, 1000.0, 320.0, 22.0, 0.45, 0, 5000, Alien),
        Kind::Rock => Spec { scale: 1.0, ..s("Rock", M::Rock0, 40.0, 0.0, 0.0, 120.0, 0.0, 0.0, 9.0, 0, 0, Neutral) },
        Kind::Splinter => Spec { scale: 0.4, ..s("Splinter", M::Rock1, 16.0, 0.0, 0.0, 25.0, 0.0, 0.0, 9.0, 0, 0, Neutral) },
        Kind::Canister => s("Canister", M::Canister, 16.0, 0.0, 0.0, 9.0, 0.0, 0.0, 9.0, 0, 0, Neutral),
        Kind::Capsule => s("Escape capsule", M::Capsule, 14.0, 0.0, 0.0, 9.0, 0.0, 0.0, 9.0, 0, 0, Neutral),
        Kind::Missile => s("Missile", M::Missile, 9.0, 520.0, 2.6, 1.0, 0.0, 0.0, 9.0, 0, 0, Neutral),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ai {
    Cruise,
    ToStation,
    Leave,
    Attack,
    Flee,
    Drift,
}

#[derive(Clone)]
pub struct Ship {
    pub id: u32,
    pub kind: Kind,
    pub fac: Faction,
    pub pos: V3,
    pub o: Orient,
    pub speed: f32,
    pub want: f32,
    pub energy: f32,
    pub energy_max: f32,
    pub shield_f: f32,
    pub shield_a: f32,
    pub shield_max: f32,
    pub flash: f32,
    pub ai: Ai,
    pub target: u32,
    pub timer: f32,
    pub evade: f32,
    pub cool: f32,
    pub missiles: u8,
    pub ecm: bool,
    pub cargo: i8,
    pub tag: u8,
    pub aggressive: bool,
    pub by_player: bool,
    pub provoked: bool,
    pub spin: V3,
    pub life: f32,
    pub age: f32,
    pub dead: bool,
    pub vel: V3,
    pub mesh_variant: u8,
}

#[derive(Clone)]
pub struct Bolt {
    pub pos: V3,
    pub vel: V3,
    pub life: f32,
    pub dmg: f32,
    pub owner: u32,
    pub owner_fac: Faction,
    pub col: u32,
    pub mining: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PKind {
    Spark,
    Fire,
    Debris,
    Trail,
    Flash,
}

#[derive(Clone)]
pub struct Particle {
    pub pos: V3,
    pub vel: V3,
    pub life: f32,
    pub max: f32,
    pub size: f32,
    pub col: u32,
    pub kind: PKind,
    pub o: Orient,
    pub spin: V3,
}

pub struct Station {
    pub pos: V3,
    pub base: Orient,
    pub spin: f32,
    pub spin_rate: f32,
}

impl Station {
    /// Station frame after rotation: f is the outward slot normal, r/u rotate with the station.
    pub fn frame(&self) -> Orient {
        let mut o = self.base;
        o.rotate_axis(self.base.f, self.spin);
        o
    }
}

pub enum Ev {
    Msg(String),
    Warn(String),
    Crime(i32),
    Kill { fac: Faction, kind: Kind, bounty: u32, tag: u8 },
    Scoop { item: i8, tag: u8 },
    FuelAdd(i32),
    Docked,
    Died(&'static str),
    Damaged(u32),
    Rescue(i64),
}

#[derive(Clone, Copy, Default)]
pub struct Controls {
    pub roll: f32,
    pub pitch: f32,
    pub throttle_up: bool,
    pub throttle_down: bool,
    pub fire: bool,
    pub missile: bool,
    pub lock: bool,
    pub unlock: bool,
    pub chaff: bool,
    pub jump: bool,
    pub dock_toggle: bool,
    pub view: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arrival {
    Launch,
    Hyper,
    Pocket,
}

pub struct Player {
    pub pos: V3,
    pub o: Orient,
    pub speed: f32,
    pub throttle: f32,
    pub roll_r: f32,
    pub pitch_r: f32,
    pub shield_f: f32,
    pub shield_a: f32,
    pub shield_max: f32,
    pub energy: f32,
    pub energy_max: f32,
    pub cabin: f32,
    pub laser_heat: [f32; 4],
    pub overheated: [bool; 4],
    pub fire_cd: f32,
    pub lock: u32,
    pub lock_t: f32,
    pub chaff_cd: f32,
    pub hit_flash: f32,
    pub hit_dir: V3,
    pub dockcomp: bool,
    pub jump_speed: f32,
    pub alive: bool,
    pub prev_pos: V3,
    pub missile_warn: bool,
    pub scooping: f32,
}

pub struct World {
    pub t: f32,
    pub rng: Rng,
    pub next_id: u32,
    pub ships: Vec<Ship>,
    pub bolts: Vec<Bolt>,
    pub parts: Vec<Particle>,
    pub events: Vec<Ev>,
    pub p: Player,
    pub has_planet: bool,
    pub planet_r: f32,
    pub planet_spin: f32,
    pub sun_pos: V3,
    pub sun_r: f32,
    pub station: Option<Station>,
    pub light_dir: V3,
    pub law: u8,
    pub heat: i32,
    pub eco: u8,
    pub spawn_timer: f32,
    pub pocket: bool,
    pub heat_acc: f32,
    pub station_hit_cd: f32,
    pub dock_phase: u8,
    pub dust: Vec<V3>,
    pub beacon: Option<V3>,
    pub contact_t: f32,
}

pub fn hostile(a: Faction, b: Faction) -> bool {
    use Faction::*;
    match (a, b) {
        (Pirate, Civil) | (Pirate, Police) | (Pirate, Hunter) => true,
        (Police, Pirate) | (Police, Alien) => true,
        (Hunter, Pirate) | (Hunter, Alien) => true,
        (Alien, x) => x != Alien && x != Neutral,
        (x, Alien) => x != Alien && x != Neutral,
        _ => false,
    }
}

fn seg_sphere(p0: V3, p1: V3, c: V3, r: f32) -> bool {
    let d = p1 - p0;
    let l2 = d.len2();
    let t = if l2 < 1e-6 { 0.0 } else { clamp((c - p0).dot(d) / l2, 0.0, 1.0) };
    (p0 + d * t - c).len2() <= r * r
}

/// Result of testing a ship against the docking slot.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DockTest {
    None,
    Docked,
    Crash { speed: f32 },
}

/// Pure docking geometry: did the ship pass through the slot plane between `prev` and `cur`?
/// `frame` is the station frame (f = outward normal, r/u = slot axes, rotating).
pub fn dock_test(spos: V3, frame: &Orient, prev: V3, cur: V3, ship: &Orient, speed: f32) -> DockTest {
    let zp = frame.to_local(prev - spos);
    let zc = frame.to_local(cur - spos);
    let plane = STATION_HALF_LEN;
    if !(zp.z >= plane && zc.z < plane) {
        return DockTest::None;
    }
    let t = (zp.z - plane) / (zp.z - zc.z);
    let hit = zp.lerp(zc, t);
    let sf = frame.to_local(ship.f);
    let sr = frame.to_local(ship.r);
    let su = frame.to_local(ship.u);
    if speed > DOCK_MAX_SPEED || sf.z > -0.93 {
        return DockTest::Crash { speed };
    }
    // wing tips and canopy corners projected into the slot plane
    for (a, b) in [(-1.0f32, -1.0f32), (-1.0, 1.0), (1.0, -1.0), (1.0, 1.0)] {
        let x = hit.x + sr.x * SHIP_HALF_W * a + su.x * SHIP_HALF_H * b;
        let y = hit.y + sr.y * SHIP_HALF_W * a + su.y * SHIP_HALF_H * b;
        if abs(x) > SLOT_HX || abs(y) > SLOT_HY {
            return DockTest::Crash { speed };
        }
    }
    DockTest::Docked
}

impl World {
    pub fn new(seed: u64) -> World {
        World {
            t: 0.0,
            rng: Rng::new(seed),
            next_id: 1,
            ships: Vec::new(),
            bolts: Vec::new(),
            parts: Vec::new(),
            events: Vec::new(),
            p: Player {
                pos: V3::ZERO,
                o: Orient::ID,
                speed: 0.0,
                throttle: 0.0,
                roll_r: 0.0,
                pitch_r: 0.0,
                shield_f: 100.0,
                shield_a: 100.0,
                shield_max: 100.0,
                energy: 400.0,
                energy_max: 400.0,
                cabin: 25.0,
                laser_heat: [0.0; 4],
                overheated: [false; 4],
                fire_cd: 0.0,
                lock: 0,
                lock_t: 0.0,
                chaff_cd: 0.0,
                hit_flash: 0.0,
                hit_dir: V3::ZERO,
                dockcomp: false,
                jump_speed: 0.0,
                alive: true,
                prev_pos: V3::ZERO,
                missile_warn: false,
                scooping: 0.0,
            },
            has_planet: true,
            planet_r: 6000.0,
            planet_spin: 0.0,
            sun_pos: v3(0.0, 0.0, SUN_DISTANCE),
            sun_r: SUN_RADIUS,
            station: None,
            light_dir: v3(0.0, 0.0, 1.0),
            law: 3,
            heat: 0,
            eco: 0,
            spawn_timer: 30.0,
            pocket: false,
            heat_acc: 0.0,
            station_hit_cd: 0.0,
            dock_phase: 0,
            dust: Vec::new(),
            beacon: None,
            contact_t: 0.0,
        }
    }

    pub fn emit(&mut self, e: Ev) {
        self.events.push(e);
    }
    pub fn msg(&mut self, s: &str) {
        self.events.push(Ev::Msg(String::from(s)));
    }

    pub fn station_frame(&self) -> Option<(V3, Orient)> {
        self.station.as_ref().map(|s| (s.pos, s.frame()))
    }

    // ------------------------------------------------------------------ setup

    pub fn add_ship(&mut self, kind: Kind, pos: V3, o: Orient, fac: Faction) -> usize {
        let sp = spec(kind);
        let id = self.next_id;
        self.next_id += 1;
        let sp_mult = if kind == Kind::Rock { 1.0 + self.rng.f() * 1.2 } else { 1.0 };
        let _ = sp_mult;
        let s = Ship {
            id,
            kind,
            fac,
            pos,
            o,
            speed: 0.0,
            want: sp.speed * 0.6,
            energy: sp.energy,
            energy_max: sp.energy,
            shield_f: sp.shield,
            shield_a: sp.shield,
            shield_max: sp.shield,
            flash: 0.0,
            ai: Ai::Cruise,
            target: 0,
            timer: 0.0,
            evade: 0.0,
            cool: self.rng.fr(0.5, 2.0),
            missiles: sp.missiles,
            ecm: kind == Kind::Hound,
            cargo: -1,
            tag: 0,
            aggressive: false,
            by_player: false,
            provoked: false,
            spin: V3::ZERO,
            life: 0.0,
            age: 0.0,
            dead: false,
            vel: V3::ZERO,
            mesh_variant: self.rng.below(3) as u8,
        };
        self.ships.push(s);
        self.ships.len() - 1
    }

    pub fn setup(&mut self, sys: &SystemInfo, mode: Arrival, cmdr: &Commander) {
        let mut rng = Rng::new(sys.seed ^ 0x57A7);
        self.ships.clear();
        self.bolts.clear();
        self.parts.clear();
        self.events.clear();
        self.law = sys.law();
        self.eco = sys.economy;
        self.heat = cmdr.heat;
        self.pocket = mode == Arrival::Pocket;
        self.has_planet = !self.pocket;
        self.planet_r = 4500.0 + sys.radius_km as f32 * 0.6;
        let sundir = rng.unit();
        self.sun_pos = if self.pocket { sundir * (SUN_DISTANCE * 4.0) } else { sundir * SUN_DISTANCE };
        self.sun_r = SUN_RADIUS;
        self.light_dir = sundir;
        self.p.dockcomp = false;
        self.p.jump_speed = 0.0;
        self.p.lock = 0;
        self.p.lock_t = 0.0;
        self.p.alive = true;
        self.p.cabin = 25.0;
        self.p.laser_heat = [0.0; 4];
        self.p.overheated = [false; 4];
        self.apply_loadout(cmdr, true);
        self.dust.clear();
        for _ in 0..90 {
            self.dust.push(v3(self.rng.fr(-1.0, 1.0), self.rng.fr(-1.0, 1.0), self.rng.fr(-1.0, 1.0)) * 1200.0);
        }
        self.station = None;
        self.beacon = None;
        self.contact_t = 0.0;
        if !self.pocket {
            let dir = loop {
                let d = rng.unit();
                if abs(d.dot(sundir)) < 0.9 {
                    break d;
                }
            };
            let axis = dir; // slot faces away from the planet
            let up_hint = if abs(axis.y) < 0.9 { v3(0.0, 1.0, 0.0) } else { v3(1.0, 0.0, 0.0) };
            self.station = Some(Station {
                pos: dir * (self.planet_r + 5200.0),
                base: Orient::look(axis, up_hint),
                spin: rng.fr(0.0, TAU),
                spin_rate: 0.32,
            });
        }
        match mode {
            Arrival::Launch => {
                let (sp, fr) = self.station_frame().unwrap();
                self.p.pos = sp + fr.f * (STATION_HALF_LEN + 130.0);
                self.p.o = fr;
                self.p.speed = 40.0;
                self.p.throttle = 0.15;
            }
            Arrival::Hyper => {
                let d = loop {
                    let d = rng.unit();
                    if d.dot(sundir) > -0.6 {
                        break d;
                    }
                };
                self.p.pos = d * 70_000.0;
                self.p.o = Orient::look(-d, v3(0.0, 1.0, 0.0));
                self.p.speed = 200.0;
                self.p.throttle = 0.55;
            }
            Arrival::Pocket => {
                self.p.pos = V3::ZERO;
                self.p.o = Orient::ID;
                self.p.speed = 150.0;
                self.p.throttle = 0.4;
            }
        }
        self.p.prev_pos = self.p.pos;
        self.p.roll_r = 0.0;
        self.p.pitch_r = 0.0;
        // initial traffic
        if mode == Arrival::Pocket {
            let n = 3 + self.rng.below(3) as usize;
            for i in 0..n {
                let k = if i == 0 { Kind::Husk } else { Kind::Needle };
                self.spawn_hostile_group_member(k, Faction::Alien, 4000.0 + 500.0 * i as f32);
            }
            return;
        }
        let pop_factor = (sys.pop as f32 / 120.0).min(1.5);
        let n_traders = 1 + (rng.f() * (2.0 + 2.0 * pop_factor)) as usize;
        for _ in 0..n_traders {
            self.spawn_trader(&mut rng, mode == Arrival::Launch);
        }
        // police around the station
        let n_police = match sys.law() {
            0 => 0,
            1 | 2 => 1,
            3 | 4 => 2,
            _ => 3,
        };
        for _ in 0..n_police {
            self.spawn_police();
        }
        if mode == Arrival::Hyper {
            // pirates and the occasional alien on the way in
            let pr = 0.55 - sys.law() as f32 * 0.06;
            if rng.chance(pr) {
                let n = 1 + rng.below(2) as usize;
                for _ in 0..n {
                    let k = if rng.chance(0.3) { Kind::Hyena } else { Kind::Jackal };
                    self.spawn_hostile_group_member(k, Faction::Pirate, 7000.0 + rng.fr(0.0, 4000.0));
                }
            }
            if rng.chance(0.08) {
                self.spawn_hostile_group_member(Kind::Needle, Faction::Alien, 9000.0);
            }
            if cmdr.heat >= FUGITIVE_HEAT && rng.chance(0.6) {
                self.spawn_hostile_group_member(Kind::Hound, Faction::Hunter, 8000.0);
            }
            if rng.chance(0.25) {
                self.spawn_rocks(5000.0);
            }
        }
    }

    pub fn apply_loadout(&mut self, cmdr: &Commander, full: bool) {
        self.p.shield_max = if cmdr.has(EQ_SHIELD) { 150.0 } else { 100.0 };
        if full {
            self.p.shield_f = self.p.shield_max;
            self.p.shield_a = self.p.shield_max;
        }
        self.p.energy_max = 400.0;
        if full {
            self.p.energy = self.p.energy_max;
        }
    }

    fn rand_dir(&mut self) -> V3 {
        self.rng.unit()
    }

    pub fn spawn_trader(&mut self, rng: &mut Rng, near_station: bool) {
        if self.ships.len() >= MAX_SHIPS {
            return;
        }
        let kind = if rng.chance(0.3) { Kind::Pelican } else { Kind::Gull };
        let (sp, fr) = match self.station_frame() {
            Some(x) => x,
            None => return,
        };
        let outside = sp + fr.f * rng.fr(3000.0, 9000.0) + rng.unit() * 1500.0;
        let pos = if near_station { outside } else { self.p.pos + rng.unit() * rng.fr(9000.0, 14000.0) };
        let leave = rng.chance(0.45);
        let o = Orient::look(if leave { fr.f } else { (sp - pos).norm() }, v3(0.0, 1.0, 0.0));
        let i = self.add_ship(kind, pos, o, Faction::Civil);
        let s = &mut self.ships[i];
        s.ai = if leave { Ai::Leave } else { Ai::ToStation };
        s.speed = spec(kind).speed * 0.6;
        s.timer = rng.fr(40.0, 100.0);
        s.cargo = rng.below(13) as i8;
    }

    pub fn spawn_police(&mut self) {
        if self.ships.len() >= MAX_SHIPS {
            return;
        }
        let (sp, fr) = match self.station_frame() {
            Some(x) => x,
            None => return,
        };
        let pos = sp + fr.f * self.rng.fr(1500.0, 3500.0) + self.rand_dir() * 900.0;
        let o = Orient::look(self.rand_dir(), v3(0.0, 1.0, 0.0));
        let i = self.add_ship(Kind::Warden, pos, o, Faction::Police);
        self.ships[i].speed = 150.0;
    }

    pub fn spawn_hostile_group_member(&mut self, kind: Kind, fac: Faction, dist: f32) -> usize {
        let d = self.rng.unit();
        let pos = self.p.pos + d * dist + self.rng.unit() * 600.0;
        let o = Orient::look(self.p.pos - pos, v3(0.0, 1.0, 0.0));
        let i = self.add_ship(kind, pos, o, fac);
        let s = &mut self.ships[i];
        s.aggressive = true;
        s.ai = Ai::Attack;
        s.target = PLAYER_ID;
        s.speed = spec(kind).speed * 0.5;
        if fac == Faction::Pirate {
            s.cargo = self.rng.below(16) as i8;
        }
        i
    }

    pub fn spawn_rocks(&mut self, dist: f32) {
        let center = self.p.pos + self.rng.unit() * dist;
        let n = 4 + self.rng.below(5);
        for _ in 0..n {
            let pos = center + self.rng.unit() * 1500.0;
            let o = Orient::look(self.rng.unit(), v3(0.0, 1.0, 0.0));
            let rk = if self.rng.chance(0.3) { Kind::Splinter } else { Kind::Rock };
            let i = self.add_ship(rk, pos, o, Faction::Neutral);
            let spin = self.rng.unit() * self.rng.fr(0.1, 0.5);
            let drift = self.rng.unit() * self.rng.fr(0.0, 12.0);
            let s = &mut self.ships[i];
            s.spin = spin;
            s.vel = drift;
            s.mesh_variant = (self.rng.below(3)) as u8;
            s.ai = Ai::Drift;
            if s.kind == Kind::Rock {
                s.energy = 90.0 + 60.0 * s.mesh_variant as f32;
                s.energy_max = s.energy;
            }
        }
    }

    pub fn spawn_canister(&mut self, pos: V3, item: i8, tag: u8) {
        let o = Orient::look(self.rng.unit(), v3(0.0, 1.0, 0.0));
        let i = self.add_ship(Kind::Canister, pos, o, Faction::Neutral);
        let spin = self.rng.unit() * self.rng.fr(0.3, 1.2);
        let vel = self.rng.unit() * self.rng.fr(5.0, 30.0);
        let s = &mut self.ships[i];
        s.cargo = item;
        s.tag = tag;
        s.spin = spin;
        s.vel = vel;
        s.ai = Ai::Drift;
        s.life = 240.0;
    }

    /// Spawn a mission-tagged ship at a distance in front of the player.
    pub fn spawn_tagged(&mut self, kind: Kind, tag: u8, dist: f32) {
        let fac = spec(kind).fac;
        let i = self.spawn_hostile_group_member(kind, fac, dist);
        self.ships[i].tag = tag;
    }

    // ------------------------------------------------------------------ queries

    pub fn mass_locked(&self) -> bool {
        if self.has_planet && self.p.pos.len() - self.planet_r < 3500.0 {
            return true;
        }
        if !self.pocket && (self.p.pos - self.sun_pos).len() - self.sun_r < 7000.0 {
            return true;
        }
        if let Some(s) = &self.station {
            if (self.p.pos - s.pos).len() < 6500.0 {
                return true;
            }
        }
        for s in &self.ships {
            if matches!(s.kind, Kind::Canister | Kind::Capsule | Kind::Missile | Kind::Splinter) {
                continue;
            }
            if (s.pos - self.p.pos).len() < 3000.0 {
                return true;
            }
        }
        false
    }

    pub fn altitude(&self) -> f32 {
        if self.has_planet {
            (self.p.pos.len() - self.planet_r).max(0.0)
        } else {
            0.0
        }
    }

    pub fn find(&self, id: u32) -> Option<&Ship> {
        self.ships.iter().find(|s| s.id == id && !s.dead)
    }

    fn target_info(&self, id: u32) -> Option<(V3, V3, f32)> {
        if id == PLAYER_ID {
            if !self.p.alive {
                return None;
            }
            return Some((self.p.pos, self.p.o.f * self.p.speed.max(self.p.jump_speed.min(400.0)), PLAYER_RADIUS));
        }
        self.find(id).map(|s| (s.pos, s.o.f * s.speed + s.vel, spec(s.kind).radius))
    }

    fn wanted_by(&self, fac: Faction) -> bool {
        match fac {
            Faction::Police => self.heat >= OFFENDER_HEAT && (self.law >= 3 || self.heat >= FUGITIVE_HEAT),
            Faction::Hunter => self.heat >= FUGITIVE_HEAT,
            _ => false,
        }
    }

    fn find_target(&self, s: &Ship) -> u32 {
        let mut best = 0;
        let mut bd = match s.fac {
            Faction::Police => 14000.0f32,
            _ => 12000.0,
        };
        // the player
        let player_hostile = match s.fac {
            Faction::Pirate | Faction::Alien => s.aggressive || s.fac == Faction::Alien,
            Faction::Police | Faction::Hunter => self.wanted_by(s.fac),
            _ => false,
        };
        if player_hostile && self.p.alive {
            let d = (self.p.pos - s.pos).len();
            if d < bd {
                bd = d * 0.8;
                best = PLAYER_ID;
            }
        }
        for o in &self.ships {
            if o.dead || o.id == s.id || !hostile(s.fac, o.fac) {
                continue;
            }
            if o.kind == Kind::Missile {
                continue;
            }
            let d = (o.pos - s.pos).len();
            if d < bd {
                bd = d;
                best = o.id;
            }
        }
        best
    }

    // ------------------------------------------------------------------ damage

    pub fn explosion(&mut self, pos: V3, size: f32, debris: usize) {
        if self.parts.len() > MAX_PARTICLES - 80 {
            self.parts.drain(0..80);
        }
        self.parts.push(Particle { pos, vel: V3::ZERO, life: 0.9, max: 0.9, size: size * 2.6, col: 0xFFB050, kind: PKind::Fire, o: Orient::ID, spin: V3::ZERO });
        self.parts.push(Particle { pos, vel: V3::ZERO, life: 0.35, max: 0.35, size: size * 3.4, col: 0xFFFFFF, kind: PKind::Flash, o: Orient::ID, spin: V3::ZERO });
        for _ in 0..28 {
            let d = self.rng.unit();
            let sp = self.rng.fr(0.5, 1.0) * size * 4.0;
            let life = self.rng.fr(0.5, 1.4);
            let col = if self.rng.chance(0.5) { 0xFFD080 } else { 0xFF7030 };
            self.parts.push(Particle { pos, vel: d * sp, life, max: life, size: size * 0.12, col, kind: PKind::Spark, o: Orient::ID, spin: V3::ZERO });
        }
        for _ in 0..debris {
            let d = self.rng.unit();
            let sp = self.rng.fr(0.2, 0.9) * size * 2.2;
            let life = self.rng.fr(1.5, 3.2);
            let o = Orient::look(self.rng.unit(), v3(0.0, 1.0, 0.0));
            let spin = self.rng.unit() * self.rng.fr(1.0, 5.0);
            let sz = size * self.rng.fr(0.08, 0.2);
            self.parts.push(Particle { pos: pos + d * size * 0.3, vel: d * sp, life, max: life, size: sz, col: 0, kind: PKind::Debris, o, spin });
        }
    }

    fn spark_burst(&mut self, pos: V3, n: usize, col: u32, speed: f32) {
        for _ in 0..n {
            let d = self.rng.unit();
            let life = self.rng.fr(0.2, 0.5);
            self.parts.push(Particle { pos, vel: d * self.rng.fr(0.3, 1.0) * speed, life, max: life, size: 3.0, col, kind: PKind::Spark, o: Orient::ID, spin: V3::ZERO });
        }
    }

    /// Apply damage to NPC `idx`. `from` is the world position of the attacker.
    pub fn damage_ship(&mut self, idx: usize, amount: f32, from: V3, by_player: bool, mining: bool) {
        let (died, kind, was_civil, pos, r) = {
            let s = &mut self.ships[idx];
            if s.dead {
                return;
            }
            let mut dmg = amount;
            if matches!(s.kind, Kind::Rock | Kind::Splinter) {
                dmg *= if mining { 6.0 } else { 0.6 };
            } else if mining {
                dmg *= 0.3;
            }
            let front = (from - s.pos).dot(s.o.f) > 0.0;
            let sh = if front { &mut s.shield_f } else { &mut s.shield_a };
            if *sh > 0.0 {
                let a = dmg.min(*sh);
                *sh -= a;
                dmg -= a;
                s.flash = 1.0;
            }
            if dmg > 0.0 {
                s.energy -= dmg;
            }
            if by_player {
                s.by_player = true;
                s.provoked = true;
            }
            (s.energy <= 0.0, s.kind, s.fac == Faction::Civil, s.pos, spec(s.kind).radius)
        };
        if self.ships[idx].flash > 0.0 && !died {
            let dir = (from - pos).norm();
            self.parts.push(Particle { pos: pos + dir * r * 0.9, vel: V3::ZERO, life: 0.25, max: 0.25, size: r * 0.9, col: 0x7FB8FF, kind: PKind::Flash, o: Orient::ID, spin: V3::ZERO });
        }
        if by_player && was_civil && !died {
            if !self.ships[idx].provoked || self.ships[idx].age >= 0.0 {
                self.ships[idx].ai = Ai::Flee;
                self.ships[idx].timer = 30.0;
            }
            self.events.push(Ev::Crime(1));
        }
        if died {
            self.destroy_ship(idx, by_player, mining);
        } else if self.ships[idx].fac != Faction::Neutral && self.ships[idx].energy < self.ships[idx].energy_max * 0.3 && self.ships[idx].fac != Faction::Alien && self.ships[idx].fac != Faction::Police {
            if self.ships[idx].ai != Ai::Flee {
                self.ships[idx].ai = Ai::Flee;
                self.ships[idx].timer = 25.0;
            }
        }
        let _ = kind;
    }

    pub fn destroy_ship(&mut self, idx: usize, by_player: bool, mining: bool) {
        let s = self.ships[idx].clone();
        if s.dead {
            return;
        }
        self.ships[idx].dead = true;
        let sp = spec(s.kind);
        match s.kind {
            Kind::Rock => {
                self.explosion(s.pos, sp.radius * 0.6, 4);
                let n = 2 + self.rng.below(2);
                for _ in 0..n {
                    let pos = s.pos + self.rng.unit() * 30.0;
                    let lo = Orient::look(self.rng.unit(), v3(0.0, 1.0, 0.0));
                    let i = self.add_ship(Kind::Splinter, pos, lo, Faction::Neutral);
                    let spin = self.rng.unit() * 0.6;
                    let vel = s.vel + self.rng.unit() * 40.0;
                    let t = &mut self.ships[i];
                    t.spin = spin;
                    t.vel = vel;
                    t.ai = Ai::Drift;
                }
                if mining || self.rng.chance(0.15) {
                    let item = match self.rng.below(5) {
                        0 | 1 => 2,
                        2 => 11,
                        3 => 10,
                        _ => 6,
                    };
                    self.spawn_canister(s.pos, item, 0);
                }
            }
            Kind::Splinter => {
                self.explosion(s.pos, 20.0, 2);
                if mining && self.rng.chance(0.6) {
                    let item = if self.rng.chance(0.6) { 2 } else { 11 };
                    self.spawn_canister(s.pos, item, 0);
                }
            }
            Kind::Canister | Kind::Capsule => {
                self.explosion(s.pos, 16.0, 0);
            }
            Kind::Missile => {
                self.explosion(s.pos, 30.0, 0);
            }
            _ => {
                let size = sp.radius * 1.4;
                self.explosion(s.pos, size, if sp.radius > 100.0 { 22 } else { 12 });
                if sp.radius > 100.0 {
                    for k in 0..4 {
                        let off = s.o.f * (k as f32 - 1.5) * 90.0;
                        self.explosion(s.pos + off, size * 0.5, 4);
                    }
                }
                // loot
                if matches!(s.fac, Faction::Pirate | Faction::Civil | Faction::Hunter) {
                    let drops = if s.fac == Faction::Pirate { 1 + self.rng.below(3) } else { self.rng.below(2) };
                    for _ in 0..drops {
                        let item = if s.cargo >= 0 && self.rng.chance(0.7) { s.cargo } else { self.rng.below(16) as i8 };
                        let off = self.rng.unit() * 40.0;
                        self.spawn_canister(s.pos + off, item, 0);
                    }
                }
                if s.kind != Kind::Needle && s.kind != Kind::Husk && s.kind != Kind::Brood && self.rng.chance(0.3) && s.fac != Faction::Police {
                    let lo = Orient::look(self.rng.unit(), v3(0.0, 1.0, 0.0));
                    let i = self.add_ship(Kind::Capsule, s.pos, lo, Faction::Neutral);
                    let vel = self.rng.unit() * 30.0;
                    let t = &mut self.ships[i];
                    t.vel = vel;
                    t.ai = Ai::Drift;
                    t.life = 150.0;
                }
                if s.kind == Kind::Brood {
                    for k in 0..6 {
                        let item = if k % 2 == 0 { 14 } else { self.rng.below(16) as i8 };
                        let off = self.rng.unit() * 200.0;
                        self.spawn_canister(s.pos + off, item, 0);
                    }
                }
                if by_player {
                    self.events.push(Ev::Kill { fac: s.fac, kind: s.kind, bounty: sp.bounty, tag: s.tag });
                    if s.fac == Faction::Civil {
                        self.events.push(Ev::Crime(14));
                    } else if s.fac == Faction::Police {
                        self.events.push(Ev::Crime(40));
                    }
                }
            }
        }
        // missiles chasing it lose their target automatically (checked each tick)
    }

    pub fn damage_player(&mut self, amount: f32, from: V3) {
        if !self.p.alive {
            return;
        }
        let local = self.p.o.to_local((from - self.p.pos).norm());
        self.p.hit_dir = local;
        let front = local.z > 0.0;
        let mut dmg = amount;
        let sh = if front { &mut self.p.shield_f } else { &mut self.p.shield_a };
        if *sh > 0.0 {
            let a = dmg.min(*sh);
            *sh -= a;
            dmg -= a;
        }
        self.p.hit_flash = 1.0;
        if dmg > 0.0 {
            self.p.energy -= dmg;
            if self.rng.chance(0.06 + dmg * 0.002) {
                let which = if self.rng.chance(0.3) { 1u32 << (12 + self.rng.below(4)) } else { 1u32 << self.rng.below(10) };
                self.events.push(Ev::Damaged(which));
            }
        }
        if self.p.energy <= 0.0 {
            self.p.energy = 0.0;
            self.kill_player("Your ship was destroyed.");
        }
    }

    pub fn kill_player(&mut self, why: &'static str) {
        if !self.p.alive {
            return;
        }
        self.p.alive = false;
        let pos = self.p.pos;
        self.explosion(pos, 60.0, 14);
        self.events.push(Ev::Died(why));
    }

    // ------------------------------------------------------------------ weapons

    fn fire_bolt(&mut self, pos: V3, dir: V3, speed: f32, dmg: f32, owner: u32, fac: Faction, col: u32, life: f32, mining: bool, base_vel: V3) {
        self.bolts.push(Bolt { pos, vel: dir * speed + base_vel * 0.0, life, dmg, owner, owner_fac: fac, col, mining });
    }

    fn launch_missile(&mut self, pos: V3, o: Orient, speed: f32, fac: Faction, target: u32, by_player: bool) {
        let i = self.add_ship(Kind::Missile, pos + o.f * 40.0, o, Faction::Neutral);
        let s = &mut self.ships[i];
        s.speed = speed + 60.0;
        s.ai = Ai::Attack;
        s.target = target;
        s.life = 14.0;
        s.by_player = by_player;
        s.tag = match fac {
            Faction::Pirate => 1,
            Faction::Police => 2,
            Faction::Hunter => 3,
            Faction::Alien => 4,
            _ => 0,
        };
    }

    fn player_fire(&mut self, view: u8, cmdr: &Commander) {
        let lt = cmdr.lasers[view as usize & 3];
        if lt == LASER_NONE || self.p.overheated[view as usize & 3] || self.p.fire_cd > 0.0 {
            return;
        }
        if cmdr.damaged & (1 << (view as u32 + 12)) != 0 {
            return;
        }
        let (cd, dmg, speed, life, heat, col, mining) = match lt {
            LASER_PULSE => (0.30, 16.0, 2800.0, 1.1, 9.0, 0x7FE0FF, false),
            LASER_BEAM => (0.12, 12.0, 4200.0, 0.9, 5.5, 0x9FFFE0, false),
            LASER_MILITARY => (0.16, 28.0, 5500.0, 1.0, 7.5, 0xFFE070, false),
            _ => (0.18, 5.0, 2200.0, 0.45, 3.0, 0x60FF70, true),
        };
        self.p.fire_cd = cd;
        let o = self.p.o;
        let dir = match view & 3 {
            0 => o.f,
            1 => -o.f,
            2 => -o.r,
            _ => o.r,
        };
        let side = match view & 3 {
            0 | 1 => o.r,
            _ => o.f,
        };
        let down = -o.u * 8.0;
        let flip = if self.p.fire_cd > 0.0 && (self.t * 10.0) as i32 % 2 == 0 { 1.0 } else { -1.0 };
        let pos = self.p.pos + dir * 30.0 + side * (flip * 18.0) + down;
        self.fire_bolt(pos, dir, speed, dmg, PLAYER_ID, Faction::Neutral, col, life, mining, V3::ZERO);
        let h = if cmdr.has(EQ_HEATSINK) { heat * 0.8 } else { heat };
        let v = view as usize & 3;
        self.p.laser_heat[v] += h;
        if self.p.laser_heat[v] >= 100.0 {
            self.p.laser_heat[v] = 100.0;
            self.p.overheated[v] = true;
            self.events.push(Ev::Warn(String::from("Laser overheated")));
        }
    }

    // ------------------------------------------------------------------ main step

    pub fn step(&mut self, ctl: &Controls, cmdr: &Commander) {
        let dt = DT;
        self.t += dt;
        self.heat = cmdr.heat;
        self.planet_spin += dt * 0.01;
        if let Some(s) = self.station.as_mut() {
            s.spin += s.spin_rate * dt;
        }
        if self.station_hit_cd > 0.0 {
            self.station_hit_cd -= dt;
        }
        self.update_player(ctl, cmdr, dt);
        self.update_ships(cmdr, dt);
        self.update_bolts(dt);
        self.update_particles(dt);
        self.ships.retain(|s| !s.dead);
        self.spawn_logic(dt);
    }

    fn update_player(&mut self, ctl: &Controls, cmdr: &Commander, dt: f32) {
        if !self.p.alive {
            self.p.speed = 0.0;
            return;
        }
        self.p.prev_pos = self.p.pos;
        // autopilot toggle
        if ctl.dock_toggle {
            if cmdr.has(EQ_DOCKCOMP) && self.station.is_some() {
                self.p.dockcomp = !self.p.dockcomp;
                self.events.push(Ev::Msg(String::from(if self.p.dockcomp { "Docking computer engaged" } else { "Docking computer off" })));
            } else if self.p.dockcomp {
                self.p.dockcomp = false;
            } else if cmdr.equip & EQ_DOCKCOMP == 0 {
                self.events.push(Ev::Warn(String::from("No docking computer fitted")));
            } else {
                self.events.push(Ev::Warn(String::from("Docking computer is damaged")));
            }
        }
        let manual = ctl.roll != 0.0 || ctl.pitch != 0.0;
        if self.p.dockcomp && manual {
            self.p.dockcomp = false;
            self.events.push(Ev::Msg(String::from("Docking computer off")));
        }
        if self.p.dockcomp {
            self.autopilot(dt);
        } else {
            // rate smoothing
            let ramp = |cur: f32, tgt: f32| -> f32 {
                let k = if tgt == 0.0 { 7.0 } else { 5.0 };
                let d = tgt - cur;
                cur + clamp(d, -k * dt, k * dt)
            };
            self.p.roll_r = ramp(self.p.roll_r, ctl.roll);
            self.p.pitch_r = ramp(self.p.pitch_r, ctl.pitch);
            self.p.o.roll(self.p.roll_r * 1.9 * dt);
            self.p.o.pitch(self.p.pitch_r * 1.25 * dt);
            if ctl.throttle_up {
                self.p.throttle = min(1.0, self.p.throttle + 0.7 * dt);
            }
            if ctl.throttle_down {
                self.p.throttle = max(0.0, self.p.throttle - 1.1 * dt);
            }
            let tgt = self.p.throttle * PLAYER_MAX_SPEED;
            let a = if tgt > self.p.speed { 240.0 } else { 320.0 };
            self.p.speed += clamp(tgt - self.p.speed, -a * dt, a * dt);
        }
        self.p.o.orthonormalize();
        // in-system jump
        let locked = self.mass_locked();
        if ctl.jump && !locked && !self.pocket && !self.p.dockcomp {
            self.p.jump_speed = min(JUMP_SPEED, self.p.jump_speed + 7000.0 * dt);
        } else {
            if ctl.jump && locked && self.p.jump_speed == 0.0 && fract(self.t) < dt {
                self.events.push(Ev::Warn(String::from("Mass lock: jump drive offline")));
            }
            self.p.jump_speed = max(0.0, self.p.jump_speed - 30000.0 * dt);
        }
        if locked && self.p.jump_speed > 400.0 {
            self.p.jump_speed = 0.0;
        }
        let eff = self.p.speed.max(self.p.jump_speed);
        let f = self.p.o.f;
        self.p.pos += f * (eff * dt);
        // timers
        self.p.fire_cd = max(0.0, self.p.fire_cd - dt);
        self.p.chaff_cd = max(0.0, self.p.chaff_cd - dt);
        self.p.hit_flash = max(0.0, self.p.hit_flash - dt * 2.5);
        self.p.scooping = max(0.0, self.p.scooping - dt);
        let cool = if cmdr.has(EQ_HEATSINK) { 20.0 } else { 11.0 };
        for i in 0..4 {
            self.p.laser_heat[i] = max(0.0, self.p.laser_heat[i] - cool * dt);
            if self.p.overheated[i] && self.p.laser_heat[i] < 60.0 {
                self.p.overheated[i] = false;
            }
        }
        // energy and shields
        let (er, sr) = if cmdr.has(EQ_ENERGY) { (3.0, 5.0) } else { (1.4, 2.6) };
        if self.p.energy < self.p.energy_max {
            self.p.energy = min(self.p.energy_max, self.p.energy + er * dt);
        }
        if self.p.energy > self.p.energy_max * 0.2 {
            if self.p.shield_f < self.p.shield_max {
                self.p.shield_f = min(self.p.shield_max, self.p.shield_f + sr * dt);
            }
            if self.p.shield_a < self.p.shield_max {
                self.p.shield_a = min(self.p.shield_max, self.p.shield_a + sr * dt);
            }
        }
        // weapons
        if ctl.fire {
            self.player_fire(ctl.view, cmdr);
        }
        self.update_lock(ctl, cmdr, dt);
        if ctl.chaff {
            if cmdr.has(EQ_CHAFF) && self.p.chaff_cd <= 0.0 && self.p.energy > 40.0 {
                self.p.chaff_cd = 6.0;
                self.p.energy -= 25.0;
                let mut n = 0;
                let pp = self.p.pos;
                let mut kill: Vec<usize> = Vec::new();
                for (i, s) in self.ships.iter().enumerate() {
                    if s.kind == Kind::Missile && s.target == PLAYER_ID && (s.pos - pp).len() < 5000.0 {
                        kill.push(i);
                    }
                }
                for i in kill {
                    if self.rng.chance(0.85) {
                        self.ships[i].dead = true;
                        let pos = self.ships[i].pos;
                        self.explosion(pos, 26.0, 0);
                        n += 1;
                    }
                }
                self.spark_burst(pp + self.p.o.f * -60.0, 30, 0xC0E0FF, 220.0);
                self.events.push(Ev::Msg(if n > 0 { format!("Chaff released: {} missile(s) neutralised", n) } else { String::from("Chaff released") }));
            } else if !cmdr.has(EQ_CHAFF) {
                self.events.push(Ev::Warn(String::from("No countermeasure pod")));
            }
        }
        // collisions with the environment
        self.environment(cmdr, dt);
        self.update_dust(dt);
    }

    fn update_dust(&mut self, dt: f32) {
        let move_v = -(self.p.o.f * self.p.speed.max(self.p.jump_speed)) * dt;
        let _ = move_v;
        let rel = self.p.pos - self.p.prev_pos;
        for d in self.dust.iter_mut() {
            *d = *d - rel;
            // wrap into the box
            for c in [&mut d.x, &mut d.y, &mut d.z] {
                if *c > 1200.0 {
                    *c -= 2400.0;
                } else if *c < -1200.0 {
                    *c += 2400.0;
                }
            }
        }
    }

    fn update_lock(&mut self, ctl: &Controls, cmdr: &Commander, dt: f32) {
        let view_dir = match ctl.view & 3 {
            0 => self.p.o.f,
            1 => -self.p.o.f,
            2 => -self.p.o.r,
            _ => self.p.o.r,
        };
        if ctl.unlock {
            self.p.lock = 0;
            self.p.lock_t = 0.0;
        }
        if self.p.lock != 0 {
            match self.find(self.p.lock) {
                Some(s) => {
                    if (s.pos - self.p.pos).len() > 12000.0 {
                        self.p.lock = 0;
                        self.p.lock_t = 0.0;
                    }
                }
                None => {
                    self.p.lock = 0;
                    self.p.lock_t = 0.0;
                }
            }
        }
        if ctl.lock {
            // pick the contact nearest to the view axis
            let mut best = 0;
            let mut bc = 0.93;
            for s in &self.ships {
                if matches!(s.kind, Kind::Canister | Kind::Capsule | Kind::Missile | Kind::Splinter) || s.dead {
                    continue;
                }
                let d = s.pos - self.p.pos;
                let l = d.len();
                if l > 9000.0 || l < 50.0 {
                    continue;
                }
                let c = d.dot(view_dir) / l;
                if c > bc {
                    bc = c;
                    best = s.id;
                }
            }
            if best != 0 {
                self.p.lock = best;
                self.p.lock_t = 0.0;
                self.events.push(Ev::Msg(String::from("Target acquired")));
            } else {
                self.events.push(Ev::Warn(String::from("No target in view")));
            }
        }
        if self.p.lock != 0 && self.p.lock_t < 1.0 {
            self.p.lock_t += dt;
            if self.p.lock_t >= 1.0 {
                self.events.push(Ev::Msg(String::from("Missile lock")));
            }
        }
        if ctl.missile {
            if cmdr.missiles == 0 {
                self.events.push(Ev::Warn(String::from("No missiles")));
            } else if self.p.lock == 0 {
                self.events.push(Ev::Warn(String::from("Lock a target first (T)")));
            } else if self.p.lock_t < 1.0 {
                self.events.push(Ev::Warn(String::from("Lock not ready")));
            } else {
                let tgt = self.p.lock;
                let o = self.p.o;
                let pos = self.p.pos;
                let sp = self.p.speed;
                self.launch_missile(pos, o, sp, Faction::Neutral, tgt, true);
                self.events.push(Ev::Msg(String::from("Missile away")));
                self.events.push(Ev::Damaged(0xFFFF_FFFF)); // sentinel: consume one missile
            }
        }
    }

    fn autopilot(&mut self, dt: f32) {
        let (spos, fr) = match self.station_frame() {
            Some(x) => x,
            None => {
                self.p.dockcomp = false;
                return;
            }
        };
        let rel = self.p.pos - spos;
        let loc = fr.to_local(rel);
        let mouth = STATION_HALF_LEN;
        // aim point: on the axis, in front of the slot, closing in as alignment improves
        let lateral = (loc.x * loc.x + loc.y * loc.y).sqrt_();
        let ahead = loc.z - mouth;
        let aim_local = if loc.z < mouth - 10.0 {
            v3(0.0, 0.0, -400.0) // already inside the plane
        } else if lateral < 70.0 && ahead < 700.0 {
            v3(0.0, 0.0, mouth - 120.0)
        } else {
            let z = (mouth + 260.0 + lateral * 1.4).min(loc.z.max(mouth + 260.0));
            let z = if lateral > 160.0 { mouth + 420.0 + lateral.min(2200.0) * 0.5 } else { z };
            v3(0.0, 0.0, z)
        };
        let aim_world = spos + fr.to_world(aim_local);
        let dir = (aim_world - self.p.pos).norm();
        let dist = (aim_world - self.p.pos).len();
        // turn: when close and aligned, point along -axis
        let final_leg = ahead < 1300.0 && lateral < 260.0 && ahead > -50.0;
        let want_dir = if final_leg {
            let lat_vec = fr.r * loc.x + fr.u * loc.y;
            (-fr.f * 80.0 - lat_vec * 1.5).norm()
        } else {
            dir
        };
        let turn = 1.7 * dt;
        self.p.o.turn_towards(want_dir, turn);
        // roll: match the slot axis (up to 180 degrees, either sign works)
        let sr = fr.to_local(self.p.o.r);
        let ang = atan2(sr.y, sr.x);
        let mut err = ang;
        if err > PI / 2.0 {
            err -= PI;
        } else if err < -PI / 2.0 {
            err += PI;
        }
        // rotate about the ship's forward axis; positive roll lowers the right wing
        let step = clamp(err, -1.2 * dt, 1.2 * dt);
        // sign: slot-plane angle increases anticlockwise as seen along the axis; roll() lowers the right wing
        self.p.o.roll(step * if self.p.o.f.dot(fr.f) < 0.0 { -1.0 } else { 1.0 });
        let speed = if final_leg && ahead < 800.0 { 75.0 } else if final_leg { 110.0 } else { clamp(dist / 4.0, 70.0, 330.0) };
        let aligned = self.p.o.f.dot(want_dir) > 0.94;
        let want = if aligned { speed } else { speed.min(110.0) };
        self.p.speed += clamp(want - self.p.speed, -300.0 * dt, 200.0 * dt);
        self.p.throttle = self.p.speed / PLAYER_MAX_SPEED;
        self.p.roll_r = 0.0;
        self.p.pitch_r = 0.0;
    }

    fn environment(&mut self, cmdr: &Commander, dt: f32) {
        let pp = self.p.pos;
        // planet
        if self.has_planet {
            let d = pp.len();
            if d < self.planet_r + 10.0 {
                self.kill_player("You flew into the planet.");
            }
        }
        // sun: heat and scoop
        if !self.pocket {
            let d = (pp - self.sun_pos).len();
            let near = d / self.sun_r;
            if near < 1.0 {
                self.kill_player("You flew into the star.");
            }
            let target = clamp((1.9 - near) * 160.0, 0.0, 140.0);
            let ambient = if self.p.cabin < 25.0 { 25.0 } else { 0.0 };
            let _ = ambient;
            if target > self.p.cabin {
                self.p.cabin += (target - self.p.cabin) * 1.2 * dt;
            } else {
                self.p.cabin = max(25.0, self.p.cabin - 6.0 * dt);
            }
            if near < 1.35 && cmdr.has(EQ_SCOOP) && self.p.cabin < 100.0 {
                self.events.push(Ev::FuelAdd(0));
            }
        } else {
            self.p.cabin = max(25.0, self.p.cabin - 6.0 * dt);
        }
        if self.p.cabin > 90.0 {
            self.p.energy -= (self.p.cabin - 90.0) * 1.2 * dt;
            if self.p.energy <= 0.0 {
                self.p.energy = 0.0;
                self.kill_player("The cabin overheated.");
            }
        }
        // station body and slot
        if let Some((spos, fr)) = self.station_frame() {
            let ploc = fr.to_local(pp - spos);
            let prev = fr.to_local(self.p.prev_pos - spos);
            let _ = prev;
            match dock_test(spos, &fr, self.p.prev_pos, pp, &self.p.o, self.p.speed) {
                DockTest::Docked => {
                    self.events.push(Ev::Docked);
                    return;
                }
                DockTest::Crash { speed } => {
                    self.bounce_off_station(spos, &fr, speed);
                }
                DockTest::None => {}
            }
            // hull box: octagon approximated by a box (half width 480) with the front frame
            let half = 470.0;
            let r = PLAYER_RADIUS;
            if abs(ploc.x) < half + r && abs(ploc.y) < half + r && ploc.z > -STATION_HALF_LEN - r && ploc.z < STATION_HALF_LEN + r {
                let in_slot_corridor = abs(ploc.x) < SLOT_HX && abs(ploc.y) < SLOT_HY && ploc.z > STATION_HALF_LEN - 60.0;
                let inside_hull = abs(ploc.x) < half && abs(ploc.y) < half && ploc.z < STATION_HALF_LEN && ploc.z > -STATION_HALF_LEN;
                if !in_slot_corridor && (inside_hull || self.hull_overlap(&ploc, r, half)) {
                    let sp = self.p.speed;
                    self.bounce_off_station(spos, &fr, sp);
                }
            }
            if self.p.dockcomp && (pp - spos).len() < 700.0 && false {
                self.p.dockcomp = false;
            }
        }
        // ships and loot
        let pp = self.p.pos;
        let tether = cmdr.has(EQ_TETHER);
        let scoop = cmdr.has(EQ_SCOOP) || tether;
        let mut hits: Vec<(usize, f32)> = Vec::new();
        let mut scoops: Vec<usize> = Vec::new();
        for (i, s) in self.ships.iter_mut().enumerate() {
            if s.dead {
                continue;
            }
            let d = s.pos - pp;
            let dl = d.len();
            let sr = spec(s.kind).radius;
            match s.kind {
                Kind::Canister | Kind::Capsule => {
                    if tether && dl < 900.0 && dl > 5.0 {
                        let pull = -d * (1.0 / dl) * 160.0;
                        s.vel = s.vel * 0.96 + pull * 0.04 * 3.0;
                    }
                    if dl < 70.0 && scoop {
                        scoops.push(i);
                    } else if dl < 50.0 {
                        // bump without a scoop
                        s.vel = s.vel + d * (1.0 / dl.max(1.0)) * 40.0;
                    }
                }
                Kind::Missile => {}
                _ => {
                    if dl < sr + PLAYER_RADIUS {
                        hits.push((i, 0.0));
                    }
                }
            }
        }
        for i in scoops {
            let item = self.ships[i].cargo;
            let tag = self.ships[i].tag;
            let kind = self.ships[i].kind;
            let full = kind == Kind::Canister && cmdr.hold_free() <= 0;
            if full {
                if self.p.scooping <= 0.0 {
                    self.events.push(Ev::Warn(String::from("Hold full")));
                    self.p.scooping = 2.0;
                }
                continue;
            }
            self.ships[i].dead = true;
            if kind == Kind::Capsule {
                let reward = 100 + self.rng.below(300) as i64;
                self.events.push(Ev::Rescue(reward));
            } else {
                self.events.push(Ev::Scoop { item, tag });
            }
        }
        for (i, _) in hits {
            let rel_v = (self.ships[i].o.f * self.ships[i].speed + self.ships[i].vel) - self.p.o.f * self.p.speed;
            let dmg = (rel_v.len() * 0.12).max(6.0);
            let pos = self.ships[i].pos;
            let dir = (self.p.pos - pos).norm();
            self.damage_player(dmg, pos);
            self.damage_ship(i, dmg, self.p.pos, true, false);
            self.p.pos = pos + dir * (spec(self.ships[i].kind).radius + PLAYER_RADIUS + 1.0);
            self.p.speed *= 0.5;
        }
    }

    fn hull_overlap(&self, loc: &V3, r: f32, half: f32) -> bool {
        // sphere against box
        let cx = clamp(loc.x, -half, half);
        let cy = clamp(loc.y, -half, half);
        let cz = clamp(loc.z, -STATION_HALF_LEN, STATION_HALF_LEN);
        let d = v3(loc.x - cx, loc.y - cy, loc.z - cz);
        d.len2() < r * r && !(abs(loc.x) < SLOT_HX && abs(loc.y) < SLOT_HY && loc.z > STATION_HALF_LEN - 60.0)
    }

    fn bounce_off_station(&mut self, spos: V3, fr: &Orient, speed: f32) {
        // push the ship out along the shortest way and hurt it
        let loc = fr.to_local(self.p.pos - spos);
        let half = 470.0 + PLAYER_RADIUS + 2.0;
        let mut out = loc;
        let pen_x = half - abs(loc.x);
        let pen_y = half - abs(loc.y);
        let pen_zp = STATION_HALF_LEN + PLAYER_RADIUS + 2.0 - loc.z;
        let pen_zn = loc.z + STATION_HALF_LEN + PLAYER_RADIUS + 2.0;
        let m = pen_x.min(pen_y).min(pen_zp).min(pen_zn);
        if m == pen_zp || loc.z > STATION_HALF_LEN - 80.0 {
            out.z = STATION_HALF_LEN + PLAYER_RADIUS + 2.0;
        } else if m == pen_zn {
            out.z = -STATION_HALF_LEN - PLAYER_RADIUS - 2.0;
        } else if m == pen_x {
            out.x = if loc.x >= 0.0 { half } else { -half };
        } else {
            out.y = if loc.y >= 0.0 { half } else { -half };
        }
        self.p.pos = spos + fr.to_world(out);
        let dmg = 8.0 + speed * 0.28;
        let from = self.p.pos + (self.p.pos - spos).norm() * 100.0;
        self.damage_player(dmg, from);
        self.p.speed = (self.p.speed * 0.2).min(40.0);
        self.p.throttle = self.p.speed / PLAYER_MAX_SPEED;
        self.p.dockcomp = false;
        let pos = self.p.pos;
        self.spark_burst(pos, 14, 0xFFD090, 200.0);
        self.events.push(Ev::Warn(String::from("Hull collision")));
    }

    // ------------------------------------------------------------------ NPC ships

    fn update_ships(&mut self, cmdr: &Commander, dt: f32) {
        let n = self.ships.len();
        let mut launches: Vec<(V3, Orient, f32, Faction, u32)> = Vec::new();
        let mut shots: Vec<(V3, V3, f32, f32, u32, Faction, u32)> = Vec::new();
        self.p.missile_warn = false;
        for i in 0..n {
            if self.ships[i].dead {
                continue;
            }
            let mut s = self.ships[i].clone();
            s.age += dt;
            s.flash = max(0.0, s.flash - dt * 2.0);
            if s.life > 0.0 {
                s.life -= dt;
                if s.life <= 0.0 {
                    s.dead = true;
                    if s.kind == Kind::Missile {
                        self.ships[i] = s;
                        let pos = self.ships[i].pos;
                        self.explosion(pos, 18.0, 0);
                        continue;
                    }
                }
            }
            // shield regen
            if s.shield_max > 0.0 {
                s.shield_f = min(s.shield_max, s.shield_f + 1.4 * dt);
                s.shield_a = min(s.shield_max, s.shield_a + 1.4 * dt);
            }
            match s.kind {
                Kind::Rock | Kind::Splinter | Kind::Canister | Kind::Capsule => {
                    s.pos += s.vel * dt;
                    if s.spin.len2() > 0.0 {
                        let ax = s.spin.norm();
                        s.o.rotate_axis(ax, s.spin.len() * dt);
                        s.o.orthonormalize();
                    }
                    // clean up far-away loot
                    if (s.pos - self.p.pos).len() > 40000.0 {
                        s.dead = true;
                    }
                }
                Kind::Missile => {
                    self.missile_step(&mut s, cmdr, dt);
                }
                _ => {
                    self.ai_step(&mut s, dt, &mut launches, &mut shots);
                }
            }
            // engine trail
            if !s.dead && s.speed > 40.0 && !matches!(s.kind, Kind::Rock | Kind::Splinter | Kind::Canister | Kind::Capsule) {
                let d = (s.pos - self.p.pos).len2();
                if d < 6000.0 * 6000.0 && self.parts.len() < MAX_PARTICLES - 100 && (s.age * 30.0) as i32 % 2 == 0 {
                    let sp = spec(s.kind);
                    let mesh_engine = s.pos - s.o.f * sp.radius * 0.9;
                    let life = if s.kind == Kind::Missile { 0.8 } else { 0.45 };
                    let col = match s.fac {
                        Faction::Alien => 0x40FFC0,
                        _ => if s.kind == Kind::Missile { 0xFFE0A0 } else { 0xFFA050 },
                    };
                    self.parts.push(Particle { pos: mesh_engine, vel: s.o.f * -20.0, life, max: life, size: sp.radius * 0.18 + 2.0, col, kind: PKind::Trail, o: Orient::ID, spin: V3::ZERO });
                }
            }
            self.ships[i] = s;
        }
        // deferred actions
        for (pos, o, speed, fac, target) in launches {
            self.launch_missile(pos, o, speed, fac, target, false);
        }
        for (pos, dir, speed, dmg, owner, fac, _) in shots {
            let col = match fac {
                Faction::Pirate => 0xFF5030,
                Faction::Police => 0x60A0FF,
                Faction::Hunter => 0xFFC040,
                Faction::Alien => 0x60FFB0,
                _ => 0xFFFFFF,
            };
            self.fire_bolt(pos, dir, speed, dmg, owner, fac, col, 1.4, false, V3::ZERO);
        }
        // ship-ship collisions for large things are ignored; separate overlapping NPCs lightly
    }

    fn missile_step(&mut self, s: &mut Ship, _cmdr: &Commander, dt: f32) {
        let info = self.target_info(s.target);
        let (tpos, tvel, tr) = match info {
            Some(x) => x,
            None => {
                // lost target: self-destruct
                s.dead = true;
                let p = s.pos;
                self.explosion(p, 16.0, 0);
                return;
            }
        };
        if s.target == PLAYER_ID {
            self.p.missile_warn = true;
        }
        let to = tpos - s.pos;
        let dist = to.len();
        let t_lead = (dist / 600.0).min(1.5);
        let aim = tpos + tvel * t_lead * 0.6;
        s.o.turn_towards(aim - s.pos, 2.6 * dt);
        s.speed = min(560.0, s.speed + 150.0 * dt);
        s.pos += s.o.f * s.speed * dt;
        if s.age > 0.4 && dist < tr + 22.0 {
            s.dead = true;
            let pos = s.pos;
            self.explosion(pos, 40.0, 3);
            if s.target == PLAYER_ID {
                self.damage_player(120.0, pos);
            } else if let Some(idx) = self.ships.iter().position(|o| o.id == s.target) {
                if idx < self.ships.len() {
                    self.damage_ship(idx, 130.0, pos, s.by_player, false);
                }
            }
        }
        // missile ecm defence for NPCs
        if s.target != PLAYER_ID && s.age > 0.3 {
            if let Some(idx) = self.ships.iter().position(|o| o.id == s.target) {
                let t = &mut self.ships[idx];
                if t.ecm && dist < 1800.0 {
                    t.ecm = false;
                    s.dead = true;
                    let pos = s.pos;
                    self.explosion(pos, 22.0, 0);
                    self.msg("A missile was jammed");
                }
            }
        }
    }

    fn ai_step(&mut self, s: &mut Ship, dt: f32, launches: &mut Vec<(V3, Orient, f32, Faction, u32)>, shots: &mut Vec<(V3, V3, f32, f32, u32, Faction, u32)>) {
        let sp = spec(s.kind);
        s.cool = max(0.0, s.cool - dt);
        s.timer -= dt;
        s.evade = max(0.0, s.evade - dt);
        let combat = matches!(s.fac, Faction::Pirate | Faction::Police | Faction::Hunter | Faction::Alien);
        // acquire / validate target
        if combat && s.ai != Ai::Flee {
            let valid = self.target_info(s.target).is_some() && (s.target != PLAYER_ID || self.player_valid_target(s));
            if !valid {
                s.target = 0;
            }
            if s.target == 0 && (s.age * 30.0) as i32 % 20 == 0 {
                s.target = self.find_target(s);
            }
            if s.target != 0 {
                if s.ai != Ai::Attack {
                    s.ai = Ai::Attack;
                }
            } else if s.ai == Ai::Attack {
                s.ai = Ai::Cruise;
            }
        }
        match s.ai {
            Ai::Attack => {
                let (tpos, tvel, tr) = match self.target_info(s.target) {
                    Some(x) => x,
                    None => {
                        s.ai = Ai::Cruise;
                        s.target = 0;
                        return;
                    }
                };
                let to = tpos - s.pos;
                let dist = to.len();
                let t_lead = dist / sp.bolt_speed;
                let aim = tpos + tvel * t_lead - s.o.f * s.speed * 0.0;
                let mut dir = (aim - s.pos).norm();
                if s.evade > 0.0 {
                    let jink = s.o.r * (if (s.id & 1) == 0 { 1.0 } else { -1.0 }) + s.o.u * 0.4;
                    dir = (s.o.f * 0.6 + jink).norm();
                } else if dist < tr + sp.radius + 260.0 {
                    s.evade = self.rng.fr(1.0, 2.2);
                }
                s.o.turn_towards(dir, sp.turn * dt);
                let ang_cos = s.o.f.dot((aim - s.pos).norm());
                s.want = if dist > 800.0 { sp.speed } else if ang_cos > 0.9 { (tvel.len() * 0.9).max(sp.speed * 0.5) } else { sp.speed * 0.8 };
                if s.evade > 0.0 {
                    s.want = sp.speed;
                }
                if sp.dmg > 0.0 && ang_cos > 0.995 && dist < 2600.0 && s.cool <= 0.0 {
                    s.cool = sp.interval * self.rng.fr(0.9, 1.5);
                    // fire with a little spread
                    let spread = s.o.f + self.rng.unit() * 0.012;
                    shots.push((s.pos + s.o.f * sp.radius, spread.norm(), sp.bolt_speed, sp.dmg, s.id, s.fac, s.target));
                }
                if s.missiles > 0 && dist > 900.0 && dist < 6500.0 && ang_cos > 0.97 && self.rng.chance(0.012) {
                    s.missiles -= 1;
                    launches.push((s.pos, s.o, s.speed, s.fac, s.target));
                }
            }
            Ai::Flee => {
                let away = if s.fac == Faction::Civil && self.station.is_some() {
                    let sp_ = self.station.as_ref().unwrap().pos;
                    // civilians run for the station when it is near, else away from the player
                    if (sp_ - s.pos).len() < 12000.0 { (sp_ - s.pos).norm() } else { (s.pos - self.p.pos).norm() }
                } else {
                    (s.pos - self.p.pos).norm()
                };
                let dir = (away + s.o.r * 0.15 * sin(self.t * 2.0 + s.id as f32)).norm();
                s.o.turn_towards(dir, sp.turn * dt);
                s.want = sp.speed * 1.05;
                if s.timer <= 0.0 {
                    // jump away
                    s.dead = true;
                    let pos = s.pos;
                    self.parts.push(Particle { pos, vel: V3::ZERO, life: 0.4, max: 0.4, size: sp.radius * 3.0, col: 0xA0C8FF, kind: PKind::Flash, o: Orient::ID, spin: V3::ZERO });
                }
            }
            Ai::ToStation | Ai::Leave | Ai::Cruise => {
                match (s.ai, self.station_frame()) {
                    (Ai::ToStation, Some((spos, fr))) => {
                        let mouth = spos + fr.f * (STATION_HALF_LEN + 300.0);
                        let dist_m = (mouth - s.pos).len();
                        let tgt = if (s.pos - spos).len() > 2500.0 { spos + fr.f * 1800.0 } else { mouth };
                        s.o.turn_towards(tgt - s.pos, sp.turn * dt);
                        s.want = if dist_m < 700.0 { 70.0 } else { sp.speed * 0.7 };
                        if (s.pos - spos).len() < STATION_HALF_LEN + 80.0 {
                            s.dead = true; // docked
                        }
                    }
                    (Ai::Leave, Some((_, _))) => {
                        s.want = sp.speed * 0.8;
                        if s.timer <= 0.0 && (s.pos - self.p.pos).len() > 7000.0 {
                            s.dead = true;
                        }
                    }
                    (Ai::Cruise, Some((spos, fr))) if s.fac == Faction::Police => {
                        // patrol: orbit the station at a distance
                        let a = self.t * 0.15 + s.id as f32;
                        let patrol = spos + fr.f * 2200.0 + fr.r * (cos(a) * 2600.0) + fr.u * (sin(a) * 2600.0);
                        s.o.turn_towards(patrol - s.pos, sp.turn * dt * 0.6);
                        s.want = sp.speed * 0.45;
                    }
                    _ => {
                        s.want = sp.speed * 0.5;
                    }
                }
                if s.ai == Ai::Leave && s.timer < 0.0 {
                    s.timer = 5.0;
                }
            }
            Ai::Drift => {}
        }
        // speed and movement
        let a = 200.0;
        s.speed += clamp(s.want - s.speed, -a * dt, a * dt);
        s.pos += s.o.f * s.speed * dt;
        if s.kind == Kind::Brood {
            // the brood-ship launches needles now and then
            if s.ai == Ai::Attack && self.rng.chance(0.002) && self.ships.len() < MAX_SHIPS {
                let pos = s.pos + s.o.f * 150.0;
                let i = self.add_ship(Kind::Needle, pos, s.o, Faction::Alien);
                self.ships[i].aggressive = true;
                self.ships[i].speed = 300.0;
                let tgt = s.target;
                self.ships[i].target = tgt;
                self.ships[i].ai = Ai::Attack;
            }
        }
    }

    fn player_valid_target(&self, s: &Ship) -> bool {
        match s.fac {
            Faction::Police | Faction::Hunter => self.wanted_by(s.fac),
            _ => self.p.alive,
        }
    }

    // ------------------------------------------------------------------ bolts and particles

    fn update_bolts(&mut self, dt: f32) {
        let mut i = 0;
        while i < self.bolts.len() {
            let mut b = self.bolts[i].clone();
            let p0 = b.pos;
            b.pos += b.vel * dt;
            b.life -= dt;
            let mut hit = false;
            if b.life <= 0.0 {
                hit = true;
            } else {
                // player
                if b.owner != PLAYER_ID && self.p.alive && seg_sphere(p0, b.pos, self.p.pos, PLAYER_RADIUS + 6.0) {
                    let from = p0;
                    self.damage_player(b.dmg, from);
                    hit = true;
                } else {
                    for j in 0..self.ships.len() {
                        let s = &self.ships[j];
                        if s.dead || s.id == b.owner || matches!(s.kind, Kind::Canister | Kind::Capsule) {
                            continue;
                        }
                        if s.kind == Kind::Missile && b.owner != PLAYER_ID {
                            continue;
                        }
                        // friendly fire between same faction is skipped
                        if b.owner != PLAYER_ID && s.fac == b.owner_fac && s.fac != Faction::Neutral {
                            continue;
                        }
                        let r = spec(s.kind).radius * if matches!(s.kind, Kind::Rock | Kind::Splinter) { 0.9 * spec_scale(s) } else { 0.85 };
                        if seg_sphere(p0, b.pos, s.pos, r) {
                            let by_player = b.owner == PLAYER_ID;
                            self.damage_ship(j, b.dmg, p0, by_player, b.mining);
                            hit = true;
                            break;
                        }
                    }
                    if !hit {
                        if let Some((spos, fr)) = self.station_frame() {
                            let a = fr.to_local(p0 - spos);
                            let c = fr.to_local(b.pos - spos);
                            let in_box = |l: V3| abs(l.x) < 480.0 && abs(l.y) < 480.0 && abs(l.z) < STATION_HALF_LEN;
                            if in_box(c) && !in_box(a) {
                                hit = true;
                                if b.owner == PLAYER_ID && self.station_hit_cd <= 0.0 {
                                    self.station_hit_cd = 3.0;
                                    self.events.push(Ev::Crime(5));
                                    self.events.push(Ev::Warn(String::from("Do not fire on the station")));
                                }
                            }
                        }
                    }
                }
            }
            if hit {
                let pos = b.pos;
                if b.life > 0.0 {
                    self.spark_burst(pos, 5, b.col, 140.0);
                }
                self.bolts.swap_remove(i);
            } else {
                self.bolts[i] = b;
                i += 1;
            }
        }
    }

    fn update_particles(&mut self, dt: f32) {
        let mut i = 0;
        while i < self.parts.len() {
            let p = &mut self.parts[i];
            p.life -= dt;
            if p.life <= 0.0 {
                self.parts.swap_remove(i);
                continue;
            }
            p.pos += p.vel * dt;
            if p.kind == PKind::Debris {
                let l = p.spin.len();
                if l > 0.0 {
                    let ax = p.spin * (1.0 / l);
                    p.o.rotate_axis(ax, l * dt);
                }
            } else if p.kind == PKind::Spark {
                p.vel = p.vel * (1.0 - 1.5 * dt);
            }
            i += 1;
        }
    }

    // ------------------------------------------------------------------ random encounters

    fn spawn_logic(&mut self, dt: f32) {
        if self.pocket || !self.p.alive {
            return;
        }
        self.spawn_timer -= dt;
        if self.spawn_timer > 0.0 {
            return;
        }
        self.spawn_timer = self.rng.fr(25.0, 60.0);
        if self.ships.len() >= MAX_SHIPS - 4 {
            return;
        }
        if let Some(s) = &self.station {
            if (self.p.pos - s.pos).len() < 4000.0 {
                return;
            }
        }
        let law = self.law as f32;
        let r = self.rng.f();
        if r < 0.30 - law * 0.02 {
            let n = 1 + self.rng.below(2) as usize;
            for _ in 0..n {
                let k = if self.rng.chance(0.3) { Kind::Hyena } else { Kind::Jackal };
                self.spawn_hostile_group_member(k, Faction::Pirate, 8000.0);
            }
            self.msg("Contacts on the scanner");
        } else if r < 0.55 {
            let mut rng = Rng::new(self.rng.next_u64());
            self.spawn_trader(&mut rng, false);
        } else if r < 0.62 {
            self.spawn_rocks(7000.0);
        } else if r < 0.66 && self.heat >= FUGITIVE_HEAT {
            self.spawn_hostile_group_member(Kind::Hound, Faction::Hunter, 8000.0);
        } else if r < 0.70 && self.heat >= OFFENDER_HEAT {
            self.spawn_police();
        } else if r < 0.72 {
            self.spawn_hostile_group_member(Kind::Needle, Faction::Alien, 9000.0);
        }
    }
}

fn spec_scale(s: &Ship) -> f32 {
    match s.kind {
        Kind::Rock => 1.0,
        _ => 1.0,
    }
}

trait SqrtExt {
    fn sqrt_(self) -> f32;
}
impl SqrtExt for f32 {
    fn sqrt_(self) -> f32 {
        sqrt(self)
    }
}
