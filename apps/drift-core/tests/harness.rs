// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Host harness: scripted input for N frames, screenshots (PPM) and gameplay checks.
mod common;
use drift_core::commander::*;
use drift_core::econ::*;
use drift_core::game::*;
use drift_core::gfx::*;
use drift_core::math::*;
use drift_core::sim::*;

struct H {
    g: Game,
    c: Canvas,
}

impl H {
    fn new(w: usize, h: usize) -> H {
        H { g: Game::new(1234), c: Canvas::new(w, h) }
    }
    fn frames(&mut self, n: usize) {
        for _ in 0..n {
            self.g.update(1.0 / 30.0);
        }
    }
    fn tap(&mut self, a: Act) {
        self.g.input.key(a, true);
        self.g.update(1.0 / 30.0);
        self.g.input.key(a, false);
        self.g.update(1.0 / 30.0);
    }
    fn hold(&mut self, a: Act, frames: usize) {
        self.g.input.key(a, true);
        self.frames(frames);
        self.g.input.key(a, false);
        self.g.update(1.0 / 30.0);
    }
    fn shot(&mut self, name: &str) {
        self.g.render(&mut self.c);
        common::save_ppm(name, self.c.w, self.c.h, &self.c.px);
    }
    fn new_game_to_dock(&mut self) {
        self.tap(Act::Enter); // title
        self.tap(Act::Enter); // New Game
        assert_eq!(self.g.screen, Screen::Intro);
        for _ in 0..6 {
            self.tap(Act::Enter);
        }
        assert_eq!(self.g.screen, Screen::Briefing);
        self.tap(Act::Enter);
        assert_eq!(self.g.screen, Screen::Status);
    }
}

#[test]
fn menus_and_story_screens() {
    let mut h = H::new(1280, 720);
    h.frames(30);
    h.shot("01_title");
    h.tap(Act::Enter);
    assert_eq!(h.g.screen, Screen::MainMenu);
    h.frames(10);
    h.shot("02_main_menu");
    h.tap(Act::Down);
    h.tap(Act::Down);
    h.tap(Act::Down);
    h.tap(Act::Enter);
    assert_eq!(h.g.screen, Screen::Settings);
    h.shot("03_settings");
    h.tap(Act::Back);
    h.tap(Act::Enter); // new game
    assert_eq!(h.g.screen, Screen::Intro);
    h.frames(40);
    h.shot("04_intro");
    for _ in 0..6 {
        h.tap(Act::Enter);
    }
    assert_eq!(h.g.screen, Screen::Briefing);
    h.shot("05_briefing_ch0");
    h.tap(Act::Enter);
    assert_eq!(h.g.screen, Screen::Status);
    h.shot("06_status");
    // chapter 1 offer
    h.g.cmdr.story.chapter = 1;
    h.g.cmdr.story.active = false;
    h.tap(Act::F11);
    assert_eq!(h.g.screen, Screen::Contracts);
    h.shot("07_contracts");
    h.tap(Act::Enter);
    assert_eq!(h.g.screen, Screen::Briefing);
    assert!(h.g.cmdr.story.active && h.g.cmdr.sealed == 1);
    h.shot("08_story_briefing_ch1");
    h.tap(Act::Enter);
    h.tap(Act::F9);
    h.frames(2);
    h.shot("09_market");
    h.tap(Act::F10);
    h.shot("10_equipment");
    h.tap(Act::F6);
    h.tap(Act::Right);
    h.shot("11_galaxy_chart");
    h.tap(Act::F7);
    h.shot("12_local_chart");
    h.tap(Act::F8);
    h.shot("13_system_data");
    h.tap(Act::Help);
    h.shot("14_controls");
}

#[test]
fn launch_fly_beacon_and_autodock() {
    let mut h = H::new(1280, 720);
    h.new_game_to_dock();
    assert!(h.g.cmdr.story.active && h.g.cmdr.story.chapter == 0);
    h.tap(Act::F1);
    assert_eq!(h.g.screen, Screen::Flight);
    assert!(!h.g.docked);
    assert!(h.g.world.beacon.is_some());
    h.hold(Act::Faster, 30);
    h.frames(30);
    h.shot("20_launch_flight");
    // steer: roll and pitch a bit, view switching
    h.hold(Act::Right, 15);
    h.hold(Act::Down, 15);
    h.shot("21_flight_maneuver");
    // beacon: teleport next to it
    let b = h.g.world.beacon.unwrap();
    h.g.world.p.pos = b + v3(100.0, 0.0, 0.0);
    h.frames(3);
    assert_eq!(h.g.cmdr.story.stage, 1, "beacon reached");
    // docking computer flies the approach
    h.g.cmdr.equip |= EQ_DOCKCOMP;
    let (sp, fr) = h.g.world.station_frame().unwrap();
    h.g.world.p.pos = sp + fr.f * 3200.0 + fr.r * 900.0 + fr.u * (-500.0);
    h.g.world.p.o = Orient::look(v3(0.3, 0.8, 0.2), v3(0.0, 1.0, 0.0));
    h.g.world.p.speed = 100.0;
    h.tap(Act::Dock);
    assert!(h.g.world.p.dockcomp);
    let mut shot_taken = false;
    for i in 0..3600 {
        h.g.update(1.0 / 30.0);
        if i == 300 && !shot_taken {
            h.shot("22_autodock_approach");
            shot_taken = true;
        }
        if h.g.docked {
            break;
        }
    }
    assert!(h.g.docked, "docking computer docked the ship; pos {:?}", h.g.world.p.pos);
    assert_eq!(h.g.screen, Screen::Briefing, "chapter 0 completed");
    h.shot("23_chapter_complete");
    h.tap(Act::Enter);
    assert_eq!(h.g.cmdr.story.chapter, 1);
    assert_eq!(h.g.cmdr.credits, 1150);
}

#[test]
fn manual_dock_and_crash() {
    use drift_core::models::*;
    let fr = Orient::ID; // slot normal +z
    let spos = V3::ZERO;
    let start = v3(0.0, 0.0, STATION_HALF_LEN + 20.0);
    let end = v3(0.0, 0.0, STATION_HALF_LEN - 5.0);
    let into = Orient::look(v3(0.0, 0.0, -1.0), v3(0.0, 1.0, 0.0));
    assert_eq!(dock_test(spos, &fr, start, end, &into, 80.0), DockTest::Docked);
    // upside down is fine (slot symmetric)
    let mut flipped = into;
    flipped.roll(PI);
    assert_eq!(dock_test(spos, &fr, start, end, &flipped, 80.0), DockTest::Docked);
    // rolled a quarter turn: the wing tips hit the frame
    let mut quarter = into;
    quarter.roll(PI / 2.0);
    assert!(matches!(dock_test(spos, &fr, start, end, &quarter, 80.0), DockTest::Crash { .. }));
    // too fast
    assert!(matches!(dock_test(spos, &fr, start, end, &into, 400.0), DockTest::Crash { .. }));
    // off centre
    let off = v3(200.0, 0.0, STATION_HALF_LEN + 20.0);
    let offe = v3(200.0, 0.0, STATION_HALF_LEN - 5.0);
    assert!(matches!(dock_test(spos, &fr, off, offe, &into, 80.0), DockTest::Crash { .. }));
    // nose not pointing in
    let sideways = Orient::look(v3(1.0, 0.0, -0.3), v3(0.0, 1.0, 0.0));
    assert!(matches!(dock_test(spos, &fr, start, end, &sideways, 80.0), DockTest::Crash { .. }));
    // moving away does nothing
    assert_eq!(dock_test(spos, &fr, end, start, &into, 80.0), DockTest::None);
    // the slot rotates with the station: a rotated frame needs a rotated ship
    let mut rot = fr;
    rot.rotate_axis(fr.f, 0.5);
    assert!(matches!(dock_test(spos, &rot, start, end, &into, 80.0), DockTest::Docked | DockTest::Crash { .. }));
    let mut matched = into;
    matched.roll(0.5);
    assert_eq!(dock_test(spos, &rot, start, end, &matched, 80.0), DockTest::Docked);
}

#[test]
fn trading_rules() {
    let mut h = H::new(640, 360);
    h.new_game_to_dock();
    h.g.cmdr.credits = 5000;
    let i = (0..NCOM).find(|&i| h.g.market.stock[i] > 5 && !COMMODITIES[i].illegal).unwrap();
    let p = h.g.market.price[i] as i64;
    let stock = h.g.market.stock[i];
    h.g.buy(i, 3);
    assert_eq!(h.g.cmdr.cargo[i], 3);
    assert_eq!(h.g.market.stock[i], stock - 3);
    assert!(h.g.cmdr.credits <= 5000 - 3 * p);
    h.g.sell(i, 2);
    assert_eq!(h.g.cmdr.cargo[i], 1);
    // the hold limit holds
    h.g.cmdr.credits = 1_000_000;
    for k in 0..NCOM {
        h.g.market.stock[k] = 90;
    }
    for k in 0..NCOM {
        h.g.buy(k, 90);
    }
    assert_eq!(h.g.cmdr.hold_used(), h.g.cmdr.hold_capacity());
    // equipment gating by tech level
    let rows = h.g.equipment_rows();
    let tl = h.g.sys().tech;
    for r in rows {
        if let EqAct::Equip(f) = r.act {
            let e = EQUIPMENT.iter().find(|e| e.flag == f).unwrap();
            assert_eq!(matches!(r.status, EqState::Locked(_)), tl < e.min_tech, "{}", e.name);
        }
    }
}

#[test]
fn combat_bounty_and_legal_status() {
    let mut h = H::new(1280, 720);
    h.new_game_to_dock();
    h.tap(Act::F1);
    h.frames(10);
    let p = h.g.world.p.pos;
    let f = h.g.world.p.o.f;
    h.g.world.ships.retain(|s| s.fac == Faction::Neutral);
    h.g.world.p.speed = 0.0;
    h.g.world.p.throttle = 0.0;
    let i = h.g.world.add_ship(Kind::Jackal, p + f * 700.0, Orient::look(-f, v3(0.0, 1.0, 0.0)), Faction::Pirate);
    h.g.world.ships[i].ai = Ai::Drift;
    h.g.world.ships[i].want = 0.0;
    h.g.world.ships[i].speed = 0.0;
    h.g.world.ships[i].energy = 12.0;
    h.g.world.ships[i].shield_f = 0.0;
    h.g.world.ships[i].shield_a = 0.0;
    let credits0 = h.g.cmdr.credits;
    let kills0 = h.g.cmdr.kills;
    h.g.input.key(Act::Fire, true);
    let mut shot = false;
    for n in 0..300 {
        h.g.update(1.0 / 30.0);
        if n == 20 && !shot {
            h.shot("30_combat_laser");
            shot = true;
        }
        if h.g.cmdr.kills > kills0 {
            break;
        }
    }
    h.g.input.key(Act::Fire, false);
    assert!(h.g.cmdr.kills > kills0, "pirate destroyed");
    assert_eq!(h.g.cmdr.credits, credits0 + 110);
    h.frames(6);
    h.shot("31_explosion");
    // shooting a trader makes you an offender, killing one makes you a fugitive
    let p = h.g.world.p.pos;
    let f = h.g.world.p.o.f;
    let j = h.g.world.add_ship(Kind::Gull, p + f * 500.0, Orient::look(-f, v3(0.0, 1.0, 0.0)), Faction::Civil);
    h.g.world.ships[j].ai = Ai::Drift;
    h.g.world.ships[j].shield_f = 0.0;
    h.g.world.ships[j].shield_a = 0.0;
    h.g.input.key(Act::Fire, true);
    for _ in 0..200 {
        h.g.update(1.0 / 30.0);
        if h.g.cmdr.legal() == Legal::Fugitive {
            break;
        }
    }
    h.g.input.key(Act::Fire, false);
    assert!(h.g.cmdr.heat > 0, "crime recorded");
    assert_ne!(h.g.cmdr.legal(), Legal::Clean);
    // missile lock and kill
    let p = h.g.world.p.pos;
    let f = h.g.world.p.o.f;
    h.g.cmdr.missiles = 2;
    let k = h.g.world.add_ship(Kind::Hyena, p + f * 1500.0, Orient::look(-f, v3(0.0, 1.0, 0.0)), Faction::Pirate);
    h.g.world.ships[k].ai = Ai::Drift;
    h.g.world.ships[k].energy = 60.0;
    h.g.world.ships[k].shield_f = 0.0;
    h.g.world.ships[k].shield_a = 0.0;
    h.tap(Act::Target);
    h.frames(40);
    assert!(h.g.world.p.lock_t >= 1.0, "lock acquired");
    h.shot("32_missile_lock");
    h.tap(Act::Missile);
    assert_eq!(h.g.cmdr.missiles, 1);
    let kills = h.g.cmdr.kills;
    for _ in 0..200 {
        h.g.update(1.0 / 30.0);
        if h.g.cmdr.kills > kills {
            break;
        }
    }
    assert!(h.g.cmdr.kills > kills, "missile killed the target");
}

#[test]
fn hyperspace_and_save_load() {
    let mut h = H::new(1280, 720);
    h.new_game_to_dock();
    h.tap(Act::F1);
    h.frames(5);
    // jump to the nearest in-range system
    let cur = h.g.cmdr.system as usize;
    let dest = (0..256).filter(|&j| j != cur && h.g.gal.dist_ly(cur, j) < 6.0).next().unwrap();
    h.g.dest = Some(dest);
    h.g.world.p.pos = h.g.world.p.pos + h.g.world.p.o.f * 20000.0; // away from the station
    let fuel0 = h.g.cmdr.fuel;
    h.tap(Act::Hyper);
    assert!(h.g.hyper.is_some(), "countdown started (mass locked? {})", h.g.world.mass_locked());
    h.frames(60);
    h.shot("40_hyperspace_tunnel");
    h.frames(120);
    assert!(h.g.cmdr.fuel < fuel0, "fuel used");
    assert!(h.g.cmdr.system as usize == dest || h.g.pocket_dest.is_some());
    h.frames(20);
    h.shot("41_arrival");
    // save and load round trip through the io queue
    let mut h2 = H::new(320, 180);
    h2.new_game_to_dock();
    h2.g.cmdr.credits = 4321;
    h2.g.cmdr.kills = 17;
    h2.g.save_to(2);
    let io = h2.g.take_io();
    let data = match &io[0] {
        Io::WriteSlot { slot, data } => {
            assert_eq!(*slot, 2);
            data.clone()
        }
        _ => panic!("expected a slot write"),
    };
    let mut h3 = H::new(320, 180);
    h3.g.provide_slot(2, Some(&data));
    assert!(h3.g.load_slot(2));
    assert_eq!(h3.g.cmdr.credits, 4321);
    assert_eq!(h3.g.cmdr.kills, 17);
    assert_eq!(h3.g.latest_slot(), Some(2));
}

#[test]
fn escape_capsule_and_game_over() {
    let mut h = H::new(1280, 720);
    h.new_game_to_dock();
    h.tap(Act::F1);
    h.frames(5);
    h.g.world.kill_player("Test death");
    h.frames(120);
    assert_eq!(h.g.screen, Screen::Dead);
    h.shot("50_game_over");
    h.tap(Act::Down);
    h.tap(Act::Enter);
    assert_eq!(h.g.screen, Screen::MainMenu);
    // with a capsule the commander survives
    let mut h = H::new(320, 180);
    h.new_game_to_dock();
    h.g.cmdr.equip |= EQ_CAPSULE;
    h.g.cmdr.credits = 777;
    h.tap(Act::F1);
    h.frames(5);
    h.g.world.kill_player("Test death");
    h.frames(120);
    assert_eq!(h.g.screen, Screen::Status);
    assert!(h.g.docked);
    assert_eq!(h.g.cmdr.credits, 777);
    assert_eq!(h.g.cmdr.equip & EQ_CAPSULE, 0);
}

#[test]
fn ending_and_credits() {
    let mut h = H::new(1280, 720);
    h.new_game_to_dock();
    h.g.cmdr.story = Story { chapter: 6, stage: 0, active: true, progress: 0, sys: [3, 4, 5], hub: 3, intro_seen: true, free_play: false };
    h.g.start_ending();
    assert_eq!(h.g.screen, Screen::Ending);
    h.frames(45);
    h.shot("60_ending");
    for _ in 0..5 {
        h.tap(Act::Enter);
    }
    assert_eq!(h.g.screen, Screen::Credits);
    h.frames(200);
    h.shot("61_credits");
    h.frames(30 * 6);
    h.shot("62_credits_end");
    h.tap(Act::Enter);
    assert_eq!(h.g.screen, Screen::FreePlay);
    h.shot("63_free_play_prompt");
    h.tap(Act::Enter);
    assert!(h.g.cmdr.story.free_play);
    assert_eq!(h.g.screen, Screen::Status);
    assert!(h.g.take_io().iter().any(|i| matches!(i, Io::WriteSlot { .. })));
}

#[test]
fn story_chapters_progress() {
    let mut h = H::new(320, 180);
    h.new_game_to_dock();
    // chapter 0 -> 1 by editing the state, then accept, deliver
    h.g.cmdr.story.chapter = 1;
    h.g.cmdr.story.active = false;
    h.tap(Act::F11);
    h.tap(Act::Enter);
    h.tap(Act::Enter);
    let st = h.g.cmdr.story.clone();
    assert!(st.active && st.chapter == 1);
    assert_ne!(st.sys[0], h.g.cmdr.system);
    assert!(h.g.gal.dist_ly(h.g.cmdr.system as usize, st.sys[0] as usize) <= 7.0);
    // gates
    h.g.cmdr.story.chapter = 3;
    h.g.cmdr.story.active = false;
    h.g.cmdr.kills = 0;
    h.tap(Act::F11);
    h.tap(Act::Enter);
    assert!(!h.g.cmdr.story.active, "chapter 3 needs 8 kills");
    h.g.cmdr.kills = 8;
    h.tap(Act::Enter);
    assert!(h.g.cmdr.story.active);
}

#[test]
fn frame_time_report() {
    // run with --release for meaningful numbers
    let mut h = H::new(1920, 1080);
    h.new_game_to_dock();
    h.tap(Act::F1);
    h.hold(Act::Faster, 20);
    let n = 40;
    let t0 = std::time::Instant::now();
    for _ in 0..n {
        h.g.update(1.0 / 30.0);
        h.g.render(&mut h.c);
    }
    let per = t0.elapsed().as_secs_f64() * 1000.0 / n as f64;
    println!("1920x1080 quality {}: {:.2} ms/frame (scene {}x{})", h.g.settings.quality, per, h.g.scene_size().0, h.g.scene_size().1);
    h.shot("70_flight_1080p");
}


#[test]
fn retro_pause_and_sun_skim() {
    let mut h = H::new(1280, 720);
    h.new_game_to_dock();
    h.tap(Act::F1);
    h.frames(30);
    h.g.settings.retro = true;
    h.shot("80_retro_mode");
    h.g.settings.retro = false;
    h.tap(Act::Pause);
    assert_eq!(h.g.screen, Screen::Pause);
    h.shot("81_pause_menu");
    h.tap(Act::Pause);
    assert_eq!(h.g.screen, Screen::Flight);
    // sun skimming: the scoop refuels, the cabin heats up
    h.g.cmdr.equip |= EQ_SCOOP;
    h.g.cmdr.fuel = 10;
    let sun = h.g.world.sun_pos;
    let r = h.g.world.sun_r;
    let dir = v3(0.0, 0.0, 1.0);
    let _ = dir;
    h.g.world.p.pos = sun + (h.g.world.p.pos - sun).norm() * (r * 1.3);
    h.g.world.p.o = Orient::look(h.g.world.p.pos.cross(v3(0.0, 1.0, 0.0)), (h.g.world.p.pos - sun).norm());
    h.g.world.p.speed = 0.0;
    h.g.world.p.throttle = 0.0;
    h.frames(90);
    h.shot("82_sun_skim");
    assert!(h.g.cmdr.fuel > 10, "fuel scooped from the star");
    assert!(h.g.world.p.cabin > 60.0, "cabin heats: {}", h.g.world.p.cabin);
}

#[test]
fn mining_laser_yields_cargo() {
    let mut h = H::new(320, 180);
    h.new_game_to_dock();
    h.g.cmdr.lasers[0] = LASER_MINING;
    h.tap(Act::F1);
    h.frames(10);
    h.g.world.ships.clear();
    let p = h.g.world.p.pos;
    let f = h.g.world.p.o.f;
    h.g.world.p.speed = 0.0;
    h.g.world.p.throttle = 0.0;
    let i = h.g.world.add_ship(Kind::Rock, p + f * 400.0, Orient::ID, Faction::Neutral);
    h.g.world.ships[i].ai = Ai::Drift;
    h.g.world.ships[i].energy = 40.0;
    h.g.input.key(Act::Fire, true);
    for _ in 0..200 {
        h.g.update(1.0 / 30.0);
    }
    h.g.input.key(Act::Fire, false);
    let canisters = h.g.world.ships.iter().filter(|s| s.kind == Kind::Canister).count();
    assert!(canisters > 0 || h.g.world.ships.iter().any(|s| s.kind == Kind::Splinter), "rock broke up");
}
