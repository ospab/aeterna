// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Host harness: scripted input for N frames, screenshots (PPM) and gameplay checks.
mod common;
use drift_core::commander::*;
use drift_core::econ::*;
use drift_core::game::*;
use drift_core::gfx::*;
use drift_core::i18n::Lang;
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
        self.g.bd_frame = 3;
        self.g.render(&mut self.c);
        common::save_ppm(name, self.c.w, self.c.h, &self.c.px);
    }
    fn shot_noaudit(&mut self, name: &str) {
        self.g.bd_frame = 3;
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
        assert_eq!(self.g.screen, Screen::TutorialAsk);
        self.tap(Act::Down);
        self.tap(Act::Enter); // skip the tutorial
        assert_eq!(self.g.screen, Screen::Status);
        assert!(self.g.tut.is_none());
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
    for _ in 0..4 {
        h.tap(Act::Down);
    }
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
    assert_eq!(h.g.screen, Screen::TutorialAsk);
    h.shot("05_tutorial_ask");
    h.tap(Act::Down);
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
fn launch_fly_and_autodock() {
    let mut h = H::new(960, 540);
    h.new_game_to_dock();
    h.g.cmdr.story.chapter = 1;
    h.tap(Act::F1);
    assert_eq!(h.g.screen, Screen::Flight);
    assert!(!h.g.docked);
    h.hold(Act::Faster, 30);
    h.frames(30);
    h.shot("20_launch_flight");
    h.hold(Act::Right, 15);
    h.hold(Act::Down, 15);
    h.shot("21_flight_maneuver");
    h.g.cmdr.equip |= EQ_DOCKCOMP;
    let (sp, fr) = h.g.world.station_frame().unwrap();
    h.g.world.p.pos = sp + fr.f * 3200.0 + fr.r * 900.0 + fr.u * (-500.0);
    h.g.world.p.o = Orient::look(v3(0.3, 0.8, 0.2), v3(0.0, 1.0, 0.0));
    h.g.world.p.speed = 100.0;
    h.tap(Act::Dock);
    assert!(h.g.world.p.dockcomp);
    for i in 0..3600 {
        h.g.update(1.0 / 30.0);
        if i == 300 {
            h.shot("22_autodock_approach");
        }
        if h.g.docked {
            break;
        }
    }
    assert!(h.g.docked, "docking computer docked the ship; pos {:?}", h.g.world.p.pos);
    assert_eq!(h.g.screen, Screen::Status);
}

#[test]
fn tutorial_full_run() {
    let mut h = H::new(1280, 800);
    h.tap(Act::Enter);
    h.tap(Act::Enter);
    for _ in 0..6 {
        h.tap(Act::Enter);
    }
    assert_eq!(h.g.screen, Screen::TutorialAsk);
    h.tap(Act::Enter);
    assert_eq!(h.g.screen, Screen::Status);
    assert_eq!(h.g.tut.as_ref().unwrap().step, 0);
    h.shot("90_tut_step1_launch");
    h.tap(Act::F1);
    h.frames(3);
    assert_eq!(h.g.tut.as_ref().unwrap().step, 1, "launched");
    h.shot("91_tut_step2_steer");
    h.hold(Act::Right, 30);
    h.hold(Act::Down, 30);
    assert_eq!(h.g.tut.as_ref().unwrap().step, 2, "steered");
    h.hold(Act::Faster, 40);
    assert_eq!(h.g.tut.as_ref().unwrap().step, 3, "throttle");
    h.tap(Act::F2);
    h.frames(3);
    h.tap(Act::F1);
    h.frames(3);
    assert_eq!(h.g.tut.as_ref().unwrap().step, 4, "views");
    h.shot("97_tut_dashboard_step");
    h.tap(Act::Enter);
    h.frames(2);
    assert_eq!(h.g.tut.as_ref().unwrap().step, 5, "dashboard");
    let (sp, _) = h.g.world.station_frame().unwrap();
    h.g.world.p.o = Orient::look(sp - h.g.world.p.pos, v3(0.0, 1.0, 0.0));
    h.frames(3);
    assert_eq!(h.g.tut.as_ref().unwrap().step, 6, "compass");
    let drone = h.g.tut.as_ref().unwrap().drone;
    let dpos = h.g.world.find(drone).unwrap().pos;
    h.g.world.p.o = Orient::look(dpos - h.g.world.p.pos, v3(0.0, 1.0, 0.0));
    h.tap(Act::Target);
    h.frames(3);
    assert_eq!(h.g.tut.as_ref().unwrap().step, 7, "target");
    h.shot("92_tut_step7_fire");
    h.g.input.key(Act::Fire, true);
    for _ in 0..200 {
        let dp = h.g.world.find(drone).map(|s| s.pos);
        if let Some(dp) = dp {
            h.g.world.p.o = Orient::look(dp - h.g.world.p.pos, v3(0.0, 1.0, 0.0));
        }
        h.g.update(1.0 / 30.0);
        if h.g.tut.as_ref().unwrap().step > 7 {
            break;
        }
    }
    h.g.input.key(Act::Fire, false);
    if h.g.tut.as_ref().unwrap().step != 8 {
        let d = h.g.world.find(drone).map(|s| (s.energy, s.pos, s.kind));
        println!("drone {:?} player {:?} screen {:?} heat {:?} cd {} lasers {:?} bolts {}", d, h.g.world.p.pos, h.g.screen, h.g.world.p.laser_heat, h.g.world.p.fire_cd, h.g.cmdr.lasers, h.g.world.bolts.len());
    }
    assert_eq!(h.g.tut.as_ref().unwrap().step, 8, "drone destroyed");
    let b = h.g.world.beacon.unwrap();
    h.g.world.p.pos = b + v3(60.0, 0.0, 0.0);
    h.frames(3);
    assert_eq!(h.g.tut.as_ref().unwrap().step, 9, "beacon");
    h.g.input.key(Act::Jump, true);
    for _ in 0..600 {
        h.g.update(1.0 / 30.0);
        if h.g.tut.as_ref().unwrap().step > 9 {
            break;
        }
    }
    h.g.input.key(Act::Jump, false);
    assert_eq!(h.g.tut.as_ref().unwrap().step, 10, "in-system jump");
    h.frames(60);
    h.tap(Act::Dock);
    let mut shot = false;
    for i in 0..4000 {
        h.g.update(1.0 / 30.0);
        if !shot && h.g.world.station_frame().map_or(false, |(sp, _)| (sp - h.g.world.p.pos).len() < 1500.0) {
            h.shot("93_tut_step10_dock_guide");
            shot = true;
        }
        if h.g.docked {
            println!("docked after {} frames", i);
            break;
        }
    }
    assert!(h.g.docked);
    assert_eq!(h.g.tut.as_ref().unwrap().step, 11, "docked");
    h.tap(Act::F9);
    h.shot("94_tut_step11_trade");
    let i = (0..NCOM).find(|&i| h.g.market.stock[i] > 0 && !COMMODITIES[i].illegal).unwrap();
    h.g.sel = i;
    h.tap(Act::Buy);
    h.frames(2);
    assert_eq!(h.g.tut.as_ref().unwrap().step, 12, "bought cargo");
    h.tap(Act::F10);
    h.shot("95_tut_step12_refuel");
    assert!(h.g.cmdr.fuel < MAX_FUEL_TENTHS);
    h.tap(Act::Enter);
    h.frames(2);
    assert!(h.g.tut.is_none(), "tutorial finished");
    assert_eq!(h.g.cmdr.story.chapter, 1);
    assert_eq!(h.g.screen, Screen::Briefing);
    assert_eq!(h.g.cmdr.equip & EQ_DOCKCOMP, 0, "loaned docking computer returned");
    h.shot("96_tut_done");
}

#[test]
fn tutorial_skip_and_practice() {
    let mut h = H::new(640, 360);
    h.tap(Act::Enter);
    h.tap(Act::Down);
    h.tap(Act::Enter); // Tutorial menu item
    assert!(h.g.tut.as_ref().map_or(false, |t| t.practice));
    h.tap(Act::Skip);
    assert!(h.g.tut.is_none());
    assert_eq!(h.g.screen, Screen::MainMenu);
    // campaign: skipping with X moves the story on
    h.tap(Act::Enter);
    for _ in 0..6 {
        h.tap(Act::Enter);
    }
    h.tap(Act::Enter);
    assert!(h.g.tut.is_some());
    h.tap(Act::Skip);
    assert!(h.g.tut.is_none());
    assert_eq!(h.g.cmdr.story.chapter, 1);
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
    let (mut tu, mut tr) = (0.0f64, 0.0f64);
    for _ in 0..n {
        let t0 = std::time::Instant::now();
        h.g.update(1.0 / 30.0);
        tu += t0.elapsed().as_secs_f64();
        let t1 = std::time::Instant::now();
        h.g.render(&mut h.c);
        tr += t1.elapsed().as_secs_f64();
    }
    println!("update {:.2} ms, render {:.2} ms", tu * 1000.0 / n as f64, tr * 1000.0 / n as f64);
    let per = (tu + tr) * 1000.0 / n as f64;
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

pub const RESOLUTIONS: [(usize, usize); 8] = [(800, 600), (1024, 768), (1280, 720), (1280, 800), (1360, 768), (1600, 900), (1920, 1080), (2560, 1440)];

/// Render `screen` with text auditing; returns offending text boxes (outside the canvas or overlapping).
fn audit(h: &mut H, label: &str) -> Vec<String> {
    h.c.audit = Some(Vec::new());
    h.g.render(&mut h.c);
    let boxes = h.c.audit.take().unwrap();
    let mut bad = Vec::new();
    let (w, hh) = (h.c.w as i32, h.c.h as i32);
    for b in &boxes {
        if b[0] < 0 || b[1] < 0 || b[2] > w || b[3] > hh {
            bad.push(format!("{}: text outside screen {:?}", label, b));
        }
    }
    for i in 0..boxes.len() {
        for j in 0..i {
            let (a, b) = (boxes[i], boxes[j]);
            if a[0] < b[2] - 2 && b[0] < a[2] - 2 && a[1] < b[3] - 3 && b[1] < a[3] - 3 {
                bad.push(format!("{}: overlap {:?} {:?}", label, a, b));
            }
        }
    }
    bad
}

fn setup_screens(h: &mut H) -> Vec<(&'static str, Screen)> {
    h.g.cmdr.story.chapter = 1;
    h.g.cmdr.story.active = false;
    h.g.cmdr.credits = 123456;
    h.g.cmdr.equip = EQ_SCOOP | EQ_CHAFF | EQ_DOCKCOMP;
    h.g.cmdr.damaged = EQ_CHAFF;
    h.g.cmdr.cargo[3] = 4;
    h.g.cmdr.cargo[13] = 2;
    h.g.dest = Some(5);
    vec![
        ("title", Screen::Title),
        ("menu", Screen::MainMenu),
        ("intro", Screen::Intro),
        ("settings", Screen::Settings),
        ("controls", Screen::Controls),
        ("credits", Screen::Credits),
        ("load", Screen::Load),
        ("save", Screen::Save),
        ("status", Screen::Status),
        ("galchart", Screen::GalChart),
        ("localchart", Screen::LocalChart),
        ("sysinfo", Screen::SysInfo),
        ("market", Screen::Market),
        ("equipment", Screen::Equipment),
        ("contracts", Screen::Contracts),
        ("briefing", Screen::Briefing),
        ("dead", Screen::Dead),
        ("ending", Screen::Ending),
        ("freeplay", Screen::FreePlay),
    ]
}

#[test]
fn layout_audit_all_resolutions() {
    let mut all_bad: Vec<String> = Vec::new();
    for (w, hh, lang) in RESOLUTIONS.iter().flat_map(|r| [(r.0, r.1, Lang::En), (r.0, r.1, Lang::Ru)]) {
        let mut h = H::new(w, hh);
        h.g.settings.lang = lang;
        h.new_game_to_dock();
        let screens = setup_screens(&mut h);
        h.g.brief = Some(Brief {
            title: String::from("Cinder Captain: complete"),
            body: vec![String::from("Corvane's hold contained a third key fragment and an order signed by Director Kael Marrow: 'Cut every anchor. Leave the Mother Anchor for me.'"), String::from("Reward: 1800 credits")],
            reward: 1800,
        });
        h.g.stats = Some(DeathStats { kills: 99, credits: 1234567, jumps: 321, seconds: 99999, why: "Your ship was destroyed." });
        h.g.after_credits = Screen::MainMenu;
        for (name, s) in &screens {
            h.g.screen = *s;
            h.g.page = 1;
            h.g.sel = 1;
            h.g.credits_y = if *s == Screen::Credits { 300.0 } else { 0.0 };
            h.g.ui_t = 3.0;
            let label = format!("{}x{} {:?} {}", w, hh, lang, name);
            let bad = audit(&mut h, &label);
            all_bad.extend(bad);
        }
        // flight HUD with everything lit
        h.g.screen = Screen::Flight;
        h.g.docked = false;
        let sp = h.g.world.station_frame().unwrap();
        h.g.world.p.pos = sp.0 + sp.1.f * 2500.0;
        h.g.world.beacon = Some(sp.0 + sp.1.f * 3500.0);
        let i = h.g.world.add_ship(Kind::Hyena, sp.0 + sp.1.f * 3000.0, Orient::ID, Faction::Pirate);
        let id = h.g.world.ships[i].id;
        h.g.world.p.lock = id;
        h.g.world.p.lock_t = 1.0;
        h.g.world.p.cabin = 95.0;
        h.g.world.p.energy = 50.0;
        h.g.world.p.missile_warn = true;
        h.g.world.p.dockcomp = true;
        h.g.hyper = Some(Hyper { t: 3.0, dest: 3, galaxy_jump: false, free: false });
        for k in 0..5 {
            h.g.warn(&format!("A rather long warning message number {} that needs to wrap inside its box", k));
        }
        h.g.ui_t = 0.0; // blink phase on
        let bad = audit(&mut h, &format!("{}x{} {:?} flight", w, hh, lang));
        all_bad.extend(bad);
    }
    for b in &all_bad {
        println!("{}", b);
    }
    assert!(all_bad.is_empty(), "{} layout problems", all_bad.len());
}

fn half(w: usize, h: usize, px: &[u32]) -> (usize, usize, Vec<u32>) {
    let (nw, nh) = (w / 2, h / 2);
    let mut o = vec![0u32; nw * nh];
    for y in 0..nh {
        for x in 0..nw {
            let p = [px[2 * y * w + 2 * x], px[2 * y * w + 2 * x + 1], px[(2 * y + 1) * w + 2 * x], px[(2 * y + 1) * w + 2 * x + 1]];
            let mut c = [0u32; 3];
            for v in p {
                c[0] += (v >> 16) & 255;
                c[1] += (v >> 8) & 255;
                c[2] += v & 255;
            }
            o[y * nw + x] = ((c[0] / 4) << 16) | ((c[1] / 4) << 8) | (c[2] / 4);
        }
    }
    (nw, nh, o)
}

fn shot_res(h: &mut H, name: &str) {
    h.g.bd_frame = 3;
    h.g.render(&mut h.c);
    if h.c.w > 1400 {
        let (w, hh, px) = half(h.c.w, h.c.h, &h.c.px);
        common::save_ppm(name, w, hh, &px);
    } else {
        common::save_ppm(name, h.c.w, h.c.h, &h.c.px);
    }
}

/// One image per screen per resolution (sizes above 1400 wide are saved at half size).
#[test]
fn resolution_screenshots() {
    for (w, hh) in RESOLUTIONS {
        let mut h = H::new(w, hh);
        let tag = format!("r{}x{}", w, hh);
        h.frames(10);
        h.tap(Act::Enter);
        h.frames(5);
        shot_res(&mut h, &format!("{}_menu", tag));
        h.g.screen = Screen::Title;
        h.new_game_to_dock();
        h.g.cmdr.story.chapter = 1;
        h.g.cmdr.story.active = false;
        h.g.cmdr.credits = 4321;
        for (nm, act) in [("status", Act::F5), ("galaxy", Act::F6), ("local", Act::F7), ("market", Act::F9), ("equipment", Act::F10), ("contracts", Act::F11)] {
            h.tap(act);
            h.frames(2);
            shot_res(&mut h, &format!("{}_{}", tag, nm));
        }
        h.g.brief = Some(Brief {
            title: String::from("Cinder Captain: complete"),
            body: vec![String::from("Corvane's hold contained a third key fragment and an order signed by Director Kael Marrow: 'Cut every anchor. Leave the Mother Anchor for me.'"), String::from("Reward: 1800 credits")],
            reward: 1800,
        });
        h.g.screen = Screen::Briefing;
        shot_res(&mut h, &format!("{}_briefing", tag));
        h.g.screen = Screen::Status;
        // flight with the tutorial and the docking guide
        h.g.start_tutorial(true);
        h.tap(Act::F1);
        h.frames(3);
        h.g.tut.as_mut().unwrap().step = 10;
        let (sp, fr) = h.g.world.station_frame().unwrap();
        h.g.world.p.pos = sp + fr.f * 1400.0 + fr.r * 120.0 + fr.u * 60.0;
        h.g.world.p.o = Orient::look(sp - h.g.world.p.pos, v3(0.0, 1.0, 0.0));
        h.g.world.p.speed = 90.0;
        let i = h.g.world.add_ship(Kind::Hyena, sp + fr.f * 2600.0 + fr.r * 500.0, Orient::ID, Faction::Pirate);
        h.g.world.ships[i].ai = Ai::Drift;
        h.g.world.p.lock = h.g.world.ships[i].id;
        h.g.world.p.lock_t = 1.0;
        h.frames(2);
        shot_res(&mut h, &format!("{}_flight", tag));
        h.g.screen = Screen::Credits;
        h.g.credits_y = 150.0;
        shot_res(&mut h, &format!("{}_credits", tag));
    }
}

#[test]
fn tutorial_panels_fit_in_both_languages() {
    let mut all_bad: Vec<String> = Vec::new();
    for (w, hh) in RESOLUTIONS {
        for lang in [Lang::En, Lang::Ru] {
            let mut h = H::new(w, hh);
            h.g.settings.lang = lang;
            h.g.start_tutorial(true);
            // docked strip for every step
            for step in 0..13 {
                h.g.tut.as_mut().unwrap().step = step;
                for scr in [Screen::Status, Screen::Market, Screen::Equipment] {
                    h.g.screen = scr;
                    let b = audit(&mut h, &format!("{}x{} {:?} strip step {} {:?}", w, hh, lang, step, scr));
                    all_bad.extend(b);
                }
            }
            h.tap(Act::F1);
            h.frames(3);
            for step in 1..13 {
                h.g.tut.as_mut().unwrap().step = step;
                h.g.screen = Screen::Flight;
                let (sp, fr) = h.g.world.station_frame().unwrap();
                h.g.world.p.pos = sp + fr.f * 1500.0;
                h.g.world.p.o = Orient::look(sp - h.g.world.p.pos, v3(0.0, 1.0, 0.0));
                let b = audit(&mut h, &format!("{}x{} {:?} flight step {}", w, hh, lang, step));
                all_bad.extend(b);
            }
        }
    }
    for b in &all_bad {
        println!("{}", b);
    }
    assert!(all_bad.is_empty(), "{} tutorial layout problems", all_bad.len());
}

#[test]
fn russian_screenshots() {
    for (w, hh) in [(1280usize, 800usize), (1920, 1080)] {
        let mut h = H::new(w, hh);
        h.g.settings.lang = Lang::Ru;
        let tag = format!("ru{}x{}", w, hh);
        h.frames(10);
        h.tap(Act::Enter);
        h.frames(5);
        shot_res(&mut h, &format!("{}_menu", tag));
        h.g.screen = Screen::Title;
        h.new_game_to_dock();
        h.g.cmdr.kills = 10;
        h.g.cmdr.story.chapter = 3;
        h.g.cmdr.story.active = false;
        h.tap(Act::F11);
        h.tap(Act::Enter);
        assert_eq!(h.g.screen, Screen::Briefing);
        shot_res(&mut h, &format!("{}_briefing", tag));
        h.tap(Act::Enter);
        h.tap(Act::F9);
        h.frames(2);
        shot_res(&mut h, &format!("{}_market", tag));
        h.tap(Act::F5);
        shot_res(&mut h, &format!("{}_status", tag));
        h.tap(Act::F8);
        shot_res(&mut h, &format!("{}_system", tag));
        h.g.start_tutorial(true);
        h.tap(Act::F1);
        h.frames(3);
        h.g.tut.as_mut().unwrap().step = 10;
        let (sp, fr) = h.g.world.station_frame().unwrap();
        h.g.world.p.pos = sp + fr.f * 1400.0 + fr.r * 120.0 + fr.u * 60.0;
        h.g.world.p.o = Orient::look(sp - h.g.world.p.pos, v3(0.0, 1.0, 0.0));
        h.g.world.p.speed = 90.0;
        let i = h.g.world.add_ship(Kind::Hyena, sp + fr.f * 2600.0 + fr.r * 500.0, Orient::ID, Faction::Pirate);
        h.g.world.ships[i].ai = Ai::Drift;
        h.g.world.p.lock = h.g.world.ships[i].id;
        h.g.world.p.lock_t = 1.0;
        h.g.warn("Hostile contacts inbound");
        h.frames(2);
        shot_res(&mut h, &format!("{}_flight", tag));
        h.g.screen = Screen::Settings;
        h.g.sel = 4;
        shot_res(&mut h, &format!("{}_settings", tag));
    }
}

#[test]
fn hud_both_languages() {
    for (w, hh) in [(1024usize, 768usize), (1280, 800), (1920, 1080)] {
        for lang in [Lang::En, Lang::Ru] {
            let mut h = H::new(w, hh);
            h.g.settings.lang = lang;
            h.new_game_to_dock();
            h.tap(Act::F1);
            h.frames(20);
            let tag = format!("hud_{}_{}x{}", if lang == Lang::En { "en" } else { "ru" }, w, hh);
            // healthy
            h.shot_noaudit(&format!("{}_normal", tag));
            // low and hot: colours change
            h.g.world.p.shield_f = 40.0;
            h.g.world.p.shield_a = 15.0;
            h.g.world.p.energy = 90.0;
            h.g.world.p.cabin = 100.0;
            h.g.world.p.laser_heat[0] = 70.0;
            h.g.cmdr.fuel = 12;
            h.g.world.p.speed = 312.0;
            h.g.world.p.throttle = 0.87;
            h.shot_noaudit(&format!("{}_warn", tag));
            // dashboard tutorial step with the panel highlighted
            h.g.start_tutorial(true);
            h.tap(Act::F1);
            h.frames(3);
            h.g.tut.as_mut().unwrap().step = 4;
            h.shot_noaudit(&format!("{}_tutorial", tag));
        }
    }
}

#[test]
fn frame_time_breakdown() {
    let mut h = H::new(1920, 1080);
    h.new_game_to_dock();
    h.tap(Act::F1);
    h.hold(Act::Faster, 20);
    for (name, bloom, retro, q) in [("default", true, false, 1u8), ("no bloom", false, false, 1), ("retro", false, true, 1), ("low", true, false, 0), ("high", true, false, 2)] {
        h.g.settings.bloom = bloom;
        h.g.settings.retro = retro;
        h.g.settings.quality = q;
        h.g.render(&mut h.c);
        let t0 = std::time::Instant::now();
        for _ in 0..20 {
            h.g.render(&mut h.c);
        }
        println!("{}: {:.2} ms", name, t0.elapsed().as_secs_f64() * 1000.0 / 20.0);
    }
    // pause screen draws the scene but no HUD
    h.g.settings = Settings::default_settings();
    h.g.screen = Screen::Title;
    let t0 = std::time::Instant::now();
    for _ in 0..20 {
        h.g.render(&mut h.c);
    }
    println!("title (scene + overlay): {:.2} ms", t0.elapsed().as_secs_f64() * 1000.0 / 20.0);
    for (name, scr) in [("main menu", Screen::MainMenu), ("settings", Screen::Settings), ("status", Screen::Status), ("market", Screen::Market), ("pause", Screen::Pause)] {
        h.g.screen = scr;
        h.g.docked = true;
        h.g.render(&mut h.c);
        let t0 = std::time::Instant::now();
        for _ in 0..10 {
            h.g.render(&mut h.c);
        }
        println!("{}: {:.2} ms", name, t0.elapsed().as_secs_f64() * 1000.0 / 10.0);
    }
}

fn energy(v: &[i16]) -> (f64, f64) {
    let (mut l, mut r) = (0f64, 0f64);
    for f in v.chunks_exact(2) {
        l += (f[0] as f64).powi(2);
        r += (f[1] as f64).powi(2);
    }
    (l, r)
}

fn run_audio(h: &mut H, frames: usize, out: &mut Vec<i16>) {
    for _ in 0..frames {
        h.g.update(1.0 / 30.0);
        let mut buf = vec![0i16; 2 * 1600];
        h.g.mix_audio(&mut buf);
        out.extend_from_slice(&buf);
    }
}

#[test]
fn audio_combat_sequence_is_audible_and_panned() {
    let mut h = H::new(320, 180);
    h.new_game_to_dock();
    let mut wav: Vec<i16> = Vec::new();
    // station music while docked
    run_audio(&mut h, 60, &mut wav);
    let music_peak = wav.iter().map(|&x| (x as i32).abs()).max().unwrap();
    assert!(music_peak > 300, "station music audible: {}", music_peak);
    // launch, throttle up: engine hum
    h.tap(Act::F1);
    h.g.input.key(Act::Faster, true);
    let start = wav.len();
    run_audio(&mut h, 60, &mut wav);
    h.g.input.key(Act::Faster, false);
    assert!(wav[start..].iter().map(|&x| (x as i32).abs()).max().unwrap() > 300, "engine audible");
    // a pirate to the right, killed with lasers: laser shots then an explosion on the right
    let p = h.g.world.p.pos;
    let o = h.g.world.p.o;
    h.g.world.ships.retain(|s| s.fac == Faction::Neutral);
    h.g.world.p.speed = 0.0;
    h.g.world.p.throttle = 0.0;
    let i = h.g.world.add_ship(Kind::Jackal, p + o.f * 500.0 + o.r * 400.0, Orient::ID, Faction::Pirate);
    h.g.world.ships[i].ai = Ai::Drift;
    h.g.world.ships[i].energy = 10.0;
    h.g.world.ships[i].shield_f = 0.0;
    h.g.world.ships[i].shield_a = 0.0;
    h.g.world.p.o = Orient::look((p + o.f * 500.0 + o.r * 400.0) - p, v3(0.0, 1.0, 0.0));
    h.g.input.key(Act::Fire, true);
    let start = wav.len();
    let kills0 = h.g.cmdr.kills;
    for _ in 0..60 {
        run_audio(&mut h, 1, &mut wav);
        if h.g.cmdr.kills > kills0 {
            break;
        }
    }
    h.g.input.key(Act::Fire, false);
    assert!(h.g.cmdr.kills > kills0, "target destroyed");
    run_audio(&mut h, 20, &mut wav);
    let seg = &wav[start..];
    assert!(seg.iter().map(|&x| (x as i32).abs()).max().unwrap() > 3000, "laser and explosion are loud");
    // the explosion was to the right of the nose before we turned to face it: after turning the
    // target is dead ahead, so test the pan with an explicit event as well
    h.g.world.sfx.push((drift_core::audio::Sfx::Explosion, h.g.world.p.pos + h.g.world.p.o.r * 500.0, 1.0));
    let start = wav.len();
    run_audio(&mut h, 20, &mut wav);
    let (l, r) = energy(&wav[start..]);
    assert!(r > l * 2.0, "right-hand explosion is louder on the right: l {} r {}", l, r);
    // missile warning and low energy alarm
    h.g.world.p.energy = 50.0;
    let start = wav.len();
    run_audio(&mut h, 40, &mut wav);
    assert!(wav[start..].iter().map(|&x| (x as i32).abs()).max().unwrap() > 1500, "low energy alarm");
    common::save_wav("audio_combat", 48000, &wav);
    // volume 0 is silence
    h.g.settings.vol_master = 0;
    let mut quiet = Vec::new();
    run_audio(&mut h, 10, &mut quiet);
    assert!(quiet.iter().all(|&x| x == 0), "master volume 0 mutes everything");
}

#[test]
fn audio_settings_roundtrip_and_ui() {
    let mut s = Settings::default_settings();
    s.vol_master = 3;
    s.vol_sfx = 5;
    s.vol_music = 0;
    s.lang = Lang::Ru;
    let b = s.to_bytes();
    assert_eq!(Settings::from_bytes(&b), Some(s));
    // a settings file from before the volume options still loads
    assert_eq!(Settings::from_bytes(&b[..8]).map(|x| x.vol_master), Some(8));
    let mut h = H::new(640, 360);
    h.tap(Act::Enter);
    for _ in 0..4 {
        h.tap(Act::Down);
    }
    h.tap(Act::Enter);
    assert_eq!(h.g.screen, Screen::Settings);
    for _ in 0..5 {
        h.tap(Act::Down);
    }
    assert_eq!(h.g.sel, 5);
    let before = h.g.settings.vol_master;
    h.tap(Act::Left);
    assert_eq!(h.g.settings.vol_master, before - 1);
    h.shot("85_settings_volume");
}
