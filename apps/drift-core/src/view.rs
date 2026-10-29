// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Rendering: the 3D scene (sky, planet, star, station, ships, effects), upscaling, and the flight HUD.
use crate::commander::*;
use crate::econ::*;
use crate::game::*;
use crate::gfx::*;
use crate::math::*;
use crate::models::*;
use crate::raster::*;
use crate::sim::*;
use crate::space::*;
use alloc::format;
use alloc::string::String;

pub const C_PANEL: u32 = rgb(10, 14, 22);
pub const C_BORDER: u32 = rgb(44, 60, 86);
pub const C_ACCENT: u32 = rgb(70, 214, 200);
pub const C_AMBER: u32 = rgb(255, 184, 64);
pub const C_RED: u32 = rgb(255, 88, 88);
pub const C_GREEN: u32 = rgb(104, 230, 140);
pub const C_TEXT: u32 = rgb(216, 226, 240);
pub const C_DIM: u32 = rgb(122, 136, 160);
pub const C_BLUE: u32 = rgb(96, 160, 255);

#[derive(Clone, Copy)]
pub struct Ui {
    pub s: f32,
    pub fs: i32,
    pub lh: i32,
    pub w: i32,
    pub h: i32,
}

impl Ui {
    pub fn new(w: usize, h: usize) -> Ui {
        // Layouts are designed on a 960x540 canvas and scaled by the limiting dimension.
        let s = clamp(min(w as f32 / 960.0, h as f32 / 540.0), 0.83, 4.0);
        let fs = ((11.0 * s + 0.5) as i32).max(9);
        Ui { s, fs, lh: fs * 8 / 5, w: w as i32, h: h as i32 }
    }
    pub fn px(&self, v: f32) -> i32 {
        (v * self.s) as i32
    }
}

pub fn panel(c: &mut Canvas, x: i32, y: i32, w: i32, h: i32, alpha: u32) {
    c.rect(x, y, w, h, C_PANEL, alpha);
    c.rect_outline(x, y, w, h, 1, C_BORDER, 255);
}

pub fn bar(c: &mut Canvas, ui: &Ui, x: i32, y: i32, w: i32, frac: f32, col: u32, label: &str) {
    let h = ui.px(5.0).max(3);
    c.text(x, y - ui.fs / 2, ui.fs - 1, label, C_DIM, 255);
    let bx = x + (ui.fs - 1) * 5;
    let bw = w - (ui.fs - 1) * 5;
    c.rect(bx, y, bw, h, rgb(24, 32, 46), 255);
    let f = clamp(frac, 0.0, 1.0);
    c.rect(bx, y, (bw as f32 * f) as i32, h, col, 255);
    c.rect(bx, y + h - 1, (bw as f32 * f) as i32, 1, scale_col(col, 0.6), 255);
}

pub fn wrap(text: &str, cols: usize) -> alloc::vec::Vec<String> {
    let mut lines = alloc::vec::Vec::new();
    let mut cur = String::new();
    for w in text.split(' ') {
        if !cur.is_empty() && cur.chars().count() + 1 + w.chars().count() > cols {
            lines.push(core::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(w);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

fn fac_color(f: Faction, kind: Kind) -> u32 {
    match (f, kind) {
        (_, Kind::Canister) | (_, Kind::Capsule) => C_AMBER,
        (_, Kind::Rock) | (_, Kind::Splinter) => rgb(150, 140, 130),
        (_, Kind::Missile) => rgb(255, 255, 255),
        (Faction::Civil, _) => rgb(220, 226, 236),
        (Faction::Pirate, _) => C_RED,
        (Faction::Police, _) => C_BLUE,
        (Faction::Hunter, _) => rgb(255, 150, 60),
        (Faction::Alien, _) => rgb(180, 110, 255),
        (Faction::Neutral, Kind::Needle) => rgb(110, 255, 210),
        _ => C_DIM,
    }
}

impl Game {
    pub fn scene_size(&self) -> (usize, usize) {
        (self.scene.w, self.scene.h)
    }

    fn quality_scale(&self) -> f32 {
        match self.settings.quality {
            0 => 0.34,
            1 => 0.5,
            _ => 0.75,
        }
    }

    fn ensure_scene(&mut self, ow: usize, oh: usize, backdrop: bool) -> bool {
        // menu and station backdrops move slowly: draw them smaller
        let q = if backdrop { 0.34f32.min(self.quality_scale()) } else { self.quality_scale() };
        let mut sw = ((ow as f32 * q) as usize).clamp(256, 1280);
        // keep the aspect ratio of the output
        let sh = (sw * oh / ow.max(1)).clamp(144, 720);
        sw = sw.max(8) & !3;
        if self.scene.w != sw || self.scene.h != sh {
            self.scene.resize(sw, sh);
            return true;
        }
        false
    }

    fn view_orient(&self) -> Orient {
        let o = self.world.p.o;
        match self.view & 3 {
            0 => o,
            1 => Orient { r: -o.r, u: o.u, f: -o.f },
            2 => Orient { r: o.f, u: o.u, f: -o.r },
            _ => Orient { r: -o.f, u: o.u, f: o.r },
        }
    }

    pub fn showcase_camera(&self) -> Camera {
        let t = self.ui_t + self.world.t * 0.0;
        let focal = self.scene.h as f32 * 0.714;
        if let Some(st) = &self.world.station {
            let a = t * 0.06 + 0.4;
            let b = &st.base;
            let pos = st.pos + b.f * (1500.0 + 160.0 * sin(t * 0.21)) + b.r * (cos(a) * 1300.0) + b.u * (300.0 + sin(a * 1.3) * 500.0);
            let target = st.pos + b.f * 120.0;
            return Camera { pos, o: Orient::look(target - pos, b.u), focal };
        }
        Camera { pos: self.world.p.pos, o: self.world.p.o, focal }
    }

    pub fn flight_camera(&self) -> Camera {
        Camera { pos: self.world.p.pos, o: self.view_orient(), focal: self.scene.h as f32 * 0.714 }
    }

    fn draw_scene(&mut self, cam: &Camera) {
        let retro = self.settings.retro;
        let star = self.gal.sys[self.cmdr.system as usize].star;
        let w = &self.world;
        let light = Light { dir: w.light_dir, col: [star[0] * 0.85, star[1] * 0.82, star[2] * 0.80], amb: [0.20, 0.23, 0.30] };
        if retro {
            for p in self.scene.col.iter_mut() {
                *p = 0;
            }
            self.scene.clear_depth();
        } else {
            self.sky.draw(&mut self.scene, cam);
        }
        let sc = &mut self.scene;
        let green = rgb(80, 255, 140);
        // planet and sun, farther first
        let dp = (w.p.pos).len();
        let ds = (w.p.pos - w.sun_pos).len();
        let mut spin = Orient::ID;
        spin.rotate_axis(v3(0.0, 1.0, 0.0), w.planet_spin);
        for pass in 0..2 {
            let planet_first = dp > ds;
            let do_planet = (pass == 0) == planet_first;
            if do_planet {
                if w.has_planet {
                    if retro {
                        let c = cam.o.to_local(-cam.pos);
                        if c.z > NEAR {
                            let k = cam.focal / c.z;
                            let (sx, sy) = sc.to_screen(c, cam.focal);
                            let r = w.planet_r * k;
                            let mut prev = (sx + r, sy);
                            for i in 1..=64 {
                                let a = TAU * i as f32 / 64.0;
                                let p = (sx + r * cos(a), sy + r * sin(a));
                                sc.line_px(prev.0, prev.1, p.0, p.1, green, 160);
                                prev = p;
                            }
                        }
                    } else {
                        draw_planet(sc, cam, &self.ptex, V3::ZERO, w.planet_r, &spin, w.light_dir, light.col);
                    }
                }
            } else if !w.pocket {
                if retro {
                    let c = cam.o.to_local(w.sun_pos - cam.pos);
                    if c.z > NEAR {
                        let k = cam.focal / c.z;
                        let (sx, sy) = sc.to_screen(c, cam.focal);
                        let r = (w.sun_r * k).max(2.0);
                        let mut prev = (sx + r, sy);
                        for i in 1..=24 {
                            let a = TAU * i as f32 / 24.0;
                            let p = (sx + r * cos(a), sy + r * sin(a));
                            sc.line_px(prev.0, prev.1, p.0, p.1, rgb(255, 220, 90), 200);
                            prev = p;
                        }
                    }
                } else {
                    draw_sun(sc, cam, w.sun_pos, w.sun_r, star, self.ui_t);
                }
            }
        }
        // station
        if let Some(st) = &w.station {
            let fr = st.frame();
            if retro {
                draw_mesh_wire(sc, cam, &self.meshes[M::Station as usize], st.pos, &fr, 1.0, green, &mut self.tmp);
            } else {
                draw_mesh(sc, cam, &self.meshes[M::Station as usize], st.pos, &fr, 1.0, &light, 0.0, &mut self.tmp);
            }
        }
        // ships
        for s in &w.ships {
            let sp = spec(s.kind);
            let mut idx = sp.mesh as usize;
            let mut scale = sp.scale;
            if matches!(s.kind, Kind::Rock | Kind::Splinter) {
                idx = M::Rock0 as usize + (s.mesh_variant as usize % 3);
                if s.kind == Kind::Rock {
                    scale *= 0.8 + ((s.id * 37) % 10) as f32 * 0.07;
                }
            }
            if retro {
                draw_mesh_wire(sc, cam, &self.meshes[idx], s.pos, &s.o, scale, fac_color(s.fac, s.kind), &mut self.tmp);
            } else {
                draw_mesh(sc, cam, &self.meshes[idx], s.pos, &s.o, scale, &light, s.flash * 0.45, &mut self.tmp);
                if s.speed > 15.0 {
                    let mesh = &self.meshes[idx];
                    let col = if s.fac == Faction::Alien || s.kind == Kind::Needle { 0x40FFC8 } else { 0xFFA050 };
                    let k = clamp(0.35 + s.speed / sp.speed.max(100.0) * 0.6, 0.0, 1.0);
                    for (e, size) in &mesh.engines {
                        let wp = s.pos + s.o.to_world(*e * scale);
                        sc.glow(cam, wp, *size * scale * 1.6, col, k, 1.5);
                    }
                }
            }
        }
        // player ship seen in rear/side views? (cockpit view: not drawn)
        // beacon
        if let Some(b) = w.beacon {
            let pulse = 0.6 + 0.4 * sin(self.ui_t * 4.0);
            sc.glow(cam, b, 160.0, 0x40FFE0, pulse, 3.0);
            sc.glow(cam, b, 40.0, 0xFFFFFF, 1.0, 2.0);
        }
        // bolts
        let ps = sc.h as f32 / 360.0;
        for b in &w.bolts {
            let dir = b.vel.norm();
            let len = clamp(b.vel.len() * 0.022, 40.0, 150.0);
            sc.beam(cam, b.pos, b.pos - dir * len, b.col, 1.7 * ps, 0.95);
        }
        // particles
        for p in &w.parts {
            let t = clamp(p.life / p.max, 0.0, 1.0);
            match p.kind {
                PKind::Fire => {
                    let age = 1.0 - t;
                    let col = if age < 0.2 { 0xFFF0C0 } else if age < 0.5 { 0xFFA040 } else { 0xC03810 };
                    sc.glow(cam, p.pos, p.size * (0.35 + 0.65 * age), col, sqrt(t) * 0.95, 2.0);
                }
                PKind::Flash => sc.glow(cam, p.pos, p.size * (1.0 + (1.0 - t) * 0.4), p.col, t, 2.0),
                PKind::Spark => sc.glow(cam, p.pos, p.size, p.col, t, 1.2),
                PKind::Trail => sc.glow(cam, p.pos, p.size * (0.6 + 0.8 * (1.0 - t)), p.col, t * 0.55, 1.0),
                PKind::Debris => {
                    let sz = p.size * min(1.0, t * 3.0);
                    if sz > 0.3 && !retro {
                        let mut o = p.o;
                        o.orthonormalize();
                        draw_mesh(sc, cam, &self.meshes[M::Debris as usize], p.pos, &o, sz, &light, 0.0, &mut self.tmp);
                        if t > 0.5 {
                            sc.glow(cam, p.pos, sz * 1.5, 0xFF8030, (t - 0.5) * 0.8, 1.0);
                        }
                    }
                }
            }
        }
        // space dust streaks
        if !w.pocket || true {
            let sp = w.p.speed.max(w.p.jump_speed);
            let len = clamp(sp * 0.03, 2.0, 700.0);
            let dir = w.p.o.f;
            let kk = if w.p.jump_speed > 500.0 { 0.9 } else { 0.55 };
            for d in &w.dust {
                let a = w.p.pos + *d;
                sc.beam(cam, a, a - dir * len, 0xB0C8FF, 0.7 * ps, kk);
            }
        }
        if !retro && self.settings.bloom {
            self.scene.bloom(128, 300);
        }
        // hyperspace tunnel
        if let Some(h) = self.hyper {
            let total = if h.galaxy_jump { 5.0 } else if h.free { 3.0 } else { 4.0 };
            let k = clamp(1.0 - h.t / total, 0.0, 1.0);
            self.draw_tunnel(k, h.t);
        }
    }

    fn draw_tunnel(&mut self, k: f32, t: f32) {
        let sc = &mut self.scene;
        let (cx, cy) = (sc.w as f32 * 0.5, sc.h as f32 * 0.5);
        let maxr = sqrt(cx * cx + cy * cy);
        let tint = (k * k * 70.0) as u32;
        if tint > 0 {
            for p in sc.col.iter_mut() {
                *p = add_px(*p, 0x4070FF, tint);
            }
        }
        let mut rng = Rng::new(77);
        for i in 0..220 {
            let a = rng.f() * TAU;
            let base = rng.f();
            let ph = fract(base + t * (0.7 + k * 2.5) * -1.0 + i as f32 * 0.013);
            let r0 = ph * ph * maxr;
            let len = (4.0 + r0 * 0.55 * (0.2 + k * 1.2)).min(maxr);
            let (c, s) = (cos(a), sin(a));
            let col = if i % 5 == 0 { 0xFFFFFF } else { 0xA0C0FF };
            sc.line_px(cx + c * r0, cy + s * r0, cx + c * (r0 + len), cy + s * (r0 + len), col, (80.0 + 170.0 * k) as u32);
        }
        if k > 0.7 {
            let a = ((k - 0.7) / 0.3 * 230.0) as u32;
            for p in sc.col.iter_mut() {
                *p = add_px(*p, 0xFFFFFF, a);
            }
        }
    }

    fn blit(&self, out: &mut Canvas) {
        let sc = &self.scene;
        let (ow, oh) = (out.w, out.h);
        let step = ((sc.w as u64) << 16) / ow as u64;
        for y in 0..oh {
            let sy = (y * sc.h / oh).min(sc.h - 1);
            let src = &sc.col[sy * sc.w..(sy + 1) * sc.w];
            let dst = &mut out.px[y * ow..(y + 1) * ow];
            let mut fx: u64 = 0;
            for d in dst.iter_mut() {
                *d = src[((fx >> 16) as usize).min(sc.w - 1)];
                fx += step;
            }
        }
    }

    /// Render one frame into `out`.
    pub fn render(&mut self, out: &mut Canvas) {
        out.tr = self.tr_for_canvas();
        let ui = Ui::new(out.w, out.h);
        let flight_view = self.screen == Screen::Flight || (self.screen == Screen::Pause && !self.docked);
        let backdrop = !(flight_view && !self.docked);
        let resized = self.ensure_scene(out.w, out.h, backdrop);
        let cam = if !backdrop { self.flight_camera() } else { self.showcase_camera() };
        // a backdrop is redrawn every fourth frame; the interface on top is drawn every frame
        self.bd_frame = self.bd_frame.wrapping_add(1);
        if !backdrop || resized || self.bd_frame % 4 == 0 {
            self.draw_scene(&cam);
        }
        self.blit(out);
        if self.screen == Screen::Flight || (self.screen == Screen::Pause && !self.docked) {
            self.draw_hud(out, &ui, &cam);
        }
        self.draw_screen(out, &ui, &cam);
    }

    // ------------------------------------------------------------------ HUD

    fn project(&self, ow: usize, oh: usize, cam: &Camera, p: V3) -> Option<(f32, f32, f32)> {
        let c = cam.o.to_local(p - cam.pos);
        if c.z < 1.0 {
            return None;
        }
        let f = oh as f32 * 0.714;
        Some((ow as f32 * 0.5 + c.x * f / c.z, oh as f32 * 0.5 - c.y * f / c.z, c.z))
    }

    fn draw_hud(&self, c: &mut Canvas, ui: &Ui, cam: &Camera) {
        let w = &self.world;
        let p = &w.p;
        let (ow, oh) = (c.w as i32, c.h as i32);
        let (cx, cy) = (ow / 2, oh / 2);
        let fs = ui.fs;
        // damage vignette
        if p.hit_flash > 0.0 {
            let a = (p.hit_flash * 120.0) as u32;
            let e = ui.px(26.0);
            for i in 0..e {
                let k = a * (e - i) as u32 / e as u32 / 2;
                c.rect(0, i, ow, 1, C_RED, k);
                c.rect(0, oh - 1 - i, ow, 1, C_RED, k);
                c.rect(i, 0, 1, oh, C_RED, k);
                c.rect(ow - 1 - i, 0, 1, oh, C_RED, k);
            }
        }
        // crosshair (only meaningful in the front view)
        let r = ui.px(14.0) as f32;
        let ch = rgb(150, 230, 255);
        c.ring(cx as f32, cy as f32, r, 1.0, ch, 150);
        for (dx, dy) in [(1.0f32, 0.0f32), (-1.0, 0.0), (0.0, 1.0), (0.0, -1.0)] {
            c.line(cx as f32 + dx * (r + 3.0), cy as f32 + dy * (r + 3.0), cx as f32 + dx * (r + ui.px(8.0) as f32), cy as f32 + dy * (r + ui.px(8.0) as f32), ch, 160);
        }
        c.rect(cx - 1, cy - 1, 2, 2, ch, 200);
        // contact brackets
        let (cw_, ch_) = (c.w, c.h);
        let hudpos = |pos: V3| self.project(cw_, ch_, cam, pos);
        for s in &w.ships {
            if matches!(s.kind, Kind::Canister | Kind::Capsule | Kind::Splinter) && p.lock != s.id {
                continue;
            }
            let d = (s.pos - p.pos).len();
            if d > 9000.0 {
                continue;
            }
            let rad = spec(s.kind).radius;
            if let Some((sx, sy, z)) = hudpos(s.pos) {
                let f = oh as f32 * 0.714;
                let pr = (rad * f / z).max(ui.px(9.0) as f32) + 4.0;
                if sx < 0.0 || sy < 0.0 || sx > ow as f32 || sy > oh as f32 {
                    continue;
                }
                let col = fac_color(s.fac, s.kind);
                let locked = p.lock == s.id;
                let ar = if locked { 230 } else { 120 };
                let l = pr * 0.45;
                for (sx_, sy_) in [(-1.0f32, -1.0f32), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
                    let (bx, by) = (sx + sx_ * pr, sy + sy_ * pr);
                    c.line(bx, by, bx - sx_ * l, by, col, ar);
                    c.line(bx, by, bx, by - sy_ * l, col, ar);
                }
                if locked || s.kind == Kind::Brood {
                    let name = spec(s.kind).name;
                    c.text(sx as i32 - c.text_w(name, fs - 2) / 2, (sy + pr) as i32 + 3, fs - 2, name, col, 230);
                    let ds = format!("{} m", d as i32);
                    c.text(sx as i32 - c.text_w(&ds, fs - 2) / 2, (sy + pr) as i32 + 3 + fs, fs - 2, &ds, C_DIM, 230);
                }
                if locked {
                    // lock progress ring and lead marker
                    let prog = clamp(p.lock_t, 0.0, 1.0);
                    c.ring(sx, sy, pr + 5.0, 1.5, if prog >= 1.0 { C_RED } else { C_AMBER }, (120.0 + 100.0 * prog) as u32);
                    let tvel = s.o.f * s.speed + s.vel;
                    let lead = s.pos + tvel * (d / 2800.0);
                    if let Some((lx, ly, _)) = hudpos(lead) {
                        let q = ui.px(5.0) as f32;
                        c.line(lx - q, ly, lx, ly - q, C_AMBER, 220);
                        c.line(lx, ly - q, lx + q, ly, C_AMBER, 220);
                        c.line(lx + q, ly, lx, ly + q, C_AMBER, 220);
                        c.line(lx, ly + q, lx - q, ly, C_AMBER, 220);
                    }
                }
            } else if p.lock == s.id {
                // off-screen pointer to the lock
                let c_loc = cam.o.to_local(s.pos - cam.pos);
                let ang = atan2(-c_loc.y, c_loc.x);
                let rr = (oh as f32) * 0.42;
                let (px, py) = (cx as f32 + cos(ang) * rr, cy as f32 + sin(ang) * rr);
                c.disc(px, py, ui.px(4.0) as f32, C_AMBER, 220);
            }
        }
        // beacon marker and station / planet markers
        if let Some(b) = w.beacon {
            self.edge_marker(c, ui, cam, b, "BEACON", C_ACCENT);
        }
        // top left: one stack, objective first, then event log lines; long text wraps, nothing overlaps
        let cols = ((ow as f32 * 0.40) as i32 / (fs - 1)).max(20) as usize;
        let mut y = ui.px(12.0);
        let mut rows: alloc::vec::Vec<(String, u32, u32)> = alloc::vec::Vec::new();
        if let Some(o) = self.objective_text() {
            for (i, l) in wrap(&self.td(&o), cols - 4).into_iter().enumerate() {
                rows.push((if i == 0 { format!("> {}", l) } else { format!("  {}", l) }, C_ACCENT, 255));
            }
        }
        for l in self.log.iter().rev().take(4).collect::<alloc::vec::Vec<_>>().into_iter().rev() {
            let a = if l.age > 6.0 { ((9.0 - l.age) / 3.0 * 255.0) as u32 } else { 255 };
            for ln in wrap(&l.text, cols) {
                rows.push((ln, if l.warn { C_AMBER } else { C_TEXT }, a));
            }
        }
        for (t, col, a) in rows {
            c.rect(ui.px(10.0), y - 2, (t.chars().count() as i32 + 2) * (fs - 1), fs + 4, C_PANEL, a * 150 / 255);
            c.text(ui.px(14.0), y, fs - 1, &t, col, a);
            y += fs + 5;
        }
        // top right: system, legal, credits
        let sys = self.sys();
        let tx = ow - ui.px(14.0);
        c.text_r(tx, ui.px(12.0), fs, &sys.name, C_TEXT, 255);
        let (lt, lc) = match self.cmdr.legal() {
            Legal::Clean => ("CLEAN", C_GREEN),
            Legal::Offender => ("OFFENDER", C_AMBER),
            Legal::Fugitive => ("FUGITIVE", C_RED),
        };
        c.text_r(tx, ui.px(12.0) + fs + 4, fs - 1, lt, lc, 255);
        c.text_r(tx, ui.px(12.0) + (fs + 4) * 2, fs - 1, &format!("{} cr", self.cmdr.credits), C_DIM, 255);
        // locked target panel
        if let Some(s) = w.find(p.lock) {
            let pw = ui.px(190.0).max(fs * 17);
            let px = ow - pw - ui.px(12.0);
            let py = ui.px(12.0) + (fs + 4) * 3 + 6;
            let b1 = py + 6 + fs + 4;
            let b2 = b1 + fs + 2;
            let ty = b2 + fs + 4;
            panel(c, px, py, pw, ty + fs + 6 - py, 190);
            c.text(px + 8, py + 6, fs - 1, spec(s.kind).name, fac_color(s.fac, s.kind), 255);
            let shf = s.shield_f / s.shield_max.max(1.0);
            let enf = s.energy / s.energy_max.max(1.0);
            let lw = c.tl("Shield").chars().count().max(c.tl("Energy").chars().count()) as i32 * (fs - 2);
            self.meter(c, ui, px + 8, b1, pw - 16, lw, 0, "Shield", &format!("{}%", (shf * 100.0) as i32), shf, C_BLUE);
            self.meter(c, ui, px + 8, b2, pw - 16, lw, 1, "Energy", &format!("{}%", (enf * 100.0) as i32), enf, if enf < 0.3 { C_RED } else { C_GREEN });
            let d = (s.pos - p.pos).len();
            c.text(px + 8, ty, fs - 2, &format!("{} m", d as i32), C_DIM, 255);
            let st = if p.lock_t >= 1.0 { "LOCKED" } else { "LOCKING" };
            c.text_r(px + pw - 8, ty, fs - 2, st, if p.lock_t >= 1.0 { C_RED } else { C_AMBER }, 255);
        }
        self.draw_dock_guide(c, ui);
        // bottom instrument panel
        self.draw_panel(c, ui, cam);
        // centre warnings
        let mut wy = cy + ui.px(40.0);
        let warn = |c: &mut Canvas, t: &str, col: u32, wy: &mut i32| {
            c.text_c(cx, *wy, fs + 2, t, col, 255);
            *wy += fs + 8;
        };
        if let Some(h) = self.hyper {
            let t = format!("{}  {:.0}", self.t(if h.galaxy_jump { "GALACTIC DRIVE" } else { "JUMP DRIVE" }), floor(h.t + 0.999));
            c.text_c(cx, cy - ui.px(120.0), fs * 2, &t, rgb(180, 210, 255), 255);
        }
        if p.missile_warn && ((self.ui_t * 4.0) as i32 % 2 == 0) {
            warn(c, "MISSILE INCOMING - C TO RELEASE CHAFF", C_RED, &mut wy);
        }
        if p.cabin > 80.0 && ((self.ui_t * 3.0) as i32 % 2 == 0) {
            warn(c, "CABIN TEMPERATURE CRITICAL", C_RED, &mut wy);
        }
        if p.energy < p.energy_max * 0.25 && ((self.ui_t * 2.0) as i32 % 2 == 0) {
            warn(c, "ENERGY LOW", C_AMBER, &mut wy);
        }
        if p.dockcomp {
            warn(c, "DOCKING COMPUTER ENGAGED", C_ACCENT, &mut wy);
        }
        if w.pocket {
            warn(c, "DRIFT POCKET - PRESS H TO RE-ENTER", C_AMBER, &mut wy);
        }
        if self.dying > 0.0 {
            c.rect(0, 0, ow, oh, rgb(0, 0, 0), (clamp(1.0 - self.dying / 3.0, 0.0, 1.0) * 160.0) as u32);
            c.text_c(cx, cy - fs * 2, fs * 3, "SHIP DESTROYED", C_RED, 255);
        }
        if self.screen == Screen::Pause {
            c.rect(0, 0, ow, oh, rgb(0, 0, 0), 120);
        }
        let _ = (CYAN_UNUSED,);
    }

    /// One dashboard row: icon, label, bar, value.
    fn meter(&self, c: &mut Canvas, ui: &Ui, x: i32, y: i32, w: i32, lab_w: i32, ic: u8, label: &'static str, value: &str, frac: f32, col: u32) {
        let sl = (ui.fs - 2).max(7);
        let icon_w = sl + 4;
        self.icon(c, ic, x, y, sl, C_DIM);
        c.text(x + icon_w, y, sl, self.t(label), C_DIM, 255);
        let val_w = sl * 10;
        let bx = x + icon_w + lab_w + 6;
        let bw = w - (icon_w + lab_w + 6) - val_w - 6;
        let bh = ui.px(5.0).max(3);
        let by = y + sl / 2 - bh / 2;
        c.rect(bx, by, bw, bh, rgb(24, 32, 46), 255);
        let f = clamp(frac, 0.0, 1.0);
        c.rect(bx, by, (bw as f32 * f) as i32, bh, col, 255);
        c.rect(bx, by + bh - 1, (bw as f32 * f) as i32, 1, scale_col(col, 0.6), 255);
        c.text_r(x + w, y, sl, value, if col == C_RED { C_RED } else if col == C_AMBER { C_AMBER } else { C_TEXT }, 255);
    }

    /// Small vector icons for the dashboard rows.
    pub(crate) fn icon(&self, c: &mut Canvas, kind: u8, x: i32, y: i32, s: i32, col: u32) {
        let (x, y, s) = (x as f32, y as f32, s as f32);
        match kind {
            0 => {
                // shield
                c.line(x, y, x + s, y, col, 230);
                c.line(x, y, x, y + s * 0.5, col, 230);
                c.line(x + s, y, x + s, y + s * 0.5, col, 230);
                c.line(x, y + s * 0.5, x + s * 0.5, y + s, col, 230);
                c.line(x + s, y + s * 0.5, x + s * 0.5, y + s, col, 230);
            }
            1 => {
                // energy bolt
                c.line(x + s * 0.7, y, x + s * 0.2, y + s * 0.55, col, 230);
                c.line(x + s * 0.2, y + s * 0.55, x + s * 0.8, y + s * 0.5, col, 230);
                c.line(x + s * 0.8, y + s * 0.5, x + s * 0.3, y + s, col, 230);
            }
            2 => {
                // fuel drop
                c.line(x + s * 0.5, y, x + s * 0.15, y + s * 0.6, col, 230);
                c.line(x + s * 0.5, y, x + s * 0.85, y + s * 0.6, col, 230);
                c.ring(x + s * 0.5, y + s * 0.65, s * 0.35, 1.0, col, 230);
            }
            3 | 4 => {
                // thermometer (laser: with a spark)
                c.line(x + s * 0.4, y, x + s * 0.4, y + s * 0.7, col, 230);
                c.disc(x + s * 0.4, y + s * 0.8, s * 0.22, col, 230);
                if kind == 4 {
                    c.line(x + s * 0.7, y + s * 0.2, x + s, y, col, 230);
                    c.line(x + s * 0.7, y + s * 0.4, x + s, y + s * 0.4, col, 230);
                }
            }
            5 => {
                // altitude: mountain
                c.line(x, y + s, x + s * 0.4, y + s * 0.2, col, 230);
                c.line(x + s * 0.4, y + s * 0.2, x + s * 0.7, y + s * 0.6, col, 230);
                c.line(x + s * 0.7, y + s * 0.6, x + s, y + s, col, 230);
            }
            6 => {
                // speed: gauge
                c.line(x, y + s, x + s, y + s, col, 230);
                c.line(x + s * 0.5, y + s, x + s * 0.85, y + s * 0.25, col, 230);
                c.ring(x + s * 0.5, y + s, s * 0.5, 1.0, col, 200);
            }
            7 => {
                // throttle: lever
                c.line(x + s * 0.5, y, x + s * 0.5, y + s, col, 230);
                c.line(x + s * 0.2, y + s * 0.3, x + s * 0.8, y + s * 0.3, col, 230);
            }
            8 => {
                // roll: tilted wings
                c.line(x, y + s * 0.8, x + s, y + s * 0.2, col, 230);
                c.disc(x + s * 0.5, y + s * 0.5, s * 0.16, col, 230);
            }
            9 => {
                // pitch: nose-up arrow
                c.line(x + s * 0.5, y, x + s * 0.5, y + s, col, 230);
                c.line(x + s * 0.5, y, x + s * 0.15, y + s * 0.4, col, 230);
                c.line(x + s * 0.5, y, x + s * 0.85, y + s * 0.4, col, 230);
            }
            _ => {
                // missile
                c.line(x + s * 0.5, y, x + s * 0.5, y + s, col, 230);
                c.line(x + s * 0.5, y, x + s * 0.3, y + s * 0.3, col, 230);
                c.line(x + s * 0.5, y, x + s * 0.7, y + s * 0.3, col, 230);
                c.line(x + s * 0.2, y + s, x + s * 0.8, y + s, col, 230);
            }
        }
    }

    /// Guidance for a manual approach: path marker, roll hint, distance and speed.
    fn draw_dock_guide(&self, c: &mut Canvas, ui: &Ui) {
        let w = &self.world;
        let (sp, fr) = match w.station_frame() {
            Some(x) => x,
            None => return,
        };
        let p = &w.p;
        let loc = fr.to_local(p.pos - sp);
        if loc.z < STATION_HALF_LEN - 20.0 || loc.z > 4500.0 || w.pocket {
            return;
        }
        let fs = ui.fs;
        let box_h = ui.px(96.0);
        let pw = ui.px(176.0).max(fs * 15);
        let ph = 8 + fs + 6 + box_h + 6 + (fs + 3) * 3 + 8;
        let px = ui.px(12.0);
        let py = c.h as i32 / 2 - ph / 2;
        panel(c, px, py, pw, ph, 205);
        c.text(px + 8, py + 8, fs - 1, self.t("DOCKING GUIDE"), C_ACCENT, 255);
        let (bx, by) = (px + 8, py + 8 + fs + 6);
        let bw = pw - 16;
        c.rect(bx, by, bw, box_h, rgb(8, 12, 18), 255);
        c.rect_outline(bx, by, bw, box_h, 1, C_BORDER, 255);
        let (cx, cy) = ((bx + bw / 2) as f32, (by + box_h / 2) as f32);
        // the nose (fixed, centre) and the ideal flight path (pip)
        let lat = fr.r * loc.x + fr.u * loc.y;
        let ahead = loc.z - STATION_HALF_LEN;
        let gain = clamp(ahead / 800.0, 0.0, 1.0) * 0.9 + 0.6;
        let aim = if ahead > 1300.0 { (sp + fr.f * (STATION_HALF_LEN + 300.0) - p.pos).norm() } else { (-fr.f * 80.0 - lat * 1.5 * gain).norm() };
        let al = p.o.to_local(aim);
        let kk = (box_h as f32 * 0.5 - 6.0) / 0.5;
        let lim = box_h as f32 * 0.5 - 5.0;
        let (qx, qy) = (clamp(al.x * kk, -lim, lim), clamp(-al.y * kk, -lim, lim));
        c.ring(cx, cy, ui.px(5.0) as f32, 1.0, C_TEXT, 220);
        c.line(cx - ui.px(9.0) as f32, cy, cx + ui.px(9.0) as f32, cy, C_DIM, 160);
        c.line(cx, cy - ui.px(9.0) as f32, cx, cy + ui.px(9.0) as f32, C_DIM, 160);
        let near = abs(al.x) < 0.04 && abs(al.y) < 0.04;
        let pc = if near { C_GREEN } else { C_AMBER };
        c.line(cx, cy, cx + qx, cy + qy, scale_col(pc, 0.6), 160);
        let r = ui.px(4.0) as f32;
        c.line(cx + qx - r, cy + qy, cx + qx, cy + qy - r, pc, 255);
        c.line(cx + qx, cy + qy - r, cx + qx + r, cy + qy, pc, 255);
        c.line(cx + qx + r, cy + qy, cx + qx, cy + qy + r, pc, 255);
        c.line(cx + qx, cy + qy + r, cx + qx - r, cy + qy, pc, 255);
        // roll: match the slot, either way up
        let sr = fr.to_local(p.o.r);
        let mut err = atan2(sr.y, sr.x);
        if err > PI / 2.0 {
            err -= PI;
        } else if err < -PI / 2.0 {
            err += PI;
        }
        let need = err * if p.o.f.dot(fr.f) < 0.0 { -1.0 } else { 1.0 };
        let (rt, rc) = if need > 0.12 {
            (self.t("ROLL RIGHT >>"), C_AMBER)
        } else if need < -0.12 {
            (self.t("<< ROLL LEFT"), C_AMBER)
        } else {
            (self.t("ROLL OK"), C_GREEN)
        };
        let mut y = by + box_h + 6;
        c.text(px + 8, y, fs - 1, rt, rc, 255);
        y += fs + 3;
        let spd = p.speed;
        let sc = if spd > DOCK_MAX_SPEED { C_RED } else { C_GREEN };
        c.text(px + 8, y, fs - 2, &format!("{} {:.0}/{:.0}", self.t("SPEED"), spd, DOCK_MAX_SPEED), sc, 255);
        y += fs + 3;
        c.text(px + 8, y, fs - 2, &format!("{} {:.0} m", self.t("DIST"), max(ahead, 0.0)), C_DIM, 255);
    }

    fn edge_marker(&self, c: &mut Canvas, ui: &Ui, cam: &Camera, pos: V3, label: &str, col: u32) {
        let (ow, oh) = (c.w as f32, c.h as f32);
        let lc = cam.o.to_local(pos - cam.pos);
        let f = oh * 0.714;
        if lc.z > 1.0 {
            let (sx, sy) = (ow * 0.5 + lc.x * f / lc.z, oh * 0.5 - lc.y * f / lc.z);
            if sx > 20.0 && sx < ow - 20.0 && sy > 20.0 && sy < oh - 20.0 {
                let q = ui.px(9.0) as f32;
                c.ring(sx, sy, q, 1.5, col, 230);
                let d = format!("{} {}", label, lc.len() as i32);
                c.text_c(sx as i32, (sy + q + 3.0) as i32, ui.fs - 2, &d, col, 220);
                return;
            }
        }
        let ang = atan2(-lc.y, lc.x);
        let rr = oh * 0.40;
        let (px, py) = (ow * 0.5 + cos(ang) * rr, oh * 0.5 + sin(ang) * rr);
        c.disc(px, py, ui.px(4.0) as f32, col, 230);
        c.text_c(px as i32, py as i32 + ui.px(6.0), ui.fs - 2, label, col, 200);
    }

    fn draw_panel(&self, c: &mut Canvas, ui: &Ui, cam: &Camera) {
        let w = &self.world;
        let p = &w.p;
        let (ow, oh) = (c.w as i32, c.h as i32);
        let fs = ui.fs;
        let ph = ui.px(124.0);
        let pw = ((ow as f32 * 0.94) as i32).min(ui.px(1100.0));
        let px = (ow - pw) / 2;
        let py = oh - ph - ui.px(8.0);
        panel(c, px, py, pw, ph, 175);
        // scanner in the middle
        let scx = px + pw / 2;
        let scy = py + ph - ui.px(34.0);
        let rx = ui.px(122.0) as f32;
        let ry = ui.px(40.0) as f32;
        for k in [1.0f32, 0.66, 0.33] {
            c.ellipse(scx as f32, scy as f32, rx * k, ry * k, rgb(40, 110, 120), 150);
        }
        c.line(scx as f32 - rx, scy as f32, scx as f32 + rx, scy as f32, rgb(34, 80, 92), 120);
        c.line(scx as f32, scy as f32 - ry, scx as f32, scy as f32 + ry, rgb(34, 80, 92), 120);
        c.disc(scx as f32, scy as f32, 2.5, C_ACCENT, 255); // you
        let o = &p.o;
        let mut contacts: alloc::vec::Vec<(f32, f32, f32, u32, f32)> = alloc::vec::Vec::new();
        for s in &w.ships {
            let rel = o.to_local(s.pos - p.pos);
            if rel.len() > SCANNER_RANGE {
                continue;
            }
            let r = spec(s.kind).radius;
            contacts.push((rel.x, rel.y, rel.z, fac_color(s.fac, s.kind), r));
        }
        if let Some((sp, _)) = w.station_frame() {
            let rel = o.to_local(sp - p.pos);
            let l = rel.len();
            let k = if l > SCANNER_RANGE { SCANNER_RANGE / l } else { 1.0 };
            contacts.push((rel.x * k, rel.y * k, rel.z * k, C_GREEN, 600.0));
        }
        // draw far-to-near by depth so sticks overlap sensibly
        for (x, y, z, col, r) in contacts {
            let ex = scx as f32 + x / SCANNER_RANGE * rx;
            let ey = scy as f32 - z / SCANNER_RANGE * ry;
            let hy = ey - y / SCANNER_RANGE * ry * 1.6;
            c.line(ex, ey, ex, hy, col, 130);
            let sz = if r > 300.0 { 3.2 } else if r > 60.0 { 2.4 } else { 1.7 };
            c.disc(ex, hy, sz, col, 255);
        }
        // dashboard: readable labels, icons, numeric values, colours that warn
        let sl = (fs - 2).max(7);
        let icon_w = sl + 4;
        let val_w = sl * 10;
        let cluster_w = pw / 2 - rx as i32 - ui.px(26.0);
        let dy = ui.px(14.5);
        let good = |f: f32, ok: u32| if f < 0.25 { C_RED } else if f < 0.5 { C_AMBER } else { ok };
        let hot = |f: f32, ok: u32| if f > 0.85 { C_RED } else if f > 0.6 { C_AMBER } else { ok };
        let sfrac = |s: f32| s / p.shield_max.max(1.0);
        let alt = w.altitude();
        let alt_s = if alt >= 10000.0 { format!("{:.1} km", alt / 1000.0) } else { format!("{} m", alt as i32) };
        let ls = (self.view & 3) as usize;
        let left: [(u8, &'static str, String, f32, u32); 7] = [
            (0, "Shield fwd", format!("{}%", (sfrac(p.shield_f) * 100.0) as i32), sfrac(p.shield_f), good(sfrac(p.shield_f), C_BLUE)),
            (0, "Shield aft", format!("{}%", (sfrac(p.shield_a) * 100.0) as i32), sfrac(p.shield_a), good(sfrac(p.shield_a), C_BLUE)),
            (1, "Energy", format!("{}%", (p.energy / p.energy_max * 100.0) as i32), p.energy / p.energy_max, good(p.energy / p.energy_max, C_GREEN)),
            (2, "Fuel", format!("{:.1} LY", self.cmdr.fuel as f32 / 10.0), self.cmdr.fuel as f32 / MAX_FUEL_TENTHS as f32, {
                let f = self.cmdr.fuel as f32 / MAX_FUEL_TENTHS as f32;
                if f < 0.15 { C_RED } else if f < 0.3 { C_AMBER } else { rgb(236, 206, 96) }
            }),
            (3, "Cabin temp", format!("{}%", (p.cabin / 140.0 * 100.0) as i32), p.cabin / 140.0, hot(p.cabin / 140.0, rgb(96, 200, 190))),
            (4, "Laser temp", format!("{}%", p.laser_heat[ls] as i32), p.laser_heat[ls] / 100.0, if p.overheated[ls] { C_RED } else { hot(p.laser_heat[ls] / 100.0, rgb(96, 200, 190)) }),
            (5, "Altitude", alt_s, clamp(alt / 40000.0, 0.0, 1.0), C_DIM),
        ];
        let lab_w = left.iter().map(|r| c.tl(r.1).chars().count() as i32).max().unwrap_or(8) * sl;
        let lx = px + ui.px(12.0);
        let mut y = py + ui.px(12.0);
        for (ic, label, val, f, col) in left.iter() {
            self.meter(c, ui, lx, y, cluster_w, lab_w, *ic, label, val, *f, *col);
            y += dy;
        }
        // right cluster
        let spd = p.speed.max(p.jump_speed);
        let rxx = px + pw / 2 + rx as i32 + ui.px(20.0);
        let rw = px + pw - ui.px(12.0) - rxx;
        let rlabels = ["Speed", "Throttle", "Roll", "Pitch", "Missiles"];
        let rlab_w = rlabels.iter().map(|s| c.tl(s).chars().count() as i32).max().unwrap_or(8) * sl;
        let mut y = py + ui.px(12.0);
        self.meter(c, ui, rxx, y, rw, rlab_w, 6, "Speed", &format!("{} m/s", spd as i32), spd / PLAYER_MAX_SPEED, C_ACCENT);
        y += dy;
        self.meter(c, ui, rxx, y, rw, rlab_w, 7, "Throttle", &format!("{}%", (p.throttle * 100.0) as i32), p.throttle, rgb(110, 170, 220));
        y += dy;
        for (ic, label, v) in [(8u8, "Roll", p.roll_r), (9u8, "Pitch", p.pitch_r)] {
            self.icon(c, ic, rxx, y, sl, C_DIM);
            c.text(rxx + icon_w, y, sl, self.t(label), C_DIM, 255);
            let bx = rxx + icon_w + rlab_w + 6;
            let bw = rw - (icon_w + rlab_w + 6) - val_w - 6;
            let bh = ui.px(5.0).max(3);
            let by = y + sl / 2 - bh / 2;
            c.rect(bx, by, bw, bh, rgb(24, 32, 46), 255);
            c.rect(bx + bw / 2 - 1, by - 2, 2, bh + 4, C_DIM, 255);
            c.rect(bx + bw / 2 + (v * bw as f32 * 0.5) as i32 - 2, by - 1, 4, bh + 2, C_ACCENT, 255);
            c.text_r(rxx + rw, y, sl, &format!("{:+}%", (v * 100.0) as i32), C_TEXT, 255);
            y += dy;
        }
        // missiles
        self.icon(c, 10, rxx, y, sl, C_DIM);
        c.text(rxx + icon_w, y, sl, self.t("Missiles"), C_DIM, 255);
        let mx = rxx + icon_w + rlab_w + 6;
        for i in 0..MISSILE_MAX as i32 {
            let on = i < self.cmdr.missiles as i32;
            let col = if on { if p.lock_t >= 1.0 && p.lock != 0 { C_RED } else { C_GREEN } } else { rgb(40, 50, 66) };
            let x0 = (mx + i * (sl + 6)) as f32;
            let s = sl as f32;
            c.line(x0, y as f32 + s, x0 + s * 0.5, y as f32, col, 255);
            c.line(x0 + s * 0.5, y as f32, x0 + s, y as f32 + s, col, 255);
            c.line(x0, y as f32 + s, x0 + s, y as f32 + s, col, 255);
        }
        c.text_r(rxx + rw, y, sl, &format!("{}/{}", self.cmdr.missiles, MISSILE_MAX), C_TEXT, 255);
        y += dy;
        // flags
        let locked = w.mass_locked();
        let mut fx = rxx;
        let flag = |c: &mut Canvas, x: &mut i32, t: &str, on: bool, col: u32| {
            c.text(*x, y, fs - 2, t, if on { col } else { rgb(44, 56, 76) }, 255);
            *x += (c.tl(t).chars().count() as i32 + 1) * (fs - 2);
        };
        flag(c, &mut fx, "MASS", locked, C_AMBER);
        flag(c, &mut fx, "JUMP", p.jump_speed > 100.0, C_ACCENT);
        flag(c, &mut fx, "DOCK", p.dockcomp, C_ACCENT);
        // tutorial: highlight the dashboard while its step is active
        if self.tut.as_ref().map_or(false, |t| t.step == crate::tutorial::STEP_DASHBOARD) {
            let a = (160.0 + 90.0 * sin(self.ui_t * 5.0)) as u32;
            c.rect_outline(px - 3, py - 3, pw + 6, ph + 6, 2, C_ACCENT, a);
        }
        // compass
        let cc = (px + pw / 2 + rx as i32 + ui.px(6.0) - ui.px(6.0), py + ph - ui.px(44.0));
        let _ = cc;
        let ccx = px + pw / 2 - rx as i32 - ui.px(0.0);
        let _ = ccx;
        let comp_r = ui.px(20.0) as f32;
        let comp_c = (px + pw / 2 + rx as i32 + ui.px(-4.0) + 0, py + ph - ui.px(36.0));
        let _ = comp_c;
        // place the compass just right of the scanner, above the flags
        let (cpx, cpy) = (scx as f32 + rx + comp_r + ui.px(6.0) as f32 - 0.0, py as f32 + ph as f32 - comp_r - ui.px(22.0) as f32);
        let _ = (cpx, cpy);
        let tgt = if let Some((sp, _)) = w.station_frame() {
            if (sp - p.pos).len() < 40000.0 {
                Some((sp, "ST"))
            } else if w.has_planet {
                Some((V3::ZERO, "PL"))
            } else {
                None
            }
        } else {
            None
        };
        let cxc = scx as f32 - rx - comp_r - ui.px(8.0) as f32;
        let cyc = scy as f32 - ui.px(4.0) as f32;
        let _ = (cxc, cyc);
        let (kx, ky) = (px as f32 + pw as f32 * 0.5, py as f32);
        let _ = (kx, ky);
        // compass sits on the panel's top edge, centred
        let (ccx, ccy) = (scx as f32, (py - ui.px(0.0)) as f32 - comp_r - ui.px(4.0) as f32);
        c.disc(ccx, ccy, comp_r + 2.0, C_PANEL, 190);
        c.ring(ccx, ccy, comp_r, 1.0, C_BORDER, 255);
        if let Some((pos, lab)) = tgt {
            let l = o.to_local((pos - p.pos).norm());
            let (dx, dy2) = (l.x, -l.y);
            let m = sqrt(dx * dx + dy2 * dy2).max(0.0001);
            let k = min(1.0, m / 0.7) * (comp_r - 4.0);
            let (dxn, dyn_) = (dx / m * k, dy2 / m * k);
            if l.z > 0.0 {
                c.disc(ccx + dxn, ccy + dyn_, 3.2, C_GREEN, 255);
            } else {
                c.ring(ccx + dxn, ccy + dyn_, 3.2, 1.2, C_GREEN, 255);
            }
            c.text_r((ccx - comp_r) as i32 - 6, ccy as i32 - fs / 2, fs - 2, lab, C_DIM, 255);
        }
        let _ = cam;
    }
}

const CYAN_UNUSED: u32 = 0;
