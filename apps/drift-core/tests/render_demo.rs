// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
mod common;
use drift_core::gfx::*;
use drift_core::math::*;
use drift_core::models::*;
use drift_core::raster::*;
use drift_core::space::*;

#[test]
fn render_scene() {
    let meshes = build_all();
    let (w, h) = (960usize, 540usize);
    let mut sc = Scene::new(w, h);
    let mut sky = Sky::generate(42);
    let tex = PlanetTex::generate(7, PlanetKind::Ocean, 192, 0.8);
    let cam = Camera { pos: v3(0.0, 0.0, -2500.0), o: Orient::look(v3(0.2, 0.0, 1.0), v3(0.0, 1.0, 0.0)), focal: 540.0 / (2.0 * 0.7) };
    let light = Light { dir: v3(0.7, 0.3, -0.4).norm(), col: [1.0, 0.95, 0.85], amb: [0.10, 0.12, 0.18] };
    let t0 = std::time::Instant::now();
    sky.draw(&mut sc, &cam);
    let t1 = t0.elapsed();
    draw_sun(&mut sc, &cam, v3(60000.0, 20000.0, 120000.0), 9000.0, [1.0, 0.85, 0.55], 0.0);
    let spin = Orient::ID;
    draw_planet(&mut sc, &cam, &tex, v3(2500.0, -5200.0, 9000.0), 6000.0, &spin, light.dir, light.col);
    let t2 = t0.elapsed();
    let mut tmp = Vec::new();
    let st = Orient::look(v3(0.2, 0.1, -1.0), v3(0.0, 1.0, 0.0));
    draw_mesh(&mut sc, &cam, &meshes[M::Station as usize], v3(0.0, 0.0, 1800.0), &st, 1.0, &light, 0.0, &mut tmp);
    let ships = [M::Tern, M::Gull, M::Pelican, M::Jackal, M::Hyena, M::Warden, M::Hound, M::Needle, M::Husk, M::Rock1];
    for (i, m) in ships.iter().enumerate() {
        let o = Orient::look(v3(0.3 * (i as f32 - 4.0), 0.1, 1.0), v3(0.2, 1.0, 0.0));
        let pos = v3(-700.0 + (i % 5) as f32 * 340.0, -200.0 + (i / 5) as f32 * 320.0, -1500.0);
        draw_mesh(&mut sc, &cam, &meshes[*m as usize], pos, &o, if *m == M::Rock1 { 2.0 } else { 1.5 }, &light, 0.0, &mut tmp);
    }
    let t3 = t0.elapsed();
    sc.bloom(140, 256);
    let t4 = t0.elapsed();
    println!("sky {:?} sun+planet {:?} meshes {:?} bloom {:?}", t1, t2 - t1, t3 - t2, t4 - t3);
    common::save_ppm("render_demo", w, h, &sc.col);
    let mut c = Canvas::new(400, 100);
    c.clear(rgb(10, 12, 18));
    c.text(10, 10, 16, "SHIELD FORE 100% AFT 87%  Credits 1234.5", rgb(220, 230, 240), 255);
    c.text(10, 40, 32, "Smooth Text 0123", rgb(70, 210, 200), 255);
    c.ring(350.0, 60.0, 30.0, 3.0, rgb(255, 180, 60), 255);
    common::save_ppm("text_demo", 400, 100, &c.px);
}
