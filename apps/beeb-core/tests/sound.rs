// SPDX-License-Identifier: AGPL-3.0-only
//! Sound tests. `chip_*` run always. `boot_audio` is ignored and needs user-supplied ROMs:
//!   BEEB_MOS=<os12.rom> [BEEB_BASIC=<basic.rom>] [BEEB_SSD=<disc.ssd>] [BEEB_SHIFT_BREAK=1]
//!   [BEEB_FRAMES=600] [BEEB_KEYS="120:Space:d,125:Space:u"] [BEEB_WAV=<out.wav>]
//! It prints RMS and zero-crossing frequency per 25-frame window and writes the WAV.
use beeb_core::keyboard::Key;
use beeb_core::machine::Beeb;
use beeb_core::sound::Sound;

fn wav(path: &str, rate: u32, s: &[i16]) {
    let mut o = Vec::new();
    let n = (s.len() * 2) as u32;
    o.extend_from_slice(b"RIFF");
    o.extend_from_slice(&(36 + n).to_le_bytes());
    o.extend_from_slice(b"WAVEfmt ");
    o.extend_from_slice(&16u32.to_le_bytes());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&rate.to_le_bytes());
    o.extend_from_slice(&(rate * 2).to_le_bytes());
    o.extend_from_slice(&2u16.to_le_bytes());
    o.extend_from_slice(&16u16.to_le_bytes());
    o.extend_from_slice(b"data");
    o.extend_from_slice(&n.to_le_bytes());
    for v in s { o.extend_from_slice(&v.to_le_bytes()); }
    std::fs::write(path, o).unwrap();
}

fn crossings(s: &[i16]) -> usize {
    let mut n = 0;
    let mut prev = 0i32;
    for &v in s {
        let v = v as i32;
        if prev < 0 && v >= 0 { n += 1; }
        if v != 0 { prev = v; }
    }
    n
}

fn rms(s: &[i16]) -> f64 {
    if s.is_empty() { return 0.0; }
    (s.iter().map(|&v| (v as f64) * (v as f64)).sum::<f64>() / s.len() as f64).sqrt()
}

fn render(snd: &mut Sound, cpu_cycles: u32) -> Vec<i16> {
    let mut acc = 0;
    for _ in 0..cpu_cycles / 100 { snd.advance(&mut acc, 100); }
    snd.drain().to_vec()
}

#[test]
fn chip_tone_frequency() {
    let mut s = Sound::new();
    // channel 0 period 284 -> 250000 / (2 * 284) = 440 Hz, full volume
    s.write(0x80 | (284 & 15) as u8);
    s.write((284 >> 4) as u8);
    s.write(0x90);
    let a = render(&mut s, 2_000_000);
    assert_eq!(a.len(), 48_000);
    let f = crossings(&a[4800..]) as f64 / 0.9;
    assert!((f - 440.0).abs() < 5.0, "f={}", f);
    assert!(rms(&a) > 1000.0);
}

#[test]
fn chip_attenuation_and_off() {
    let mut s = Sound::new();
    s.write(0x80 | 4);
    s.write(0x10);
    s.write(0x90);
    let loud = rms(&render(&mut s, 400_000));
    s.write(0x90 | 5);
    let quiet = rms(&render(&mut s, 400_000));
    assert!(quiet < loud * 0.45 && quiet > loud * 0.2, "{} {}", loud, quiet);
    s.write(0x9F);
    let off = render(&mut s, 400_000);
    assert!(rms(&off[2000..]) < 5.0);
}

#[test]
fn chip_noise() {
    let mut s = Sound::new();
    s.write(0xE4);
    s.write(0xF0);
    let a = render(&mut s, 400_000);
    assert!(rms(&a) > 500.0);
}

fn key_named(n: &str) -> Key {
    let all = [
        Key::Shift, Key::Ctrl, Key::Escape, Key::A, Key::B, Key::C, Key::D, Key::E, Key::F, Key::G, Key::H,
        Key::I, Key::J, Key::K, Key::L, Key::M, Key::N, Key::O, Key::P, Key::Q, Key::R, Key::S, Key::T, Key::U,
        Key::V, Key::W, Key::X, Key::Y, Key::Z, Key::D0, Key::D1, Key::D2, Key::D3, Key::D4, Key::D5, Key::D6,
        Key::D7, Key::D8, Key::D9, Key::F0, Key::F1, Key::F2, Key::F3, Key::F4, Key::F5, Key::F6, Key::F7,
        Key::F8, Key::F9, Key::Space, Key::Left, Key::Right, Key::Up, Key::Down, Key::Return, Key::Tab,
        Key::Slash, Key::Period, Key::Comma,
    ];
    *all.iter().find(|k| format!("{:?}", k).eq_ignore_ascii_case(n)).unwrap_or_else(|| panic!("unknown key {}", n))
}

#[test]
#[ignore]
fn boot_audio() {
    let Ok(mos) = std::env::var("BEEB_MOS") else { return };
    let frames: usize = std::env::var("BEEB_FRAMES").ok().and_then(|v| v.parse().ok()).unwrap_or(600);
    let mut keys: Vec<(usize, Key, bool)> = Vec::new();
    for e in std::env::var("BEEB_KEYS").unwrap_or_default().split(',').filter(|e| !e.is_empty()) {
        let p: Vec<&str> = e.split(':').collect();
        keys.push((p[0].parse().unwrap(), key_named(p[1]), p[2] == "d"));
    }
    let mut b = Beeb::new(&std::fs::read(mos).unwrap());
    if let Ok(r) = std::env::var("BEEB_BASIC") { b.insert_rom(15, &std::fs::read(r).unwrap()); }
    if let Ok(d) = std::env::var("BEEB_SSD") { b.insert_disc(std::fs::read(d).unwrap()); }
    b.reset(std::env::var("BEEB_SHIFT_BREAK").is_ok());
    let mut all: Vec<i16> = Vec::new();
    for f in 1..=frames {
        for &(kf, k, d) in &keys { if kf == f { b.key(k, d); } }
        b.run_frame();
        let a = b.audio();
        all.extend_from_slice(a);
    }
    let win: usize = std::env::var("BEEB_WIN").ok().and_then(|v| v.parse().ok()).unwrap_or(25);
    let w = win * 960;
    for (i, c) in all.chunks(w).enumerate() {
        let r = rms(c);
        if r < 1.0 { continue; }
        let f = crossings(c) as f64 * 48000.0 / c.len() as f64;
        let (lo, hi) = (c.iter().min().unwrap(), c.iter().max().unwrap());
        eprintln!("frames {:4}-{:4}: rms {:7.1} zc-freq {:7.1} Hz range {}..{}", i * win, i * win + win, r, f, lo, hi);
    }
    eprintln!("total samples {} ({} per frame)", all.len(), all.len() / frames);
    assert!(all.iter().any(|&v| v.unsigned_abs() > 500), "audio is silent");
    if let Ok(p) = std::env::var("BEEB_WAV") { wav(&p, 48000, &all); }
}
