// SPDX-License-Identifier: AGPL-3.0-only
//! Ignored integration test: boots a user-supplied MOS (and optional disc / BASIC ROM), runs
//! frames, writes PNG screenshots.
//!   BEEB_MOS=<os12.rom> [BEEB_SSD=<disc.ssd>] [BEEB_BASIC=<basic.rom>] [BEEB_OUT=<dir>]
//!   [BEEB_FRAMES=300] [BEEB_SHOTS=100,200] [BEEB_SHIFT_BREAK=1]
//!   [BEEB_KEYS="120:Space:d,125:Space:u"]   (frame:KeyDebugName:d|u, key names = keyboard::Key)
use beeb_core::keyboard::Key;
use beeb_core::machine::{Beeb, SCREEN_H, SCREEN_W};
use std::path::Path;

fn crc32(d: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in d {
        c ^= b as u32;
        for _ in 0..8 { c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 }; }
    }
    !c
}

fn png(path: &Path, px: &[u32]) {
    let mut raw = Vec::new();
    for y in 0..SCREEN_H {
        raw.push(0);
        for x in 0..SCREEN_W {
            let p = px[y * SCREEN_W + x];
            raw.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, p as u8]);
        }
    }
    let mut z = vec![0x78, 0x01];
    let mut i = 0;
    while i < raw.len() {
        let n = (raw.len() - i).min(65535);
        z.push(if i + n == raw.len() { 1 } else { 0 });
        z.extend_from_slice(&(n as u16).to_le_bytes());
        z.extend_from_slice(&(!(n as u16)).to_le_bytes());
        z.extend_from_slice(&raw[i..i + n]);
        i += n;
    }
    let (mut a, mut b) = (1u32, 0u32);
    for &v in &raw { a = (a + v as u32) % 65521; b = (b + a) % 65521; }
    z.extend_from_slice(&((b << 16) | a).to_be_bytes());
    let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut chunk = |t: &[u8; 4], d: &[u8]| {
        out.extend_from_slice(&(d.len() as u32).to_be_bytes());
        let mut c = t.to_vec();
        c.extend_from_slice(d);
        out.extend_from_slice(&c);
        out.extend_from_slice(&crc32(&c).to_be_bytes());
    };
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(SCREEN_W as u32).to_be_bytes());
    ihdr.extend_from_slice(&(SCREEN_H as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    chunk(b"IHDR", &ihdr);
    chunk(b"IDAT", &z);
    chunk(b"IEND", &[]);
    std::fs::write(path, out).unwrap();
}

fn key_named(n: &str) -> Key {
    let all = [
        Key::Shift, Key::Ctrl, Key::CapsLock, Key::ShiftLock, Key::Tab, Key::Escape, Key::A, Key::B, Key::C, Key::D,
        Key::E, Key::F, Key::G, Key::H, Key::I, Key::J, Key::K, Key::L, Key::M, Key::N, Key::O, Key::P, Key::Q,
        Key::R, Key::S, Key::T, Key::U, Key::V, Key::W, Key::X, Key::Y, Key::Z, Key::D0, Key::D1, Key::D2, Key::D3,
        Key::D4, Key::D5, Key::D6, Key::D7, Key::D8, Key::D9, Key::F0, Key::F1, Key::F2, Key::F3, Key::F4, Key::F5,
        Key::F6, Key::F7, Key::F8, Key::F9, Key::Minus, Key::Caret, Key::Underscore, Key::At, Key::LeftBracket,
        Key::RightBracket, Key::Backslash, Key::Semicolon, Key::Colon, Key::Comma, Key::Period, Key::Slash,
        Key::Space, Key::Left, Key::Right, Key::Up, Key::Down, Key::Copy, Key::Delete, Key::Return, Key::Break,
    ];
    *all.iter().find(|k| format!("{:?}", k).eq_ignore_ascii_case(n)).unwrap_or_else(|| panic!("unknown key {}", n))
}

/// Test-only stand-in for the BASIC ELITE loader (no BASIC ROM here): *FX200,3, *RUN Elite2,
/// MODE 7, flush, wait for a key, then raise "No such line" like the loader's jump to a missing
/// line (which Elite2's BRKV hook turns into the next loading stage).
fn fake_loader() -> Vec<u8> {
    let mut r = vec![0u8; 0x100];
    r[0..3].copy_from_slice(&[0x4C, 0x10, 0x80]);
    r[6] = 0x40;
    r[7] = 0x0C;
    r[9..12].copy_from_slice(b"LDR");
    r[0x0D..0x10].copy_from_slice(b"(C)");
    let mut c: Vec<u8> = vec![0x58, 0xA9, 0, 0xA0, 0, 0x20, 0xCE, 0xFF, 0xA9, 200, 0xA2, 3, 0xA0, 0, 0x20, 0xF4, 0xFF];
    let cmd_at = 0x8010 + c.len() as u16 + 4 + 3 + 10 + 9 + 3 + 2 + 12 + 1;
    c.extend_from_slice(&[0xA2, cmd_at as u8, 0xA0, (cmd_at >> 8) as u8, 0x20, 0xF7, 0xFF]);
    c.extend_from_slice(&[0xA9, 22, 0x20, 0xEE, 0xFF, 0xA9, 7, 0x20, 0xEE, 0xFF]);
    c.extend_from_slice(&[0xA9, 15, 0xA2, 0, 0xA0, 0, 0x20, 0xF4, 0xFF]);
    c.extend_from_slice(&[0x20, 0xE0, 0xFF, 0, 0]);
    c.extend_from_slice(b"No such line\0");
    c.extend_from_slice(b"RUN Elite2
");
    r[0x10..0x10 + c.len()].copy_from_slice(&c);
    r
}

#[test]
#[ignore]
fn boot_and_shoot() {
    let Ok(mos) = std::env::var("BEEB_MOS") else { return };
    let out = std::path::PathBuf::from(std::env::var("BEEB_OUT").unwrap_or_else(|_| ".".into()));
    let frames: u64 = std::env::var("BEEB_FRAMES").ok().and_then(|v| v.parse().ok()).unwrap_or(300);
    let shots: Vec<u64> = std::env::var("BEEB_SHOTS").unwrap_or_default().split(',').filter_map(|v| v.parse().ok()).collect();
    let mut keys: Vec<(u64, Key, bool)> = Vec::new();
    for e in std::env::var("BEEB_KEYS").unwrap_or_default().split(',').filter(|e| !e.is_empty()) {
        let p: Vec<&str> = e.split(':').collect();
        keys.push((p[0].parse().unwrap(), key_named(p[1]), p[2] == "d"));
    }
    let mut b = Beeb::new(&std::fs::read(mos).unwrap());
    if let Ok(r) = std::env::var("BEEB_BASIC") { b.insert_rom(15, &std::fs::read(r).unwrap()); }
    match std::env::var("BEEB_FAKE_LOADER").as_deref() {
        Ok("echo") => {
            let mut r = vec![0u8; 0x100];
            r[0..3].copy_from_slice(&[0x4C, 0x10, 0x80]);
            r[6] = 0x40;
            r[7] = 0x0C;
            r[0x0D..0x10].copy_from_slice(b"(C)");
            r[0x10..0x1A].copy_from_slice(&[0x58, 0x20, 0xE0, 0xFF, 0x20, 0xEE, 0xFF, 0x4C, 0x11, 0x80]);
            b.insert_rom(15, &r);
        }
        Ok(_) => b.insert_rom(15, &fake_loader()),
        Err(_) => {}
    }
    let sb = std::env::var("BEEB_SHIFT_BREAK").is_ok();
    if let Ok(d) = std::env::var("BEEB_SSD") { b.insert_disc(std::fs::read(d).unwrap()); }
    b.reset(sb);
    let tf: u64 = std::env::var("BEEB_TRACEFRAME").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let jit: u64 = std::env::var("BEEB_JITTER").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut prev: Option<Vec<u32>> = None;
    for f in 1..=frames {
        if tf != 0 { b.trace_enable(f == tf); }
        if tf != 0 { b.trace_enable(f == tf); }
        for &(kf, k, d) in &keys { if kf == f { b.key(k, d); } }
        b.run_frame();
        if std::env::var("BEEB_TRACE").is_ok() && (f % 20 == 0 || false) { eprintln!("f{} {}", f, b.debug()); }
        if jit != 0 && f >= jit && f < jit + 12 {
            let s = b.screen();
            let first = (0..SCREEN_H).find(|&y| (0..SCREEN_W).filter(|&x| s[y * SCREEN_W + x] == 0xFFFF00).count() > 300);
            let d = prev.as_ref().map(|p: &Vec<u32>| (192 * SCREEN_W..SCREEN_H * SCREEN_W).filter(|&i| p[i] != s[i]).count());
            eprintln!("JIT f{} dash_top={:?} dash_diff={:?}", f, first, d);
            prev = Some(s.to_vec());
        }
        if shots.contains(&f) || f == frames {
            png(&out.join(format!("beeb_{:05}.png", f)), b.screen());
        }
    }
    if tf != 0 { for (c, r, v) in b.trace() { eprintln!("TR {} {:02X} {:02X}", c, r, v); } }
    let lg = b.disc_log(); let lg = &lg[lg.len().saturating_sub(25)..]; eprintln!("log {:?} 256={:02X} vec={:02X}{:02X} v212={:02X?}", lg, b.peek(0x256), b.peek(0x217), b.peek(0x216), (0x212..0x220).map(|a| b.peek(a)).collect::<Vec<_>>());
    eprintln!("done, frames={} pc={:04X}", b.frames(), b.pc());
}
