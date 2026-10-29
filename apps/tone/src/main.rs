// SPDX-License-Identifier: AGPL-3.0-only
//! tone: proves ring-3 sound output (syscalls 271..274). Plays 440 Hz for one second (mono,
//! 48000 Hz), then a C major chord for one second (stereo, 44100 Hz, so the kernel resamples),
//! and exits. `tone N` plays each part for N seconds. Without a sound device it says so.
#![no_std]
#![no_main]

use liboos::audio::Audio;
use liboos::println;
use liboos::screen;

liboos::entry!(main);

/// Sine of a phase (full turn = 2^32), result in -32768..=32767 (parabola with a correction).
fn sin(phase: u32) -> i32 {
    let p = (phase >> 16) as i64; // 0..65535 per turn
    let (x, neg) = if p < 32768 { (p, false) } else { (p - 32768, true) };
    let mut y = (4 * x * (32768 - x)) >> 15; // 0..=32768
    // y += 0.225 * (y * y - y)
    y += (7373 * ((y * y >> 15) - y)) >> 15;
    let y = y.min(32767) as i32;
    if neg {
        -y
    } else {
        y
    }
}

/// Play the sum of `freqs` (Hz) for `ms` milliseconds at amplitude `amp` (of 32767) in total.
fn play(a: &Audio, freqs: &[u32], ms: u32, amp: i32) {
    let rate = a.rate();
    let ch = a.channels() as usize;
    let total = (rate as u64 * ms as u64 / 1000) as usize;
    let mut phase = [0u32; 4];
    let mut inc = [0u32; 4];
    for (i, f) in freqs.iter().enumerate() {
        inc[i] = (((*f as u64) << 32) / rate as u64) as u32;
    }
    let each = amp / freqs.len() as i32;
    let mut buf = [0i16; 960];
    let mut done = 0;
    while done < total {
        let frames = (total - done).min(buf.len() / ch);
        for f in 0..frames {
            let mut v = 0i32;
            for i in 0..freqs.len() {
                v += (sin(phase[i]) * each) >> 15;
                phase[i] = phase[i].wrapping_add(inc[i]);
            }
            for c in 0..ch {
                buf[f * ch + c] = v as i16;
            }
        }
        let n = frames * ch;
        let mut off = 0;
        while off < n {
            let w = a.write(&buf[off..n]);
            off += w;
            if w == 0 {
                screen::sleep_ms(10); // buffer full: the kernel is playing it
            }
        }
        done += frames;
    }
}

fn main(args: liboos::Args) -> i32 {
    let mut ms = 1000;
    if let Some(a) = args.get(1) {
        let mut n = 0u32;
        for b in a.bytes() {
            if b.is_ascii_digit() {
                n = n * 10 + (b - b'0') as u32;
            }
        }
        if n > 0 {
            ms = n * 1000;
        }
    }

    let mono = match Audio::open(48000, 1) {
        Ok(a) => a,
        Err(e) => {
            println!("tone: no sound output (error {})", e);
            return 1;
        }
    };
    println!("tone: 440 Hz, mono 48000 Hz, {} ms", ms);
    play(&mono, &[440], ms, 16000);
    mono.drain();
    drop(mono);

    let stereo = match Audio::open(44100, 2) {
        Ok(a) => a,
        Err(e) => {
            println!("tone: cannot open the second stream (error {})", e);
            return 1;
        }
    };
    println!("tone: C major chord (262, 330, 392 Hz), stereo 44100 Hz, {} ms", ms);
    play(&stereo, &[262, 330, 392], ms, 24000);
    stereo.drain();
    println!("tone: done");
    0
}
