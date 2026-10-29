// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Procedural sound: oscillators, noise, envelopes and one-pole filters mixed into 48 kHz stereo
//! 16-bit samples. No sample files. The game feeds events in; the front end pulls samples out.
use crate::math::*;
use alloc::vec::Vec;

pub const RATE: u32 = 48_000;
const DT: f32 = 1.0 / RATE as f32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sfx {
    Laser,
    EnemyLaser,
    ShieldHit,
    Hit,
    Explosion,
    Missile,
    Lock,
    Ready,
    Scoop,
    Click,
    Select,
    Clamp,
    Chaff,
    Ding,
    Whoosh,
    Warn,
}

#[derive(Clone)]
struct Voice {
    sfx: Sfx,
    t: f32,
    dur: f32,
    gl: f32,
    gr: f32,
    phase: f32,
    lp: f32,
    lp2: f32,
}

/// Sine from a phase in cycles (parabolic approximation, fine for a synth).
#[inline]
fn sin01(p: f32) -> f32 {
    let p = p - floor(p);
    let x = if p < 0.5 { p } else { p - 1.0 };
    let y = 16.0 * x * (0.5 - abs(x));
    y * (0.775 + 0.225 * abs(y))
}

#[inline]
fn saw01(p: f32) -> f32 {
    2.0 * (p - floor(p)) - 1.0
}

/// Continuous state the game keeps updating.
#[derive(Clone, Copy, Default)]
pub struct AudioState {
    pub throttle: f32,
    pub speed_k: f32,
    pub jump_k: f32,
    pub hyper_k: f32,
    pub low_energy: bool,
    pub hot: bool,
    pub missile_warn: bool,
    pub in_flight: bool,
    pub music: bool,
}

pub struct Synth {
    voices: Vec<Voice>,
    noise: u32,
    pub master: f32,
    pub sfx_vol: f32,
    pub music_vol: f32,
    pub st: AudioState,
    // engine
    eng_ph: f32,
    eng_ph2: f32,
    eng_lp: f32,
    eng_amp: f32,
    jump_ph: f32,
    jump_lp: f32,
    hyper_ph: f32,
    alarm_t: f32,
    warn_t: f32,
    // music
    mus_t: f32,
    mus_gain: f32,
    bell_t: f32,
    bell: Option<(f32, f32, f32, f32)>, // freq, age, pan, phase
    pad_ph: [f32; 9],
    mus_seed: u32,
    last_chord: usize,
}

const CHORDS: [[f32; 3]; 4] = [[110.0, 164.81, 220.0], [87.31, 130.81, 174.61], [98.0, 146.83, 196.0], [98.0, 123.47, 196.0]];
const BELLS: [f32; 6] = [440.0, 523.25, 587.33, 659.25, 783.99, 880.0];

impl Synth {
    pub fn new() -> Synth {
        Synth {
            voices: Vec::new(),
            noise: 0x1234_5678,
            master: 0.8,
            sfx_vol: 0.8,
            music_vol: 0.6,
            st: AudioState::default(),
            eng_ph: 0.0,
            eng_ph2: 0.0,
            eng_lp: 0.0,
            eng_amp: 0.0,
            jump_ph: 0.0,
            jump_lp: 0.0,
            hyper_ph: 0.0,
            alarm_t: 0.0,
            warn_t: 0.0,
            mus_t: 0.0,
            mus_gain: 0.0,
            bell_t: 1.0,
            bell: None,
            pad_ph: [0.0; 9],
            mus_seed: 99,
            last_chord: 0,
        }
    }

    #[inline]
    fn rnd(&mut self) -> f32 {
        let mut x = self.noise;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.noise = x;
        (x >> 8) as f32 * (2.0 / 8388608.0) - 1.0
    }

    /// Start a one-shot sound. `pan` is -1 (left) to 1 (right), `gain` 0..1.
    pub fn trigger(&mut self, sfx: Sfx, pan: f32, gain: f32) {
        let dur = match sfx {
            Sfx::Laser => 0.22,
            Sfx::EnemyLaser => 0.2,
            Sfx::ShieldHit => 0.25,
            Sfx::Hit => 0.35,
            Sfx::Explosion => 1.6,
            Sfx::Missile => 0.7,
            Sfx::Lock => 0.09,
            Sfx::Ready => 0.2,
            Sfx::Scoop => 0.3,
            Sfx::Click => 0.03,
            Sfx::Select => 0.09,
            Sfx::Clamp => 0.6,
            Sfx::Chaff => 0.5,
            Sfx::Ding => 0.9,
            Sfx::Whoosh => 1.6,
            Sfx::Warn => 0.1,
        };
        if self.voices.len() >= 28 {
            // drop the oldest
            self.voices.remove(0);
        }
        let g = clamp(gain, 0.0, 1.0);
        let pan = clamp(pan, -1.0, 1.0);
        self.voices.push(Voice { sfx, t: 0.0, dur, gl: g * sqrt((1.0 - pan) * 0.5), gr: g * sqrt((1.0 + pan) * 0.5), phase: 0.0, lp: 0.0, lp2: 0.0 });
    }

    fn voice_sample(&mut self, i: usize) -> f32 {
        let (sfx, t, dur) = {
            let v = &self.voices[i];
            (v.sfx, v.t, v.dur)
        };
        let k = t / dur; // 0..1
        let n = self.rnd();
        let v = &mut self.voices[i];
        let s = match sfx {
            Sfx::Laser => {
                let f = 1900.0 * exp_neg(k * 3.2) + 260.0;
                v.phase += f * DT;
                let env = exp_neg(k * 5.0);
                (sin01(v.phase) * 0.6 + saw01(v.phase * 0.5) * 0.25) * env + n * 0.15 * exp_neg(k * 40.0)
            }
            Sfx::EnemyLaser => {
                let f = 700.0 * exp_neg(k * 2.5) + 180.0;
                v.phase += f * DT;
                let sq = if sin01(v.phase) > 0.0 { 1.0 } else { -1.0 };
                sq * 0.35 * exp_neg(k * 5.0)
            }
            Sfx::ShieldHit => {
                v.phase += (900.0 - 500.0 * k) * DT;
                v.lp += (n - v.lp) * 0.5;
                (sin01(v.phase) * 0.5 + (n - v.lp) * 0.5) * exp_neg(k * 6.0)
            }
            Sfx::Hit => {
                v.phase += (130.0 - 70.0 * k) * DT;
                v.lp += (n - v.lp) * 0.12;
                (sin01(v.phase) * 0.7 + v.lp * 1.6) * exp_neg(k * 5.0)
            }
            Sfx::Explosion => {
                // low-passed noise whose cutoff falls, plus a falling boom
                let c = 0.30 * exp_neg(k * 3.5) + 0.01;
                v.lp += (n - v.lp) * c;
                v.lp2 += (v.lp - v.lp2) * 0.3;
                v.phase += (70.0 * exp_neg(k * 2.0) + 22.0) * DT;
                let env = exp_neg(k * 3.0) * (1.0 - exp_neg(t * 200.0));
                (v.lp2 * 3.2 + sin01(v.phase) * 0.9) * env
            }
            Sfx::Missile => {
                v.phase += (180.0 + 700.0 * k) * DT;
                v.lp += (n - v.lp) * (0.05 + 0.3 * k);
                let env = sin01(k * 0.5) * exp_neg(k * 1.2);
                (v.lp * 1.6 + saw01(v.phase) * 0.12) * env
            }
            Sfx::Lock => {
                v.phase += 1050.0 * DT;
                (if sin01(v.phase) > 0.0 { 0.28 } else { -0.28 }) * (1.0 - k)
            }
            Sfx::Ready => {
                let f = if k < 0.5 { 1250.0 } else { 1700.0 };
                v.phase += f * DT;
                (if sin01(v.phase) > 0.0 { 0.25 } else { -0.25 }) * (1.0 - k)
            }
            Sfx::Scoop => {
                let f = if k < 0.33 { 620.0 } else if k < 0.66 { 820.0 } else { 1040.0 };
                v.phase += f * DT;
                sin01(v.phase) * 0.4 * (1.0 - k)
            }
            Sfx::Click => {
                v.phase += 2600.0 * DT;
                sin01(v.phase) * 0.3 * (1.0 - k)
            }
            Sfx::Select => {
                let f = if k < 0.5 { 640.0 } else { 960.0 };
                v.phase += f * DT;
                sin01(v.phase) * 0.35 * (1.0 - k)
            }
            Sfx::Clamp => {
                v.phase += 90.0 * DT;
                let ring = sin01(v.phase * 13.3) * 0.25 * exp_neg(k * 4.0);
                v.lp += (n - v.lp) * 0.2;
                (sin01(v.phase) * 0.8 * exp_neg(k * 8.0)) + ring + v.lp * 0.3 * exp_neg(k * 20.0)
            }
            Sfx::Chaff => {
                v.lp += (n - v.lp) * 0.7;
                (n - v.lp) * 0.7 * sin01(k * 0.5)
            }
            Sfx::Ding => {
                v.phase += 880.0 * DT;
                (sin01(v.phase) * 0.5 + sin01(v.phase * 2.76) * 0.2 + sin01(v.phase * 5.4) * 0.08) * exp_neg(k * 5.0)
            }
            Sfx::Whoosh => {
                v.lp += (n - v.lp) * (0.02 + 0.5 * k * k);
                v.phase += (100.0 + 2400.0 * k * k) * DT;
                (v.lp * 2.4 + sin01(v.phase) * 0.15) * sin01(k * 0.5)
            }
            Sfx::Warn => {
                v.phase += 880.0 * DT;
                (if sin01(v.phase) > 0.0 { 0.3 } else { -0.3 }) * (1.0 - k)
            }
        };
        v.t += DT;
        s
    }

    fn music_sample(&mut self) -> (f32, f32) {
        let target = if self.st.music { 1.0 } else { 0.0 };
        self.mus_gain += (target - self.mus_gain) * 0.00008;
        if self.mus_gain < 0.002 && !self.st.music {
            return (0.0, 0.0);
        }
        self.mus_t += DT;
        let seg = 9.0;
        let idx = (self.mus_t / seg) as usize;
        let chord = CHORDS[idx % 4];
        let next = CHORDS[(idx + 1) % 4];
        let frac = self.mus_t / seg - floor(self.mus_t / seg);
        let x = smoothstep(0.7, 1.0, frac); // crossfade near the end of a segment
        if idx != self.last_chord {
            self.last_chord = idx;
        }
        let lfo = 0.5 + 0.5 * sin01(self.mus_t * 0.07);
        let mut l = 0.0;
        let mut r = 0.0;
        for v in 0..3 {
            for d in 0..3 {
                let det = 1.0 + (d as f32 - 1.0) * 0.003;
                let a = chord[v] * det;
                let b = next[v] * det;
                let f = a * (1.0 - x) + b * x;
                let p = &mut self.pad_ph[v * 3 + d];
                *p += f * DT;
                if *p > 1000.0 {
                    *p -= 1000.0;
                }
                let s = sin01(*p) * 0.7 + sin01(*p * 2.0) * 0.18 * lfo;
                let pan = (d as f32 - 1.0) * 0.5;
                l += s * (0.5 - pan * 0.5);
                r += s * (0.5 + pan * 0.5);
            }
        }
        l *= 0.06;
        r *= 0.06;
        // sparse bell notes
        self.bell_t -= DT;
        if self.bell_t <= 0.0 && self.bell.is_none() {
            self.mus_seed = self.mus_seed.wrapping_mul(1664525).wrapping_add(1013904223);
            let n = BELLS[((self.mus_seed >> 16) % 6) as usize];
            let pan = ((self.mus_seed >> 8) & 255) as f32 / 128.0 - 1.0;
            self.bell = Some((n, 0.0, pan * 0.7, 0.0));
            self.bell_t = 2.2 + ((self.mus_seed >> 4) & 15) as f32 * 0.35;
        }
        if let Some((f, age, pan, ph)) = self.bell {
            let ph = ph + f * DT;
            let age = age + DT;
            let env = exp_neg(age * 1.8) * (1.0 - exp_neg(age * 400.0));
            let s = (sin01(ph) * 0.6 + sin01(ph * 2.0) * 0.2 + sin01(ph * 3.01) * 0.08) * env * 0.09;
            l += s * (0.5 - pan * 0.5) * 2.0;
            r += s * (0.5 + pan * 0.5) * 2.0;
            self.bell = if age > 3.0 { None } else { Some((f, age, pan, ph)) };
        }
        (l * self.mus_gain, r * self.mus_gain)
    }

    /// Fill `out` with interleaved stereo samples.
    pub fn render(&mut self, out: &mut [i16]) {
        let st = self.st;
        let master = self.master;
        let (sv, mv) = (self.sfx_vol * master, self.music_vol * master);
        for frame in out.chunks_exact_mut(2) {
            let mut l = 0.0f32;
            let mut r = 0.0f32;
            // ---- engine hum (only in flight)
            let want = if st.in_flight { 0.05 + 0.2 * st.throttle + 0.12 * st.speed_k } else { 0.0 };
            self.eng_amp += (want - self.eng_amp) * 0.0004;
            if self.eng_amp > 0.001 {
                let f = 34.0 + 62.0 * st.throttle;
                self.eng_ph += f * DT;
                self.eng_ph2 += f * 1.505 * DT;
                let n = self.rnd();
                self.eng_lp += (n - self.eng_lp) * 0.04;
                let tone = saw01(self.eng_ph) * 0.5 + sin01(self.eng_ph2) * 0.35 + self.eng_lp * 1.4;
                let e = tone * self.eng_amp;
                l += e * sv;
                r += e * sv;
            }
            // ---- in-system jump drive and hyperspace charge
            if st.jump_k > 0.01 {
                self.jump_ph += (90.0 + 700.0 * st.jump_k) * DT;
                let n = self.rnd();
                self.jump_lp += (n - self.jump_lp) * (0.02 + 0.1 * st.jump_k);
                let s = (sin01(self.jump_ph) * 0.25 + self.jump_lp * 1.2) * st.jump_k * 0.5;
                l += s * sv;
                r += s * sv;
            }
            if st.hyper_k > 0.01 {
                self.hyper_ph += (180.0 + 1700.0 * st.hyper_k * st.hyper_k) * DT;
                let pulse = 0.6 + 0.4 * sin01(self.hyper_ph * 0.004 + st.hyper_k * 8.0);
                let s = (sin01(self.hyper_ph) * 0.3 + sin01(self.hyper_ph * 1.5) * 0.15) * st.hyper_k * pulse * 0.45;
                l += s * sv;
                r += s * sv;
            }
            // ---- alarms
            let mut alarm = 0.0;
            if st.low_energy || st.hot {
                self.alarm_t += DT;
                let ph = self.alarm_t * if st.hot { 3.0 } else { 2.0 };
                if ph - floor(ph) < 0.35 {
                    self.hyper_ph += 0.0;
                    alarm = sin01(self.alarm_t * if st.hot { 1320.0 } else { 760.0 }) * 0.18;
                }
            }
            if st.missile_warn {
                self.warn_t += DT;
                let ph = self.warn_t * 5.0;
                if ph - floor(ph) < 0.4 {
                    alarm += (if sin01(self.warn_t * 1500.0) > 0.0 { 0.12 } else { -0.12 }) as f32;
                }
            }
            l += alarm * sv;
            r += alarm * sv;
            // ---- one-shot voices
            let mut i = 0;
            while i < self.voices.len() {
                if self.voices[i].t >= self.voices[i].dur {
                    self.voices.swap_remove(i);
                    continue;
                }
                let s = self.voice_sample(i);
                let v = &self.voices[i];
                l += s * v.gl * sv;
                r += s * v.gr * sv;
                i += 1;
            }
            // ---- music
            let (ml, mr) = self.music_sample();
            l += ml * mv;
            r += mr * mv;
            // soft clip
            let clip = |x: f32| -> f32 {
                let x = clamp(x, -1.5, 1.5);
                x - x * x * x / 6.75
            };
            frame[0] = (clip(l) * 30000.0) as i16;
            frame[1] = (clip(r) * 30000.0) as i16;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(s: &mut Synth, frames: usize) -> alloc::vec::Vec<i16> {
        let mut v = alloc::vec![0i16; frames * 2];
        s.render(&mut v);
        v
    }
    fn peak(v: &[i16]) -> i32 {
        v.iter().map(|&x| (x as i32).abs()).max().unwrap_or(0)
    }

    #[test]
    fn silent_when_idle_and_loud_when_triggered() {
        let mut s = Synth::new();
        assert_eq!(peak(&render(&mut s, 2000)), 0);
        s.trigger(Sfx::Explosion, 0.0, 1.0);
        let v = render(&mut s, 24_000);
        assert!(peak(&v) > 3000, "explosion peak {}", peak(&v));
        // and it dies out
        let tail = render(&mut s, 96_000);
        let end = render(&mut s, 2000);
        assert!(peak(&tail) > 0);
        assert_eq!(peak(&end), 0);
    }

    #[test]
    fn panning_follows_direction() {
        let mut s = Synth::new();
        s.trigger(Sfx::Laser, 1.0, 1.0);
        let v = render(&mut s, 4000);
        let (mut l, mut r) = (0i64, 0i64);
        for f in v.chunks(2) {
            l += (f[0] as i64).abs();
            r += (f[1] as i64).abs();
        }
        assert!(r > l * 5, "right {} left {}", r, l);
    }

    #[test]
    fn music_and_engine_are_audible_when_enabled() {
        let mut s = Synth::new();
        s.st.music = true;
        let v = render(&mut s, 48_000 * 4);
        assert!(peak(&v) > 500, "music peak {}", peak(&v));
        let mut e = Synth::new();
        e.st.in_flight = true;
        e.st.throttle = 1.0;
        let v = render(&mut e, 48_000 * 2);
        assert!(peak(&v) > 500, "engine peak {}", peak(&v));
    }
}
