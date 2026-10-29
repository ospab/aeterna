// SPDX-License-Identifier: AGPL-3.0-only
//! SN76489 sound chip as wired in the Model B, plus the resampler to the host output rate.
//!
//! The chip clock is 4 MHz; the tone and noise counters run at clock/16 = 250 kHz, which is one
//! `tick` per 8 CPU cycles (2 MHz). A tone output toggles every `period` ticks, so the frequency
//! is 250000 / (2 * period). Noise shifts every 32 << rate ticks (rate 3 follows tone channel 3).
//! The output level of every tick is averaged over the output sample period (a box filter) and
//! passed through a DC-blocking high-pass.
//!
//! Register protocol: a byte with bit 7 set latches channel (bits 6-5), type (bit 4: 1 = attenuation)
//! and the low 4 data bits; a byte with bit 7 clear carries the high 6 bits of a tone period or
//! the low bits of the latched register.

use alloc::vec::Vec;

pub const CHIP_HZ: u32 = 250_000;
pub const DEFAULT_RATE: u32 = 48_000;
/// Samples kept if the caller never drains (one second).
const MAX_PENDING: usize = 96_000;

/// Linear amplitude per attenuation step (2 dB each, 15 = off), full scale per channel 7000.
const LEVEL: [i32; 16] = [
    7000, 5560, 4417, 3509, 2787, 2214, 1759, 1397, 1110, 882, 700, 556, 442, 351, 279, 0,
];

pub struct Sound {
    period: [u16; 3],
    count: [u16; 3],
    out: [bool; 3],
    atten: [u8; 4],
    noise_ctl: u8,
    noise_count: u16,
    noise_out: bool,
    lfsr: u16,
    latch: u8,
    rate: u32,
    phase: u32,
    sum: i64,
    n: u32,
    hp_x: i32,
    hp_y: i32,
    pending: Vec<i16>,
    ready: Vec<i16>,
}

impl Sound {
    pub fn new() -> Self {
        Sound {
            period: [0; 3], count: [1; 3], out: [false; 3], atten: [15; 4], noise_ctl: 0,
            noise_count: 16, noise_out: false, lfsr: 0x4000, latch: 0, rate: DEFAULT_RATE, phase: 0,
            sum: 0, n: 0, hp_x: 0, hp_y: 0, pending: Vec::new(), ready: Vec::new(),
        }
    }

    pub fn set_rate(&mut self, rate: u32) {
        self.rate = rate.clamp(8_000, CHIP_HZ);
        self.phase = 0;
        self.sum = 0;
        self.n = 0;
    }

    pub fn rate(&self) -> u32 { self.rate }

    /// Takes the samples produced since the last call.
    pub fn drain(&mut self) -> &[i16] {
        core::mem::swap(&mut self.pending, &mut self.ready);
        self.pending.clear();
        &self.ready
    }

    /// A byte written to the chip (the strobe on addressable latch bit 0).
    pub fn write(&mut self, v: u8) {        if v & 0x80 != 0 {
            self.latch = (v >> 4) & 7;
            self.set_reg(v & 15, true);
        } else {
            self.set_reg(v & 0x3F, false);
        }
    }

    fn set_reg(&mut self, d: u8, low_nibble: bool) {
        let ch = (self.latch >> 1) as usize;
        if self.latch & 1 != 0 {
            self.atten[ch] = d & 15;
        } else if ch < 3 {
            if low_nibble {
                self.period[ch] = (self.period[ch] & 0x3F0) | d as u16;
            } else {
                self.period[ch] = (self.period[ch] & 0x00F) | (d as u16) << 4;
            }
        } else {
            self.noise_ctl = d & 7;
            self.lfsr = 0x4000;
        }
    }

    fn per(&self, ch: usize) -> u16 {
        if self.period[ch] == 0 { 0x400 } else { self.period[ch] }
    }

    fn noise_reload(&self) -> u16 {
        match self.noise_ctl & 3 {
            3 => self.per(2),
            n => 16u16 << n,
        }
    }

    /// One 250 kHz chip tick.
    fn tick(&mut self) {
        for ch in 0..3 {
            self.count[ch] -= 1;
            if self.count[ch] == 0 {
                self.count[ch] = self.per(ch);
                self.out[ch] = !self.out[ch];
            }
        }
        self.noise_count -= 1;
        if self.noise_count == 0 {
            self.noise_count = self.noise_reload();
            self.noise_out = !self.noise_out;
            if self.noise_out {
                let fb = if self.noise_ctl & 4 != 0 { (self.lfsr ^ (self.lfsr >> 1)) & 1 } else { self.lfsr & 1 };
                self.lfsr = (self.lfsr >> 1) | (fb << 14);
            }
        }
        let mut level = 0i32;
        for ch in 0..3 {
            // Period 1 is above the audible range: the real chip outputs a constant level.
            let on = if self.period[ch] == 1 { true } else { self.out[ch] };
            if on { level += LEVEL[self.atten[ch] as usize]; }
        }
        if self.lfsr & 1 != 0 { level += LEVEL[self.atten[3] as usize]; }
        self.sum += level as i64;
        self.n += 1;
        self.phase += self.rate;
        if self.phase >= CHIP_HZ {
            self.phase -= CHIP_HZ;
            let x = (self.sum / self.n as i64) as i32;
            self.sum = 0;
            self.n = 0;
            // DC blocker: y[n] = x[n] - x[n-1] + 0.995 * y[n-1]
            let y = x - self.hp_x + (self.hp_y * 995) / 1000;
            self.hp_x = x;
            self.hp_y = y;
            if self.pending.len() < MAX_PENDING { self.pending.push(y.clamp(-32768, 32767) as i16); }
        }
    }

    /// Advances by `cyc` CPU cycles (2 MHz); `acc` carries the remainder between calls.
    pub fn advance(&mut self, acc: &mut u32, cyc: u32) {
        *acc += cyc;
        while *acc >= 8 {
            *acc -= 8;
            self.tick();
        }
    }
}
