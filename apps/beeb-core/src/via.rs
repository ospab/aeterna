// SPDX-License-Identifier: AGPL-3.0-only
//! 6522 VIA. Timers count at 1 MHz (`tick(n)` takes 1 MHz cycles). Port pins are supplied by the
//! machine through `pa_in`/`pb_in`; handshake output modes are not modelled.

pub const IFR_CA2: u8 = 0x01;
pub const IFR_CA1: u8 = 0x02;
pub const IFR_SR: u8 = 0x04;
pub const IFR_CB2: u8 = 0x08;
pub const IFR_CB1: u8 = 0x10;
pub const IFR_T2: u8 = 0x20;
pub const IFR_T1: u8 = 0x40;

pub struct Via {
    pub ora: u8,
    pub orb: u8,
    pub ddra: u8,
    pub ddrb: u8,
    pub pa_in: u8,
    pub pb_in: u8,
    pub acr: u8,
    pub pcr: u8,
    pub ifr: u8,
    pub ier: u8,
    sr: u8,
    t1_latch: u16,
    t1_cnt: i32,
    t1_fire: bool,
    pb7: bool,
    t2_latch: u16,
    t2_cnt: i32,
    t2_fire: bool,
    ca2_level: bool,
}

impl Via {
    pub const fn new() -> Self {
        Via {
            ora: 0, orb: 0, ddra: 0, ddrb: 0, pa_in: 0xFF, pb_in: 0xFF, acr: 0, pcr: 0, ifr: 0, ier: 0,
            sr: 0, t1_latch: 0xFFFF, t1_cnt: 0xFFFF, t1_fire: false, pb7: false,
            t2_latch: 0xFFFF, t2_cnt: 0xFFFF, t2_fire: false, ca2_level: false
        }
    }

    pub fn irq(&self) -> bool { self.ifr & self.ier & 0x7F != 0 }

    pub fn port_a(&self) -> u8 { (self.ora & self.ddra) | (self.pa_in & !self.ddra) }

    pub fn port_b(&self) -> u8 {
        let mut v = (self.orb & self.ddrb) | (self.pb_in & !self.ddrb);
        if self.acr & 0x80 != 0 { v = (v & 0x7F) | if self.pb7 { 0x80 } else { 0 }; }
        v
    }

    pub fn read(&mut self, reg: u8) -> u8 {
        match reg & 15 {
            0 => {
                self.ifr &= !IFR_CB1;
                if self.pcr & 0xA0 != 0x20 { self.ifr &= !IFR_CB2; }
                self.port_b()
            }
            1 => {
                self.ifr &= !IFR_CA1;
                if self.pcr & 0x0A != 0x02 { self.ifr &= !IFR_CA2; }
                self.port_a()
            }
            2 => self.ddrb,
            3 => self.ddra,
            4 => { self.ifr &= !IFR_T1; self.t1_cnt as u8 }
            5 => (self.t1_cnt >> 8) as u8,
            6 => self.t1_latch as u8,
            7 => (self.t1_latch >> 8) as u8,
            8 => { self.ifr &= !IFR_T2; self.t2_cnt as u8 }
            9 => (self.t2_cnt >> 8) as u8,
            10 => { self.ifr &= !IFR_SR; self.sr }
            11 => self.acr,
            12 => self.pcr,
            13 => self.ifr | if self.irq() { 0x80 } else { 0 },
            14 => self.ier | 0x80,
            _ => self.port_a(),
        }
    }

    pub fn write(&mut self, reg: u8, v: u8) {
        match reg & 15 {
            0 => {
                self.orb = v;
                self.ifr &= !IFR_CB1;
                if self.pcr & 0xA0 != 0x20 { self.ifr &= !IFR_CB2; }
            }
            1 => {
                self.ora = v;
                self.ifr &= !IFR_CA1;
                if self.pcr & 0x0A != 0x02 { self.ifr &= !IFR_CA2; }
            }
            2 => self.ddrb = v,
            3 => self.ddra = v,
            4 | 6 => self.t1_latch = (self.t1_latch & 0xFF00) | v as u16,
            5 => {
                self.t1_latch = (self.t1_latch & 0x00FF) | (v as u16) << 8;
                self.t1_cnt = self.t1_latch as i32 + 1;
                self.ifr &= !IFR_T1;
                self.t1_fire = true;
                self.pb7 = false;
            }
            7 => { self.t1_latch = (self.t1_latch & 0x00FF) | (v as u16) << 8; self.ifr &= !IFR_T1; }
            8 => self.t2_latch = (self.t2_latch & 0xFF00) | v as u16,
            9 => {
                self.t2_latch = (self.t2_latch & 0x00FF) | (v as u16) << 8;
                self.t2_cnt = self.t2_latch as i32 + 1;
                self.ifr &= !IFR_T2;
                self.t2_fire = true;
            }
            10 => { self.sr = v; self.ifr &= !IFR_SR; }
            11 => self.acr = v,
            12 => self.pcr = v,
            13 => self.ifr &= !(v & 0x7F),
            14 => { if v & 0x80 != 0 { self.ier |= v & 0x7F } else { self.ier &= !(v & 0x7F) } }
            _ => {
                self.ora = v;
            }
        }
    }

    pub fn tick(&mut self, n: u32) {
        for _ in 0..n {
            self.t1_cnt -= 1;
            if self.t1_cnt < 0 {
                if self.acr & 0x40 != 0 {
                    self.ifr |= IFR_T1;
                    self.pb7 = !self.pb7;
                    self.t1_cnt = self.t1_latch as i32 + 1;
                } else {
                    if self.t1_fire { self.ifr |= IFR_T1; self.t1_fire = false; self.pb7 = true; }
                    self.t1_cnt = 0xFFFF;
                }
            }
            self.t2_cnt -= 1;
            if self.t2_cnt < 0 {
                if self.t2_fire && self.acr & 0x20 == 0 { self.ifr |= IFR_T2; self.t2_fire = false; }
                self.t2_cnt = 0xFFFF;
            }
        }
    }

    /// Active CA1 transition seen (the machine decides which edge counts via `pcr_ca1_rising`).
    pub fn pcr_ca1_rising(&self) -> bool { self.pcr & 1 != 0 }

    pub fn ca1_edge(&mut self) { self.ifr |= IFR_CA1; }
    pub fn cb1_edge(&mut self) { self.ifr |= IFR_CB1; }

    /// CA2 input level change; flags the interrupt on the configured edge.
    pub fn set_ca2(&mut self, level: bool) {
        if level == self.ca2_level { return; }
        self.ca2_level = level;
        if self.pcr & 0x08 == 0 {
            let rising = self.pcr & 0x04 != 0;
            if rising == level { self.ifr |= IFR_CA2; }
        }
    }
}
