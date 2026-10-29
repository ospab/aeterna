// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Commodities, local markets and equipment catalogue.
use crate::galaxy::*;
use crate::math::*;

pub const NCOM: usize = 16;

pub struct Commodity {
    pub name: &'static str,
    pub unit: &'static str,
    pub base: i32,
    /// Economies (bit per economy index) that produce / consume it.
    pub producers: u8,
    pub consumers: u8,
    pub min_tech: u8,
    pub illegal: bool,
}

const fn eco(bits: &[u8]) -> u8 {
    let mut m = 0u8;
    let mut i = 0;
    while i < bits.len() {
        m |= 1 << bits[i];
        i += 1;
    }
    m
}

pub static COMMODITIES: [Commodity; NCOM] = [
    Commodity { name: "Algae Bricks", unit: "t", base: 18, producers: eco(&[1, 0]), consumers: eco(&[3, 2, 7]), min_tech: 1, illegal: false },
    Commodity { name: "Cryo Water", unit: "t", base: 24, producers: eco(&[1, 5]), consumers: eco(&[0, 2, 3]), min_tech: 1, illegal: false },
    Commodity { name: "Ferrite Ingots", unit: "t", base: 52, producers: eco(&[2, 7]), consumers: eco(&[3, 0]), min_tech: 2, illegal: false },
    Commodity { name: "Polymer Resin", unit: "t", base: 66, producers: eco(&[3]), consumers: eco(&[0, 6]), min_tech: 3, illegal: false },
    Commodity { name: "Spun Silk", unit: "crate", base: 140, producers: eco(&[6, 1]), consumers: eco(&[4, 5]), min_tech: 2, illegal: false },
    Commodity { name: "Amber Spirits", unit: "case", base: 210, producers: eco(&[1, 6]), consumers: eco(&[2, 3, 7]), min_tech: 2, illegal: false },
    Commodity { name: "Heavy Isotopes", unit: "t", base: 330, producers: eco(&[2]), consumers: eco(&[5, 3]), min_tech: 5, illegal: false },
    Commodity { name: "Servo Assemblies", unit: "t", base: 280, producers: eco(&[3]), consumers: eco(&[0, 2, 7]), min_tech: 5, illegal: false },
    Commodity { name: "Lattice Chips", unit: "crate", base: 520, producers: eco(&[5, 4]), consumers: eco(&[3, 6]), min_tech: 8, illegal: false },
    Commodity { name: "Synth Tonics", unit: "crate", base: 190, producers: eco(&[5]), consumers: eco(&[0, 2, 7]), min_tech: 6, illegal: false },
    Commodity { name: "Cut Prisms", unit: "crate", base: 900, producers: eco(&[2, 6]), consumers: eco(&[4, 5]), min_tech: 3, illegal: false },
    Commodity { name: "Iridite", unit: "crate", base: 760, producers: eco(&[2, 7]), consumers: eco(&[5, 3]), min_tech: 4, illegal: false },
    Commodity { name: "Plasma Carbines", unit: "crate", base: 620, producers: eco(&[3, 5]), consumers: eco(&[7, 0, 2]), min_tech: 7, illegal: false },
    Commodity { name: "Dreamfog", unit: "crate", base: 480, producers: eco(&[7, 6]), consumers: eco(&[5, 4]), min_tech: 1, illegal: true },
    Commodity { name: "Ghost Cores", unit: "crate", base: 1100, producers: eco(&[7]), consumers: eco(&[4, 5]), min_tech: 3, illegal: true },
    Commodity { name: "Warhead Casings", unit: "crate", base: 840, producers: eco(&[3, 7]), consumers: eco(&[0, 2]), min_tech: 6, illegal: true },
];

#[derive(Clone, Debug)]
pub struct Market {
    pub price: [i32; NCOM],
    pub stock: [i32; NCOM],
    /// Sell price numerator in percent of the buy price.
    pub sell_pct: i32,
}

impl Market {
    /// `visit` changes the short-term fluctuation each time the player comes back.
    pub fn generate(s: &SystemInfo, visit: u32) -> Market {
        let mut base = Rng::new(s.seed ^ 0xA11CE);
        let mut vis = Rng::new(s.seed ^ (visit as u64).wrapping_mul(0x9E37_79B9) ^ 0xF1AC);
        let mut price = [0; NCOM];
        let mut stock = [0; NCOM];
        let law = s.law() as i32;
        for (i, c) in COMMODITIES.iter().enumerate() {
            let prod = (c.producers >> s.economy) & 1 == 1;
            let cons = (c.consumers >> s.economy) & 1 == 1;
            let region = base.range(-9, 9);
            let fluct = vis.range(-7, 7);
            let mut pct = 100 + region + fluct;
            if prod {
                pct -= 24;
            }
            if cons {
                pct += 24;
            }
            // advanced goods are cheaper where tech is high
            if c.min_tech >= 5 {
                pct -= (s.tech as i32 - 8) * 2;
            }
            if c.illegal {
                pct += law * 8;
            }
            let p = c.base * pct.max(30) / 100;
            price[i] = p.max(1);
            let mut q = 10 + base.range(0, 18) + vis.range(-4, 6);
            if prod {
                q += 28;
            }
            if cons {
                q -= 8;
            }
            q = q * (50 + (s.pop as i32).min(150)) / 100;
            if s.tech < c.min_tech {
                q = 0;
            }
            if c.illegal && law >= 6 {
                q = 0;
            }
            stock[i] = q.clamp(0, 90);
        }
        Market { price, stock, sell_pct: if s.economy == 4 { 98 } else { 92 } }
    }
    pub fn sell_price(&self, i: usize) -> i32 {
        (self.price[i] * self.sell_pct / 100).max(1)
    }
    /// Buy one unit; returns the price paid, if possible.
    pub fn buy(&mut self, i: usize) -> Option<i32> {
        if self.stock[i] <= 0 {
            return None;
        }
        let p = self.price[i];
        self.stock[i] -= 1;
        self.price[i] = p + p / 120;
        Some(p)
    }
    pub fn sell(&mut self, i: usize) -> i32 {
        let p = self.sell_price(i);
        self.stock[i] += 1;
        let dec = (self.price[i] / 160).max(0);
        self.price[i] = (self.price[i] - dec).max(1);
        p
    }
}

// ------------------------------------------------------------------ equipment

pub const LASER_NONE: u8 = 0;
pub const LASER_PULSE: u8 = 1;
pub const LASER_BEAM: u8 = 2;
pub const LASER_MILITARY: u8 = 3;
pub const LASER_MINING: u8 = 4;

pub const LASER_NAMES: [&str; 5] = ["none", "Pulse", "Beam", "Military", "Mining"];
pub const LASER_PRICE: [i32; 5] = [0, 400, 2200, 5800, 800];
pub const LASER_TECH: [u8; 5] = [0, 1, 5, 9, 3];
pub const MOUNT_NAMES: [&str; 4] = ["Front", "Rear", "Left", "Right"];

// equipment bit flags
pub const EQ_SCOOP: u32 = 1 << 0;
pub const EQ_CHAFF: u32 = 1 << 1;
pub const EQ_SHIELD: u32 = 1 << 2;
pub const EQ_ENERGY: u32 = 1 << 3;
pub const EQ_DOCKCOMP: u32 = 1 << 4;
pub const EQ_GALDRIVE: u32 = 1 << 5;
pub const EQ_CAPSULE: u32 = 1 << 6;
pub const EQ_HEATSINK: u32 = 1 << 7;
pub const EQ_GHOST: u32 = 1 << 8;
pub const EQ_TETHER: u32 = 1 << 9;

pub struct EquipDef {
    pub flag: u32,
    pub name: &'static str,
    pub price: i32,
    pub min_tech: u8,
    pub desc: &'static str,
}

pub static EQUIPMENT: [EquipDef; 10] = [
    EquipDef { flag: EQ_SCOOP, name: "Fuel Scoop", price: 700, min_tech: 4, desc: "Skim a sun or scoop jettisoned fuel" },
    EquipDef { flag: EQ_CHAFF, name: "Countermeasure Pod", price: 600, min_tech: 3, desc: "Chaff that kills incoming missiles" },
    EquipDef { flag: EQ_SHIELD, name: "Shield Booster", price: 1500, min_tech: 5, desc: "Shields hold 50 percent more" },
    EquipDef { flag: EQ_ENERGY, name: "Energy Unit", price: 2500, min_tech: 7, desc: "Faster energy and shield recharge" },
    EquipDef { flag: EQ_DOCKCOMP, name: "Docking Computer", price: 1500, min_tech: 6, desc: "Flies the approach and slot for you" },
    EquipDef { flag: EQ_GALDRIVE, name: "Galactic Drive", price: 5000, min_tech: 10, desc: "One jump to the next galaxy, used up" },
    EquipDef { flag: EQ_CAPSULE, name: "Escape Capsule", price: 1000, min_tech: 4, desc: "Survive the loss of the ship" },
    EquipDef { flag: EQ_HEATSINK, name: "Heat Sink", price: 900, min_tech: 5, desc: "Lasers cool down twice as fast" },
    EquipDef { flag: EQ_GHOST, name: "Ghost Plate", price: 3000, min_tech: 8, desc: "Hides illegal cargo from most scans" },
    EquipDef { flag: EQ_TETHER, name: "Salvage Tether", price: 1200, min_tech: 6, desc: "Pulls cargo canisters in from afar" },
];

pub const HOLD_BASE: i32 = 20;
pub const HOLD_STEP: i32 = 15;
pub const HOLD_PRICE: [i32; 2] = [450, 1400];
pub const HOLD_TECH: [u8; 2] = [3, 7];
pub const MISSILE_PRICE: i32 = 60;
pub const MISSILE_MAX: u8 = 4;
pub const FUEL_PRICE_PER_TENTH: i32 = 2;
pub const MAX_FUEL_TENTHS: i32 = 70;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn markets_are_deterministic_and_react_to_economy() {
        let g = Galaxy::generate(0);
        for s in g.sys.iter().take(40) {
            let a = Market::generate(s, 3);
            let b = Market::generate(s, 3);
            assert_eq!(a.price, b.price);
            assert_eq!(a.stock, b.stock);
        }
        // producers are cheaper than consumers on average
        let mut pc = 0;
        let mut cc = 0;
        let (mut ps, mut cs) = (0i64, 0i64);
        for s in g.sys.iter() {
            let m = Market::generate(s, 1);
            for (i, c) in COMMODITIES.iter().enumerate() {
                if (c.producers >> s.economy) & 1 == 1 && (c.consumers >> s.economy) & 1 == 0 {
                    ps += (m.price[i] * 100 / c.base) as i64;
                    pc += 1;
                }
                if (c.consumers >> s.economy) & 1 == 1 && (c.producers >> s.economy) & 1 == 0 {
                    cs += (m.price[i] * 100 / c.base) as i64;
                    cc += 1;
                }
            }
        }
        assert!(ps / pc < cs / cc - 20, "{} vs {}", ps / pc, cs / cc);
    }
    #[test]
    fn visit_changes_prices() {
        let g = Galaxy::generate(0);
        let a = Market::generate(&g.sys[5], 1);
        let b = Market::generate(&g.sys[5], 2);
        assert_ne!(a.price, b.price);
    }
    #[test]
    fn buying_moves_stock_and_price() {
        let g = Galaxy::generate(0);
        let mut m = Market::generate(&g.sys[7], 1);
        let i = (0..NCOM).find(|&i| m.stock[i] > 3).unwrap();
        let s0 = m.stock[i];
        let p0 = m.buy(i).unwrap();
        assert_eq!(m.stock[i], s0 - 1);
        assert!(m.sell_price(i) <= p0 + 5);
        for _ in 0..m.stock[i] {
            m.buy(i);
        }
        assert!(m.buy(i).is_none());
    }
}
