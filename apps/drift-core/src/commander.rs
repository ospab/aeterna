// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! The player's persistent state: money, hold, equipment, legal record, missions, and its save format.
use crate::econ::*;
use alloc::string::String;
use alloc::vec::Vec;

pub const SAVE_SLOTS: usize = 5;
pub const SAVE_SIZE: usize = 256;
pub const FUGITIVE_HEAT: i32 = 50;
pub const OFFENDER_HEAT: i32 = 10;

pub const RANKS: [(&str, u32); 10] = [
    ("Stray", 0),
    ("Drifter", 4),
    ("Picket", 16),
    ("Lancer", 48),
    ("Striker", 128),
    ("Reaver", 320),
    ("Warhawk", 800),
    ("Sentinel", 2000),
    ("Paragon", 5000),
    ("Apex", 12000),
];

pub fn rank_of(kills: u32) -> usize {
    let mut r = 0;
    for (i, (_, k)) in RANKS.iter().enumerate() {
        if kills >= *k {
            r = i;
        }
    }
    r
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Legal {
    Clean,
    Offender,
    Fugitive,
}

pub const MISSION_LEDGER: u8 = 1;
pub const MISSION_HUNT: u8 = 2;
pub const MISSION_SALVAGE: u8 = 3;

/// A contract with its progress. `a`/`b` are star systems in galaxy `gal`; `origin` issued it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mission {
    pub kind: u8,
    pub stage: u8,
    pub gal: u8,
    pub origin: u8,
    pub a: u8,
    pub b: u8,
    pub reward: u32,
    pub progress: u8,
    pub seed: u16,
}

/// Progress through the main campaign.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Story {
    /// Current chapter 0..=6; 7 means the campaign is finished.
    pub chapter: u8,
    pub stage: u8,
    /// The chapter has been accepted at the contracts board.
    pub active: bool,
    pub progress: u8,
    /// Systems chosen for the chapter (galaxy 0).
    pub sys: [u8; 3],
    /// The broker's station.
    pub hub: u8,
    pub intro_seen: bool,
    pub free_play: bool,
}

pub const CHAPTERS: u8 = 7;

#[derive(Clone, Debug, PartialEq)]
pub struct Commander {
    pub name: String,
    pub credits: i64,
    /// Fuel in tenths of a light year.
    pub fuel: i32,
    pub galaxy: u8,
    pub system: u8,
    pub cargo: [u8; NCOM],
    pub lasers: [u8; 4],
    pub missiles: u8,
    pub equip: u32,
    pub damaged: u32,
    pub hold_level: u8,
    pub kills: u32,
    pub heat: i32,
    pub play_seconds: u32,
    pub market_tick: u32,
    pub jumps: u32,
    pub missions: Vec<Mission>,
    pub missions_done: u16,
    /// Sealed mission packages in the hold.
    pub sealed: u8,
    pub rng: u64,
    pub story: Story,
}

impl Commander {
    pub fn new(name: &str) -> Commander {
        Commander {
            name: String::from(name),
            credits: 1000,
            fuel: MAX_FUEL_TENTHS,
            galaxy: 0,
            system: 0,
            cargo: [0; NCOM],
            lasers: [LASER_PULSE, 0, 0, 0],
            missiles: 1,
            equip: 0,
            damaged: 0,
            hold_level: 0,
            kills: 0,
            heat: 0,
            play_seconds: 0,
            market_tick: 1,
            jumps: 0,
            missions: Vec::new(),
            missions_done: 0,
            sealed: 0,
            rng: 0x5EED_1234,
            story: Story::default(),
        }
    }
    pub fn hold_capacity(&self) -> i32 {
        HOLD_BASE + HOLD_STEP * self.hold_level as i32
    }
    pub fn hold_used(&self) -> i32 {
        self.cargo.iter().map(|&c| c as i32).sum::<i32>() + self.sealed as i32
    }
    pub fn hold_free(&self) -> i32 {
        self.hold_capacity() - self.hold_used()
    }
    pub fn has(&self, flag: u32) -> bool {
        self.equip & flag != 0 && self.damaged & flag == 0
    }
    pub fn legal(&self) -> Legal {
        if self.heat >= FUGITIVE_HEAT {
            Legal::Fugitive
        } else if self.heat >= OFFENDER_HEAT {
            Legal::Offender
        } else {
            Legal::Clean
        }
    }
    pub fn rank(&self) -> &'static str {
        RANKS[rank_of(self.kills)].0
    }
    pub fn illegal_units(&self) -> i32 {
        let mut n = 0;
        for (i, c) in COMMODITIES.iter().enumerate() {
            if c.illegal {
                n += self.cargo[i] as i32;
            }
        }
        n
    }
    pub fn max_fuel(&self) -> i32 {
        MAX_FUEL_TENTHS
    }

    // ---------------------------------------------------------------- save format

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b: Vec<u8> = Vec::with_capacity(SAVE_SIZE);
        b.extend_from_slice(b"DRFT");
        b.push(2);
        let name = self.name.as_bytes();
        let nl = name.len().min(16);
        b.push(nl as u8);
        b.extend_from_slice(&name[..nl]);
        b.extend_from_slice(&self.credits.to_le_bytes());
        b.extend_from_slice(&(self.fuel as i16).to_le_bytes());
        b.push(self.galaxy);
        b.push(self.system);
        b.extend_from_slice(&self.cargo);
        b.extend_from_slice(&self.lasers);
        b.push(self.missiles);
        b.extend_from_slice(&self.equip.to_le_bytes());
        b.extend_from_slice(&self.damaged.to_le_bytes());
        b.push(self.hold_level);
        b.extend_from_slice(&self.kills.to_le_bytes());
        b.extend_from_slice(&(self.heat as i16).to_le_bytes());
        b.extend_from_slice(&self.play_seconds.to_le_bytes());
        b.extend_from_slice(&self.market_tick.to_le_bytes());
        b.extend_from_slice(&self.jumps.to_le_bytes());
        b.extend_from_slice(&self.missions_done.to_le_bytes());
        b.push(self.sealed);
        b.extend_from_slice(&self.rng.to_le_bytes());
        let nm = self.missions.len().min(3);
        b.push(nm as u8);
        for m in self.missions.iter().take(3) {
            b.extend_from_slice(&[m.kind, m.stage, m.gal, m.origin, m.a, m.b, m.progress]);
            b.extend_from_slice(&m.reward.to_le_bytes());
            b.extend_from_slice(&m.seed.to_le_bytes());
        }
        let st = &self.story;
        b.extend_from_slice(&[st.chapter, st.stage, st.active as u8, st.progress, st.sys[0], st.sys[1], st.sys[2], st.hub, st.intro_seen as u8, st.free_play as u8]);
        let sum = fnv32(&b);
        b.extend_from_slice(&sum.to_le_bytes());
        while b.len() < SAVE_SIZE {
            b.push(0);
        }
        b
    }

    pub fn from_bytes(d: &[u8]) -> Option<Commander> {
        let mut r = Reader { d, p: 0 };
        if r.take(4)? != b"DRFT" || r.u8()? != 2 {
            return None;
        }
        let nl = r.u8()? as usize;
        if nl > 16 {
            return None;
        }
        let name = core::str::from_utf8(r.take(nl)?).ok()?;
        let mut c = Commander::new(name);
        c.credits = r.i64()?;
        c.fuel = r.i16()? as i32;
        c.galaxy = r.u8()?;
        c.system = r.u8()?;
        c.cargo.copy_from_slice(r.take(NCOM)?);
        c.lasers.copy_from_slice(r.take(4)?);
        c.missiles = r.u8()?;
        c.equip = r.u32()?;
        c.damaged = r.u32()?;
        c.hold_level = r.u8()?;
        c.kills = r.u32()?;
        c.heat = r.i16()? as i32;
        c.play_seconds = r.u32()?;
        c.market_tick = r.u32()?;
        c.jumps = r.u32()?;
        c.missions_done = r.u16()?;
        c.sealed = r.u8()?;
        c.rng = r.u64()?;
        let nm = r.u8()? as usize;
        if nm > 3 {
            return None;
        }
        for _ in 0..nm {
            let h = r.take(7)?;
            let reward = r.u32()?;
            let seed = r.u16()?;
            c.missions.push(Mission { kind: h[0], stage: h[1], gal: h[2], origin: h[3], a: h[4], b: h[5], progress: h[6], reward, seed });
        }
        let sb = r.take(10)?;
        c.story = Story { chapter: sb[0], stage: sb[1], active: sb[2] != 0, progress: sb[3], sys: [sb[4], sb[5], sb[6]], hub: sb[7], intro_seen: sb[8] != 0, free_play: sb[9] != 0 };
        if c.story.chapter > CHAPTERS {
            return None;
        }
        let end = r.p;
        let sum = r.u32()?;
        if fnv32(&d[..end]) != sum {
            return None;
        }
        if c.galaxy as usize >= crate::galaxy::GALAXIES || c.fuel < 0 || c.fuel > 255 {
            return None;
        }
        Some(c)
    }
}

pub fn fnv32(d: &[u8]) -> u32 {
    let mut h = 0x811C_9DC5u32;
    for &b in d {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

struct Reader<'a> {
    d: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.p + n > self.d.len() {
            return None;
        }
        let s = &self.d[self.p..self.p + n];
        self.p += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }
    fn i16(&mut self) -> Option<i16> {
        Some(self.u16()? as i16)
    }
    fn u32(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn i64(&mut self) -> Option<i64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Some(i64::from_le_bytes(a))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(self.i64()? as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn save_roundtrip() {
        let mut c = Commander::new("Rook");
        c.credits = 123456;
        c.fuel = 42;
        c.galaxy = 3;
        c.system = 99;
        c.cargo[3] = 7;
        c.cargo[14] = 2;
        c.lasers = [2, 1, 0, 4];
        c.equip = EQ_SCOOP | EQ_DOCKCOMP;
        c.damaged = EQ_DOCKCOMP;
        c.kills = 77;
        c.heat = 33;
        c.sealed = 1;
        c.story = Story { chapter: 3, stage: 1, active: true, progress: 2, sys: [4, 5, 6], hub: 9, intro_seen: true, free_play: false };
        c.missions.push(Mission { kind: 2, stage: 1, gal: 3, origin: 99, a: 12, b: 200, reward: 4000, progress: 2, seed: 777 });
        let b = c.to_bytes();
        assert_eq!(b.len(), SAVE_SIZE);
        let d = Commander::from_bytes(&b).unwrap();
        assert_eq!(c, d);
        let mut bad = b.clone();
        bad[20] ^= 1;
        assert!(Commander::from_bytes(&bad).is_none());
        assert!(Commander::from_bytes(&b[..10]).is_none());
    }
    #[test]
    fn ranks() {
        assert_eq!(rank_of(0), 0);
        assert_eq!(rank_of(48), 3);
        assert_eq!(RANKS[rank_of(100000)].0, "Apex");
    }
}
