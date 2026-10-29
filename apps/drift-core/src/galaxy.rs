// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Procedural universe: 8 galaxies of 256 star systems, generated from fixed seeds.
use crate::math::*;
use crate::space::PlanetKind;
use alloc::string::String;
use alloc::vec::Vec;

pub const GALAXIES: usize = 8;
pub const SYSTEMS: usize = 256;
const UNIVERSE_SEED: u64 = 0x6F5F_A57E_2D01_91C3;
/// Chart units per light year.
const UNITS_PER_LY: f32 = 6.0;
pub const MAX_JUMP_LY: f32 = 7.0;

pub const GOVERNMENTS: [&str; 8] = [
    "Free Compact",
    "Syndicate Rule",
    "Cantor Republic",
    "Mandate",
    "Warlord Holdings",
    "Theocracy",
    "Guild Federation",
    "Cogitate Assembly",
];
/// Law level 0..7: how hard illegal goods are policed.
pub const GOV_LAW: [u8; 8] = [1, 3, 5, 7, 0, 6, 4, 2];
const GOV_TECH: [i32; 8] = [0, 1, 2, 3, -1, 0, 2, 4];

pub const ECONOMIES: [&str; 8] = [
    "Dust Farms",
    "Hydro Ranches",
    "Ore Belts",
    "Foundry Worlds",
    "Hub Exchange",
    "Research Enclaves",
    "Pleasure Rings",
    "Salvage Yards",
];
const ECO_TECH: [i32; 8] = [1, 2, 2, 5, 6, 8, 5, 1];

const SYLLABLES: [&str; 36] = [
    "ka", "vo", "ren", "thu", "mi", "sar", "del", "oq", "zun", "bre", "lai", "nox", "pel", "yar", "ith", "cu", "gor", "fen", "wa", "tes", "ul", "dro",
    "vi", "an", "sho", "re", "qui", "hal", "bem", "ost", "jae", "mur", "pha", "xi", "tol", "eb",
];

const ADJ: [&str; 16] = [
    "windswept",
    "cratered",
    "storm-wrapped",
    "amber-skied",
    "low-gravity",
    "tidally locked",
    "ash-grey",
    "silent",
    "crowded",
    "mist-laden",
    "frost-bitten",
    "sun-scorched",
    "quiet",
    "fractured",
    "terraced",
    "brine-heavy",
];
const TRAIT: [&str; 16] = [
    "Dockers hold a feast whenever a ship arrives late",
    "Locals will not buy anything that was not repaired twice",
    "Contracts are sealed by trading names, not signatures",
    "Every household keeps a spare air filter by the door",
    "Children learn orbital arithmetic before they learn to read",
    "Debts are settled in public, with an audience",
    "Strangers are fed first and questioned afterwards",
    "Night is observed as a public holiday, once a year",
    "Elders arbitrate all disputes about water",
    "Pilots are expected to leave a gift at the shrine",
    "Nobody here admits to owning a weapon",
    "The tax office doubles as the post office",
    "Songs are used as legal evidence",
    "Rationing cards are treated as family heirlooms",
    "Visitors must register their boots, not their names",
    "Market days are announced by sirens",
];
const FAMOUS: [&str; 16] = [
    "bitter orchard spirits",
    "hand-cut glass lenses",
    "slow-brewed fuel tea",
    "lacquered ore carts",
    "a legendary pilots' school",
    "salvage auctions held at midnight",
    "tidal clocks",
    "deep-core drilling crews",
    "woven wire tapestries",
    "its unreliable weather forecasts",
    "spiced algae loaves",
    "copper-throated choirs",
    "reclaimed ship plating",
    "precision gears",
    "mirror gardens",
    "its endless customs forms",
];

#[derive(Clone, Debug)]
pub struct SystemInfo {
    pub galaxy: u8,
    pub index: u8,
    pub x: u8,
    pub y: u8,
    pub name: String,
    pub govt: u8,
    pub economy: u8,
    pub tech: u8,
    /// Population in units of 100 million.
    pub pop: u32,
    /// Gross product in millions of credits.
    pub gdp: u32,
    pub radius_km: u32,
    pub seed: u64,
    pub planet: PlanetKind,
    /// Star colour (RGB 0..1).
    pub star: [f32; 3],
}

impl SystemInfo {
    pub fn law(&self) -> u8 {
        GOV_LAW[self.govt as usize]
    }
    pub fn govt_name(&self) -> &'static str {
        GOVERNMENTS[self.govt as usize]
    }
    pub fn economy_name(&self) -> &'static str {
        ECONOMIES[self.economy as usize]
    }
    pub fn description(&self) -> String {
        let mut rng = Rng::new(self.seed ^ 0xDE5C);
        let kind = match self.planet {
            PlanetKind::Ocean => "ocean",
            PlanetKind::Arid => "desert",
            PlanetKind::Frozen => "ice",
            PlanetKind::Volcanic => "caldera",
            PlanetKind::Barren => "rock",
            PlanetKind::Jungle => "jungle",
        };
        let adj = ADJ[rng.below(16) as usize];
        let tr = TRAIT[rng.below(16) as usize];
        let fam = FAMOUS[rng.below(16) as usize];
        alloc::format!("A {} {} world under {} rule. {}. Known for {}.", adj, kind, self.govt_name(), tr, fam)
    }
}

pub struct Galaxy {
    pub index: usize,
    pub sys: Vec<SystemInfo>,
}

fn make_name(rng: &mut Rng) -> String {
    let n = 2 + rng.below(3) as usize;
    let mut s = String::new();
    let mut last = 99;
    for k in 0..n {
        let mut i = rng.below(36) as usize;
        if i == last {
            i = (i + 7) % 36;
        }
        last = i;
        let syl = SYLLABLES[i];
        if k == 0 {
            let mut ch = syl.chars();
            if let Some(c) = ch.next() {
                s.push(c.to_ascii_uppercase());
                s.push_str(ch.as_str());
            }
        } else {
            s.push_str(syl);
        }
    }
    s
}

impl Galaxy {
    pub fn generate(g: usize) -> Galaxy {
        let g = g % GALAXIES;
        let mut sys: Vec<SystemInfo> = Vec::with_capacity(SYSTEMS);
        for i in 0..SYSTEMS {
            let seed = mix64(UNIVERSE_SEED ^ ((g as u64) << 40) ^ ((i as u64) * 0x9E37_79B1));
            let mut rng = Rng::new(seed);
            // grid position: a bijective shuffle of the 16x16 cells plus jitter inside the cell
            let cell = (i * 167 + g * 41 + 13) % 256;
            let (cx, cy) = (cell % 16, cell / 16);
            let x = (cx * 16 + 1 + rng.below(13) as usize) as u8;
            let y = (cy * 16 + 1 + rng.below(13) as usize) as u8;
            // unique name inside the galaxy
            let mut name = make_name(&mut rng);
            let mut tries = 0;
            while sys.iter().any(|s| s.name == name) {
                name = make_name(&mut rng);
                tries += 1;
                if tries > 20 {
                    name.push_str(SYLLABLES[(i % 36) as usize]);
                }
            }
            let govt = rng.below(8) as u8;
            let economy = rng.below(8) as u8;
            let tech = clamp((1 + ECO_TECH[economy as usize] + GOV_TECH[govt as usize] + rng.below(4) as i32) as f32, 1.0, 14.0) as u8;
            let pop = 4 + rng.below(30 + tech as u32 * 14);
            let gdp = pop * (tech as u32 + 2) * (3 + rng.below(6));
            let radius_km = 2800 + rng.below(6800);
            let planet = match economy {
                0 => if rng.chance(0.7) { PlanetKind::Arid } else { PlanetKind::Barren },
                1 => if rng.chance(0.5) { PlanetKind::Jungle } else { PlanetKind::Ocean },
                2 => if rng.chance(0.6) { PlanetKind::Barren } else { PlanetKind::Frozen },
                3 => if rng.chance(0.6) { PlanetKind::Volcanic } else { PlanetKind::Arid },
                4 => PlanetKind::Ocean,
                5 => if rng.chance(0.6) { PlanetKind::Frozen } else { PlanetKind::Ocean },
                6 => if rng.chance(0.5) { PlanetKind::Jungle } else { PlanetKind::Ocean },
                _ => if rng.chance(0.5) { PlanetKind::Barren } else { PlanetKind::Volcanic },
            };
            let star = match rng.below(6) {
                0 => [1.0, 0.55, 0.30],
                1 => [1.0, 0.75, 0.40],
                2 | 3 => [1.0, 0.92, 0.65],
                4 => [0.90, 0.95, 1.0],
                _ => [0.65, 0.78, 1.0],
            };
            sys.push(SystemInfo { galaxy: g as u8, index: i as u8, x, y, name, govt, economy, tech, pop, gdp, radius_km, seed, planet, star });
        }
        Galaxy { index: g, sys }
    }

    pub fn dist_ly(&self, a: usize, b: usize) -> f32 {
        let (dx, dy) = (self.sys[a].x as f32 - self.sys[b].x as f32, self.sys[a].y as f32 - self.sys[b].y as f32);
        sqrt(dx * dx + dy * dy) / UNITS_PER_LY
    }

    /// System nearest to chart coordinates.
    pub fn nearest(&self, x: f32, y: f32) -> usize {
        let mut best = 0;
        let mut bd = f32::MAX;
        for (i, s) in self.sys.iter().enumerate() {
            let (dx, dy) = (s.x as f32 - x, s.y as f32 - y);
            let d = dx * dx + dy * dy;
            if d < bd {
                bd = d;
                best = i;
            }
        }
        best
    }

    pub fn find_name(&self, name: &str) -> Option<usize> {
        let n = name.trim();
        self.sys.iter().position(|s| s.name.eq_ignore_ascii_case(n))
    }

    /// System closest to the given one in direction of the chart cursor movement.
    pub fn step(&self, from: usize, dx: i32, dy: i32) -> usize {
        let (fx, fy) = (self.sys[from].x as f32, self.sys[from].y as f32);
        let dirv = (dx as f32, dy as f32);
        let mut best = from;
        let mut score = f32::MAX;
        for (i, s) in self.sys.iter().enumerate() {
            if i == from {
                continue;
            }
            let (vx, vy) = (s.x as f32 - fx, s.y as f32 - fy);
            let along = vx * dirv.0 + vy * dirv.1;
            if along <= 0.5 {
                continue;
            }
            let perp = abs(vx * dirv.1 - vy * dirv.0);
            let sc = sqrt(vx * vx + vy * vy) + perp * 1.5;
            if sc < score {
                score = sc;
                best = i;
            }
        }
        best
    }

    /// Position the player lands in when using the galactic drive: the nearest system in the next galaxy.
    pub fn galactic_arrival(&self, from: usize, next: &Galaxy) -> usize {
        next.nearest(self.sys[from].x as f32, self.sys[from].y as f32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_and_unique() {
        for g in 0..GALAXIES {
            let a = Galaxy::generate(g);
            let b = Galaxy::generate(g);
            assert_eq!(a.sys.len(), 256);
            for i in 0..256 {
                assert_eq!(a.sys[i].name, b.sys[i].name);
                assert_eq!((a.sys[i].x, a.sys[i].y), (b.sys[i].x, b.sys[i].y));
                assert_eq!(a.sys[i].tech, b.sys[i].tech);
            }
            for i in 0..256 {
                for j in 0..i {
                    assert_ne!(a.sys[i].name, a.sys[j].name);
                    assert!((a.sys[i].x, a.sys[i].y) != (a.sys[j].x, a.sys[j].y));
                }
            }
        }
        let a = Galaxy::generate(0);
        let b = Galaxy::generate(1);
        assert_ne!(a.sys[0].name, b.sys[0].name);
    }
    #[test]
    fn every_system_has_a_neighbour_in_jump_range() {
        for g in 0..GALAXIES {
            let a = Galaxy::generate(g);
            for i in 0..256 {
                let n = (0..256).filter(|&j| j != i && a.dist_ly(i, j) <= MAX_JUMP_LY).count();
                assert!(n >= 2, "galaxy {} system {} has {} neighbours", g, i, n);
            }
        }
    }
    #[test]
    fn data_ranges() {
        let a = Galaxy::generate(3);
        for s in &a.sys {
            assert!((1..=14).contains(&s.tech));
            assert!(s.govt < 8 && s.economy < 8);
            assert!(!s.description().is_empty());
        }
    }
}
