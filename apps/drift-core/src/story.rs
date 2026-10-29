// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! The campaign: premise, chapters, characters and text. The stage logic lives in `game.rs`.
use crate::commander::*;
use alloc::string::String;

pub const INTRO: [&str; 6] = [
    "The Reach is eight clusters of stars strung along the old drift lanes. Ships do not cross the gaps between them. They fall through, into the drift, where distance is only a rumour.",
    "Something lives in the drift. The Vael have never answered a hail, never taken a cargo, never fired the first shot. For a century we called them weather.",
    "Then the Cinder Syndicate began cutting the anchors: small buoys that keep the drift's pockets closed. Every cut pocket leaks. Every leak brings the Vael nearer, and angrier.",
    "Your aunt Halda Venn flew couriers between the anchors. Three months ago her ship went silent near a pocket that was not on any chart.",
    "Yesterday her lawyer sent you a key, a sealed ledger, a debt, and the docking tag of a Tern-class runabout called the Moth Lark. The ship is old. The debt is not.",
    "You have a thousand credits, one pulse laser and a full tank of fuel. The rest is up to you.",
];

pub const ENDING: [&str; 5] = [
    "The Cinder Sovereign comes apart in slow, bright pieces. Marrow's last transmission is not a threat. It is a request to be let out of the drift.",
    "Nobody answers him. Oru-Ten's needles close the Mother Anchor from the inside, one door at a time, and the pocket folds shut like a hand.",
    "Over the following weeks the leaks stop. Wardens find the cut anchors re-sealed, their buoys humming. The Vael go back to being weather.",
    "Tobias Quill pays Halda's debt out of his own pocket and does not say so. Commander Anand files your name under a heading she has never used before.",
    "Somewhere in the drift, a pocket that was not on any chart opens for a moment, and a very old courier's beacon answers your ship's call. Then it is quiet. The lanes are open.",
];

pub const CREDITS: [(&str, &str); 9] = [
    ("DRIFT", ""),
    ("Design and direction", "ospab"),
    ("Engine and code", "ospab.os project"),
    ("Story", "ospab"),
    ("Galaxy generator, markets, flight model", "written for ospab.os"),
    ("Bitmap font", "public domain 8x8 set"),
    ("Platform", "ospab.os, ring 3, liboos"),
    ("Licence", "AGPL-3.0-only"),
    ("Copyright (c) 2026 ospab", ""),
];

pub enum Gate {
    None,
    Kills(u32),
    Credits(i64),
}

pub struct ChapterDef {
    pub title: &'static str,
    pub gate: Gate,
    pub accept: &'static [&'static str],
    pub done: &'static [&'static str],
    pub reward: i64,
}

pub fn chapter(n: u8) -> ChapterDef {
    match n {
        0 => ChapterDef {
            title: "First Light",
            gate: Gate::None,
            accept: &[
                "Dock control: Moth Lark, you are cleared for launch.",
                "Halda's checklist says to calibrate the nav beacon before every first flight. Launch, fly to the beacon, then come back and dock.",
                "A raises throttle, Z lowers it, the arrow keys steer. To dock, fly nose first through the slot with your wings level with it and move slowly. Press D if you have a docking computer. Press Tab for the full key map.",
            ],
            done: &["Flight school complete. A clean landing: Halda would have scraped the paint.", "The docking computer was on loan and has been returned. There is a message waiting for you on the contracts board (F11)."],
            reward: 150,
        },
        1 => ChapterDef {
            title: "The Sealed Ledger",
            gate: Gate::None,
            accept: &[
                "The ledger is addressed to Tobias Quill, a Guild broker at {0}.",
                "Halda's note on the cover: 'Deliver it by hand. Do not read it. Do not trust anyone who asks.'",
                "Take the package to {0}. Expect company on the way.",
            ],
            done: &[
                "Quill reads the ledger twice and closes it. 'Your aunt found an anchor map. The Syndicate wants it. So do I.'",
                "He pays for the delivery and asks you to come back once you have found what is left of her cargo.",
            ],
            reward: 600,
        },
        2 => ChapterDef {
            title: "Wreck of the Small Hours",
            gate: Gate::None,
            accept: &[
                "Quill's scanners saw three cargo canisters carrying Halda's seal, drifting at {1}. They came from her first ship, the Small Hours.",
                "You need a fuel scoop or a salvage tether to pick them up, and the Syndicate may have the same idea. Bring them back to {h}.",
            ],
            done: &["The canisters hold route charts and one half of an old key. Quill matches it against the Venn Key: two pieces of five."],
            reward: 900,
        },
        3 => ChapterDef {
            title: "Cinder Captain",
            gate: Gate::Kills(8),
            accept: &[
                "Syndicate raiders have been shadowing you. Their captain, Dann Corvane, flies a Hyena out of {1}.",
                "Commander Anand of the Warden service will pay for his head, and Quill wants whatever he carries. Come back to {h} when it is done.",
            ],
            done: &["Corvane's hold contained a third key fragment and an order signed by Director Kael Marrow: 'Cut every anchor. Leave the Mother Anchor for me.'"],
            reward: 1800,
        },
        4 => ChapterDef {
            title: "The Envoy",
            gate: Gate::Credits(2500),
            accept: &[
                "A Vael needle has been seen holding station at {1} and not attacking. If it is an envoy, it will speak to someone carrying the Venn Key.",
                "Fly to within a kilometre of it and hold your position. The key will do the rest. Then report to {h}.",
            ],
            done: &[
                "Oru-Ten speaks in clicks that the transcriber renders as sentences: 'The anchors are our doors. The Cinder man cuts them from outside.'",
                "'When the last door breaks we will come through, and we will not be gentle. Help us close them.'",
            ],
            reward: 2500,
        },
        5 => ChapterDef {
            title: "Anchor Run",
            gate: Gate::Kills(24),
            accept: &[
                "A Syndicate crew is cutting an anchor at {2}. Oru-Ten says the pocket will open within the hour.",
                "Destroy the raiders, then report to {h}.",
            ],
            done: &["The anchor holds. Oru-Ten sends a single word through the transcriber: 'Remaining.' It means there is one door left."],
            reward: 3500,
        },
        _ => ChapterDef {
            title: "The Cinder Sovereign",
            gate: Gate::Kills(64),
            accept: &[
                "Marrow's flagship, the Cinder Sovereign, is parked at the Mother Anchor at {2}, with an escort of Hyenas.",
                "Oru-Ten will hold the pocket open for you. If you lose, nobody closes it behind you. Fit every missile and every shield you can carry.",
            ],
            done: &[],
            reward: 10000,
        },
    }
}

pub fn gate_ok(g: &Gate, c: &Commander) -> bool {
    match g {
        Gate::None => true,
        Gate::Kills(k) => c.kills >= *k,
        Gate::Credits(cr) => c.credits >= *cr,
    }
}

pub fn gate_text(g: &Gate) -> String {
    match g {
        Gate::None => String::new(),
        Gate::Kills(k) => alloc::format!("Needs {} kills ({})", k, RANKS[rank_of(*k)].0),
        Gate::Credits(cr) => alloc::format!("Needs {} credits in hand", cr),
    }
}

/// Replace {0} {1} {2} {h} with system names.
pub fn fill(t: &str, names: &[String; 4]) -> String {
    let mut s = String::from(t);
    for (i, k) in ["{0}", "{1}", "{2}", "{h}"].iter().enumerate() {
        s = s.replace(k, &names[i]);
    }
    s
}
