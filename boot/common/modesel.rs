/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Video mode choice shared by the UEFI (GOP) and BIOS (VBE) front-ends.

The front-end lists the usable direct-colour modes, optionally the native size of the
monitor (EDID), and the id of the current mode. `choose` returns the index of the mode
to set (None: leave the current mode) and a short reason for the log.
*/
use alloc::string::String;

use crate::config::Resolution;

#[derive(Clone, Copy)]
pub struct Cand {
    pub w: u32,
    pub h: u32,
}

fn area(c: &Cand) -> u64 {
    c.w as u64 * c.h as u64
}

/// Index of the mode closest to w x h (exact match wins; ties go to the larger mode).
fn closest(modes: &[Cand], w: u32, h: u32) -> Option<usize> {
    let mut best: Option<(usize, u64)> = None;
    for (i, m) in modes.iter().enumerate() {
        let d = (m.w as i64 - w as i64).unsigned_abs() + (m.h as i64 - h as i64).unsigned_abs();
        if best.map_or(true, |(b, bd)| d < bd || (d == bd && area(m) > area(&modes[b]))) {
            best = Some((i, d));
        }
    }
    best.map(|(i, _)| i)
}

/// `current`: index of the mode that is active now, if it is in `modes`.
/// `native`: the monitor's preferred size from EDID, if known.
pub fn choose(res: Resolution, modes: &[Cand], native: Option<(u32, u32)>, current: Option<usize>) -> (Option<usize>, String) {
    if modes.is_empty() {
        return (None, String::from("no usable mode"));
    }
    match res {
        Resolution::Keep => (None, String::from("keep")),
        Resolution::Exact(w, h) => {
            let i = closest(modes, w, h).unwrap();
            let m = modes[i];
            if m.w == w && m.h == h {
                (Some(i), alloc::format!("{}x{} as requested", w, h))
            } else {
                (Some(i), alloc::format!("{}x{} not available, closest is {}x{}", w, h, m.w, m.h))
            }
        }
        Resolution::Max => {
            let fits = |m: &&Cand| native.map_or(true, |(nw, nh)| m.w <= nw && m.h <= nh);
            let pool_has = modes.iter().filter(fits).count() > 0;
            let mut best = 0;
            for (i, m) in modes.iter().enumerate() {
                if (!pool_has || fits(&m)) && (area(m) > area(&modes[best]) || (!pool_has || fits(&&modes[best])) == false) {
                    best = i;
                }
            }
            let m = modes[best];
            match native {
                Some((nw, nh)) if pool_has => (Some(best), alloc::format!("max {}x{} (monitor native {}x{})", m.w, m.h, nw, nh)),
                _ => (Some(best), alloc::format!("max {}x{}", m.w, m.h)),
            }
        }
        Resolution::Auto => {
            if let Some((nw, nh)) = native {
                let i = closest(modes, nw, nh).unwrap();
                return (Some(i), alloc::format!("monitor native {}x{} -> {}x{}", nw, nh, modes[i].w, modes[i].h));
            }
            if let Some(c) = current {
                return (None, alloc::format!("current mode {}x{}", modes[c].w, modes[c].h));
            }
            let i = closest(modes, 1024, 768).unwrap();
            (Some(i), alloc::format!("default {}x{}", modes[i].w, modes[i].h))
        }
    }
}
