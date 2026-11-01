/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
ospab-boot update state: boot counter and automatic fallback to the previous kernel.

Shared by the UEFI and BIOS front-ends (included with #[path]); the kernel side lives in
src/esp.rs and writes the same file format. Documentation: docs/en/boot.md ("Updating the system").

`tomato upgrade` installs a new kernel as KERNEL, keeps the old one as KERNEL.OLD and writes the
state file UPDATE.ST (next to ospab.cfg) with `pending=1 tries=2`. The state file is exactly
512 bytes, so the loader can overwrite it in place without touching the FAT:

    ospab-update 1
    pending=1                 the new kernel has not reported a good boot yet
    tries=2                   boots of the new kernel still allowed
    failed=0                  1: the loader gave up on the new kernel (the previous one is used)
    kernel=/boot/KERNEL       path of the new kernel as written in ospab.cfg
    old=/boot/KERNEL.OLD      path of the previous kernel
    version=1.1.0.191         new version
    previous=1.1.0.190        previous version

Loader, on every start:
  - `pending=1 tries>0`: booting an entry whose kernel is `kernel=` counts one try (tries-1, written
    before the jump) and adds `update_try=1` to the command line;
  - `pending=1 tries=0`: the kernel never reported success in `MAX_TRIES` boots: the state becomes
    `pending=0 failed=1` and every entry that boots `kernel=` boots `old=` instead; the menu says why;
  - `failed=1`: same fallback, until the next update replaces the state.
The kernel clears `pending` (tries=0) once its console is ready, but only when it was started with
`update_try=1`, so booting the previous kernel by hand never confirms the new one.
*/
use alloc::string::{String, ToString};

use crate::config::{Config, EntryType, MAX_CMDLINE};

pub const STATE_NAME: &str = "UPDATE.ST";
pub const STATE_SIZE: usize = 512;
const MAGIC: &str = "ospab-update 1";

#[derive(Clone, PartialEq)]
pub struct State {
    pub pending: bool,
    pub tries: u32,
    pub failed: bool,
    pub kernel: String,
    pub old: String,
    pub version: String,
    pub previous: String,
}

/// Directory part of a config path plus the state file name: "/boot/ospab.cfg" -> "/boot/UPDATE.ST".
pub fn state_path(cfg_path: &str) -> String {
    let dir = cfg_path.rfind('/').map(|i| &cfg_path[..i]).unwrap_or("");
    alloc::format!("{}/{}", dir, STATE_NAME)
}

fn same_path(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Parse a state file; `None` when it is not one (the loader then ignores it).
pub fn parse(raw: &[u8]) -> Option<State> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let text = core::str::from_utf8(&raw[..end]).ok()?;
    let mut lines = text.lines();
    if lines.next()?.trim() != MAGIC {
        return None;
    }
    let mut s = State {
        pending: false,
        tries: 0,
        failed: false,
        kernel: String::new(),
        old: String::new(),
        version: String::new(),
        previous: String::new(),
    };
    for l in lines {
        let Some((k, v)) = l.split_once('=') else { continue };
        let v = v.trim();
        match k.trim() {
            "pending" => s.pending = v == "1",
            "failed" => s.failed = v == "1",
            "tries" => s.tries = v.parse().ok()?,
            "kernel" => s.kernel = v.to_string(),
            "old" => s.old = v.to_string(),
            "version" => s.version = v.to_string(),
            "previous" => s.previous = v.to_string(),
            _ => {}
        }
    }
    if !s.kernel.starts_with('/') || !s.old.starts_with('/') || s.tries > 9 {
        return None;
    }
    Some(s)
}

/// The 512 bytes to store. `None` when the text does not fit.
pub fn encode(s: &State) -> Option<[u8; STATE_SIZE]> {
    let text = alloc::format!(
        "{}\npending={}\ntries={}\nfailed={}\nkernel={}\nold={}\nversion={}\nprevious={}\n",
        MAGIC, s.pending as u8, s.tries, s.failed as u8, s.kernel, s.old, s.version, s.previous
    );
    if text.len() >= STATE_SIZE {
        return None;
    }
    let mut out = [0u8; STATE_SIZE];
    out[..text.len()].copy_from_slice(text.as_bytes());
    Some(out)
}

/// What the loader decided at start-up.
pub struct Outcome {
    /// Shown above the footer of the menu.
    pub notice: Option<String>,
    /// New state to store right away (the fallback decision).
    pub write: Option<State>,
    /// The state, as it is after this step.
    pub state: State,
}

fn append_cmdline(cmdline: &mut String, extra: &str) {
    if cmdline.len() + 1 + extra.len() <= MAX_CMDLINE {
        if !cmdline.is_empty() {
            cmdline.push(' ');
        }
        cmdline.push_str(extra);
    }
}

/// Apply the state to the configuration: after a failed update every entry that boots the new
/// kernel boots the previous one. `old_exists` tells whether the previous kernel file is there.
pub fn evaluate(cfg: &mut Config, mut st: State, old_exists: bool) -> Outcome {
    let mut write = None;
    if st.pending && st.tries == 0 {
        st.pending = false;
        st.failed = true;
        write = Some(st.clone());
    }
    if !st.failed {
        let notice = if st.pending {
            Some(alloc::format!(
                "System update {} is on trial: {} boot(s) left before the previous kernel {} is used.",
                st.version, st.tries, st.previous
            ))
        } else {
            None
        };
        return Outcome { notice, write, state: st };
    }
    if !old_exists {
        let notice = alloc::format!(
            "Update {} did not start, but the previous kernel {} is missing; trying the new one again.",
            st.version, st.old
        );
        return Outcome { notice: Some(notice), write, state: st };
    }
    for e in cfg.entries.iter_mut().filter(|e| e.typ == EntryType::Ospab) {
        if !same_path(&e.kernel, &st.kernel) {
            continue;
        }
        let from = e.kernel.clone();
        e.kernel = st.old.clone();
        for m in e.modules.iter_mut().filter(|m| same_path(&m.0, &from)) {
            m.0 = st.old.clone();
        }
        append_cmdline(&mut e.cmdline, "update_fallback=1");
    }
    let notice = alloc::format!(
        "System update {} failed to start {} times. Booting the previous kernel {} ({}). A new tomato upgrade tries again.",
        st.version, MAX_TRIES, st.previous, st.old
    );
    Outcome { notice: Some(notice), write, state: st }
}

pub const MAX_TRIES: u32 = 2;

/// Called right before an `ospab` entry boots. When this boot is a trial of the new kernel,
/// returns the state to store (one try used) and adds `update_try=1` to the command line.
pub fn trial_boot(st: &State, kernel: &str, cmdline: &mut String) -> Option<State> {
    if !st.pending || st.tries == 0 || !same_path(kernel, &st.kernel) {
        return None;
    }
    append_cmdline(cmdline, "update_try=1");
    let mut next = st.clone();
    next.tries -= 1;
    Some(next)
}
