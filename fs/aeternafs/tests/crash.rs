// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// Crash consistency: cut the power after every N-th block write, drop and
// reorder unflushed writes, tear writes, remount. The result must be exactly
// the last committed state or the one being committed, and fsck must pass.
mod common;
use aeternafs::dev::host::{FaultDevice, MemDevice, Rng};
use aeternafs::{Error, Fs};
use common::*;
use std::collections::BTreeMap;

const BLOCKS: u64 = 2048;

/// Runs the deterministic workload. `states[k]` is the model after k successful
/// commits (state 0 is the freshly formatted fs). Returns the device.
fn workload(dev: FaultDevice, seed: u64, steps: usize, states: &mut Vec<Model>) -> FaultDevice {
    let mut fs = match Fs::mount(dev) {
        Ok(f) => f,
        Err(_) => unreachable!("mount before the cut cannot fail"),
    };
    let mut model = Model::new();
    let mut g = Gen::new(seed);
    g.big = false;
    let mut rng = Rng::new(seed ^ 0xABCD);
    let mut snaps: BTreeMap<String, Model> = BTreeMap::new();
    states.push(model.clone());
    let res: Result<(), Error> = (|| {
        for step in 0..steps {
            for _ in 0..10 {
                random_op(&mut fs, &mut model, &mut g)?;
            }
            fs.commit()?;
            states.push(model.clone());
            match (step % 5, rng.below(3)) {
                (2, _) | (4, 0) => {
                    let name = format!("s{}", step);
                    fs.snapshot_create(&name)?;
                    snaps.insert(name, model.clone());
                    states.push(model.clone());
                }
                (3, 0) if !snaps.is_empty() => {
                    let name = snaps.keys().next().unwrap().clone();
                    fs.snapshot_delete(&name)?;
                    snaps.remove(&name);
                    states.push(model.clone());
                }
                (4, 1) if !snaps.is_empty() => {
                    let name = snaps.keys().last().unwrap().clone();
                    fs.snapshot_rollback(&name)?;
                    model = snaps[&name].clone();
                    states.push(model.clone());
                }
                _ => {}
            }
        }
        Ok(())
    })();
    let _ = res;
    fs.into_device()
}

fn base_image() -> Vec<u8> {
    Fs::mkfs(MemDevice::new(BLOCKS), "crash", 5).unwrap().data
}

fn run_crash_test(seed: u64, steps: usize, images_per_point: u64) -> (u64, u64) {
    let img = base_image();
    // uncut reference run
    let mut all = Vec::new();
    let dev = workload(FaultDevice::new(img.clone(), None), seed, steps, &mut all);
    let total = dev.writes;
    assert!(all.len() > steps, "reference run must not fail");
    let mut points = 0;
    let mut checked = 0;
    for n in 0..=total {
        let mut got = Vec::new();
        let dev = workload(FaultDevice::new(img.clone(), Some(n)), seed, steps, &mut got);
        let done = got.len() - 1;
        for s in 0..images_per_point {
            let crashed = dev.crash_image(n * 31 + s + seed * 1000);
            let mut fs = match Fs::mount(MemDevice::from_vec(crashed)) {
                Ok(f) => f,
                Err(e) => panic!("seed {} cut {} image {}: mount failed: {:?}", seed, n, s, e),
            };
            let d = dump(&mut fs).unwrap_or_else(|e| panic!("seed {} cut {}: dump failed {:?}", seed, n, e));
            let ok = d == all[done] || (done + 1 < all.len() && d == all[done + 1]);
            assert!(ok, "seed {} cut {} image {}: state is neither commit {} nor {}", seed, n, s, done, done + 1);
            let r = fs.fsck(true).unwrap();
            assert!(r.is_ok(), "seed {} cut {} image {}: fsck {:?}", seed, n, s, r);
            // the recovered fs must be usable: write, commit, remount
            fs.write_file("/after-crash", b"ok").unwrap();
            let mut fs = remount(fs);
            assert_eq!(fs.read_file("/after-crash").unwrap(), b"ok");
            let r = fs.fsck(false).unwrap();
            assert!(r.is_ok(), "seed {} cut {} image {}: fsck after use {:?}", seed, n, s, r);
            checked += 1;
        }
        points += 1;
    }
    (points, checked)
}

#[test]
fn power_cut_at_every_write() {
    let mut points = 0;
    let mut checked = 0;
    for seed in [1u64, 2, 3, 4, 5, 6] {
        let (p, c) = run_crash_test(seed, 30, 4);
        points += p;
        checked += c;
    }
    println!("CRASH: {} power-cut points, {} crash images checked, all consistent", points, checked);
}
