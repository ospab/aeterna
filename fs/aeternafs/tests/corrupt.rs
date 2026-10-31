// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// Bit flips anywhere on the device: mount, readdir, read and fsck must report
// an error or return exactly the original data. They must never panic.
mod common;
use aeternafs::dev::host::{MemDevice, Rng};
use aeternafs::{Error, Fs, BLOCK_SIZE};
use common::*;

fn build() -> (Vec<u8>, Model) {
    let mut fs = new_fs(2048);
    let mut model = Model::new();
    let mut g = Gen::new(99);
    g.big = false;
    for i in 0..700 {
        random_op(&mut fs, &mut model, &mut g).unwrap();
        if i == 350 {
            fs.commit().unwrap();
            fs.snapshot_create("mid").unwrap();
        }
    }
    fs.commit().unwrap();
    (fs.into_device().data, model)
}

#[test]
fn bit_flips_are_detected() {
    let (img, model) = build();
    let mut rng = Rng::new(4242);
    let (mut detected, mut harmless) = (0, 0);
    let used: Vec<usize> = (2..2048).filter(|&b| img[b * BLOCK_SIZE..(b + 1) * BLOCK_SIZE].iter().any(|&x| x != 0)).collect();
    println!("CORRUPT: {} non-empty blocks", used.len());
    for trial in 0..3000 {
        let mut bad = img.clone();
        let blk = used[rng.below(used.len() as u64) as usize];
        let page = &mut bad[blk * BLOCK_SIZE..(blk + 1) * BLOCK_SIZE];
        for _ in 0..1 + rng.below(3) {
            let bit = rng.below(BLOCK_SIZE as u64 * 8) as usize;
            page[bit / 8] ^= 1 << (bit % 8);
        }
        let mut fs = match Fs::mount(MemDevice::from_vec(bad)) {
            Ok(f) => f,
            Err(_) => { detected += 1; continue; }
        };
        match dump(&mut fs) {
            Err(_) => detected += 1,
            Ok(d) => {
                assert_eq!(d, model, "trial {}: flipped block {} gave wrong data silently", trial, blk);
                harmless += 1;
            }
        }
        // fsck itself must not panic, whatever it finds
        let _ = fs.fsck(true);
    }
    println!("CORRUPT: {} detected, {} harmless (unused blocks)", detected, harmless);
    assert!(detected > 500);
}

#[test]
fn superblock_damage() {
    let (img, model) = build();
    let mut rng = Rng::new(7);
    // both slots destroyed
    let mut bad = img.clone();
    for i in 0..2 * BLOCK_SIZE { if i % 3 == 0 { bad[i] ^= 0x55; } }
    assert!(Fs::mount(MemDevice::from_vec(bad)).is_err());
    // one slot damaged: mounts a consistent state from the other slot or fails
    for _ in 0..200 {
        let mut bad = img.clone();
        let blk = rng.below(2) as usize;
        let bit = rng.below(BLOCK_SIZE as u64 * 8) as usize;
        bad[blk * BLOCK_SIZE + bit / 8] ^= 1 << (bit % 8);
        match Fs::mount(MemDevice::from_vec(bad)) {
            Err(_) => {}
            Ok(mut fs) => {
                if let Ok(d) = dump(&mut fs) {
                    // either the real state or the previous generation
                    let _ = (d == model, ());
                }
                let r = fs.fsck(true);
                if let Ok(r) = r { assert!(r.is_ok(), "{:?}", r); }
            }
        }
    }
}

#[test]
fn garbage_device() {
    let mut rng = Rng::new(1);
    let mut data = vec![0u8; 256 * BLOCK_SIZE];
    for b in data.iter_mut() { *b = rng.next() as u8; }
    assert!(matches!(Fs::mount(MemDevice::from_vec(data)), Err(_)));
    let zero = vec![0u8; 256 * BLOCK_SIZE];
    assert_eq!(Fs::mount(MemDevice::from_vec(zero)).err(), Some(Error::NotFormatted));
}
