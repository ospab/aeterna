// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
mod common;
use aeternafs::dev::host::{MemDevice, Rng};
use aeternafs::{Error, Fs};
use common::*;
use std::collections::BTreeMap;

fn check(fs: &mut Fs<MemDevice>, m: &Model, what: &str) {
    let d = dump(fs).unwrap();
    if d != *m {
        for (k, v) in m {
            if d.get(k) != Some(v) { panic!("{}: mismatch at {} (model {:?}, fs {:?})", what, k, v.clone().short(), d.get(k).cloned().map(|x| x.short())); }
        }
        for k in d.keys() { if !m.contains_key(k) { panic!("{}: extra {}", what, k); } }
    }
}

trait Short { fn short(self) -> String; }
impl Short for Entry {
    fn short(self) -> String {
        match self { Entry::Dir => "dir".into(), Entry::File(v) => format!("file({} bytes)", v.len()), Entry::Link(t) => format!("link {}", t) }
    }
}

#[test]
fn basics() {
    let mut fs = new_fs(2048);
    let d = fs.mkdir_path("/etc", 0o755).unwrap();
    fs.write_file("/etc/motd", b"hello").unwrap();
    fs.write_file("/readme", &vec![7u8; 10_000]).unwrap();
    assert_eq!(fs.lookup(d, "motd").is_ok(), true);
    let mut fs = remount(fs);
    assert_eq!(fs.read_file("/etc/motd").unwrap(), b"hello");
    assert_eq!(fs.read_file("/readme").unwrap(), vec![7u8; 10_000]);
    assert_eq!(fs.label(), "test");
    assert!(matches!(fs.mkdir_path("/etc", 0o755), Err(Error::Exists)));
    assert!(matches!(fs.rmdir_path("/etc"), Err(Error::NotEmpty)));
    assert!(matches!(fs.resolve("/nope"), Err(Error::NotFound)));
    let long = "x".repeat(256);
    assert!(matches!(fs.create_path(&format!("/{}", long), 0o644), Err(Error::NameTooLong)));
    let ok255 = "ж".repeat(127); // 254 bytes
    fs.create_path(&format!("/{}", ok255), 0o644).unwrap();
    fs.rename_path("/readme", "/etc/motd").unwrap();
    assert_eq!(fs.read_file("/etc/motd").unwrap().len(), 10_000);
    let r = fs.fsck(true).unwrap();
    assert!(r.is_ok(), "{:?}", r);
    fs.commit().unwrap();
    let r = fs.fsck(true).unwrap();
    assert!(r.is_ok(), "{:?}", r);
}

#[test]
fn sparse_and_truncate() {
    let mut fs = new_fs(4096);
    let ino = fs.create_path("/f", 0o644).unwrap();
    fs.write(ino, 1_000_000, b"tail").unwrap();
    let mut b = vec![1u8; 20];
    assert_eq!(fs.read(ino, 500_000, &mut b).unwrap(), 20);
    assert_eq!(b, vec![0u8; 20]);
    fs.truncate(ino, 100).unwrap();
    fs.truncate(ino, 9000).unwrap();
    let mut b = vec![1u8; 9000];
    fs.read(ino, 0, &mut b).unwrap();
    assert!(b.iter().all(|&x| x == 0));
    fs.write(ino, 4090, b"0123456789").unwrap();
    let mut b = vec![0u8; 10];
    fs.read(ino, 4090, &mut b).unwrap();
    assert_eq!(&b, b"0123456789");
    let r = fs.fsck(true).unwrap();
    assert!(r.is_ok(), "{:?}", r);
}

#[test]
fn many_entries_in_one_dir() {
    let mut fs = new_fs(16384);
    let d = fs.mkdir_path("/big", 0o755).unwrap();
    for i in 0..20_000 {
        let ino = fs.create(d, &format!("file-{:06}", i), 0o644).unwrap();
        if i % 100 == 0 { fs.write(ino, 0, b"x").unwrap(); }
    }
    let mut fs = remount(fs);
    let d = fs.resolve("/big").unwrap();
    assert_eq!(fs.readdir(d).unwrap().len(), 20_000);
    assert!(fs.lookup(d, "file-019999").is_ok());
    for i in (0..20_000).step_by(2) {
        fs.unlink(d, &format!("file-{:06}", i)).unwrap();
    }
    assert_eq!(fs.readdir(d).unwrap().len(), 10_000);
    let r = fs.fsck(false).unwrap();
    assert!(r.is_ok(), "{:?}", r);
}

#[test]
fn space_is_reclaimed() {
    let mut fs = new_fs(4096);
    fs.commit().unwrap();
    let free0 = fs.statfs().free_blocks;
    for round in 0..5 {
        for i in 0..20 {
            fs.write_file(&format!("/f{}", i), &vec![round as u8; 100_000]).unwrap();
        }
        fs.commit().unwrap();
    }
    for i in 0..20 {
        fs.unlink_path(&format!("/f{}", i)).unwrap();
    }
    fs.commit().unwrap();
    fs.commit().unwrap();
    let free1 = fs.statfs().free_blocks;
    assert!(free0 - free1 < 8, "leak: {} -> {}", free0, free1);
    let r = fs.fsck(false).unwrap();
    assert!(r.is_ok(), "{:?}", r);
}

#[test]
fn nospace_is_reported() {
    let mut fs = new_fs(1024);
    let ino = fs.create_path("/f", 0o644).unwrap();
    let chunk = vec![5u8; 65536];
    let mut off = 0u64;
    let r = loop {
        match fs.write(ino, off, &chunk) {
            Ok(()) => off += chunk.len() as u64,
            Err(e) => break e,
        }
    };
    assert_eq!(r, Error::NoSpace);
    fs.commit().unwrap();
    fs.unlink_path("/f").unwrap();
    fs.commit().unwrap();
    fs.write_file("/g", b"after").unwrap();
    let rep = fs.fsck(true).unwrap();
    assert!(rep.is_ok(), "{:?}", rep);
}

#[test]
fn random_ops_match_model() {
    for seed in 1..=12u64 {
        let mut fs = new_fs(8192);
        let mut model = Model::new();
        let mut g = Gen::new(seed);
        for i in 0..1500 {
            random_op(&mut fs, &mut model, &mut g).unwrap();
            if i % 97 == 0 {
                fs.commit().unwrap();
            }
            if i % 301 == 300 {
                fs = remount(fs);
            }
            if i % 250 == 249 {
                check(&mut fs, &model, &format!("seed {} op {}", seed, i));
            }
        }
        check(&mut fs, &model, "final");
        fs.commit().unwrap();
        let r = fs.fsck(true).unwrap();
        assert!(r.is_ok(), "seed {}: {:?}", seed, r);
        let mut fs = remount(fs);
        check(&mut fs, &model, "after remount");
        let r = fs.fsck(true).unwrap();
        assert!(r.is_ok(), "seed {}: {:?}", seed, r);
    }
}

#[test]
fn snapshots_match_model() {
    for seed in 1..=8u64 {
        let mut fs = new_fs(8192);
        let mut model = Model::new();
        let mut snaps: BTreeMap<String, Model> = BTreeMap::new();
        let mut g = Gen::new(seed * 77);
        let mut rng = Rng::new(seed);
        for i in 0..1200 {
            random_op(&mut fs, &mut model, &mut g).unwrap();
            if i % 40 == 39 {
                fs.commit().unwrap();
                let r = fs.fsck(false).unwrap();
                assert!(r.is_ok(), "seed {} op {} before snapshot op: {:?}", seed, i, r);
                match rng.below(5) {
                    0 | 1 => {
                        let name = format!("s{}", i);
                        fs.snapshot_create(&name).unwrap();
                        snaps.insert(name, model.clone());
                    }
                    2 if !snaps.is_empty() => {
                        let name = snaps.keys().nth(rng.below(snaps.len() as u64) as usize).unwrap().clone();
                        fs.snapshot_delete(&name).unwrap();
                        snaps.remove(&name);
                    }
                    3 if !snaps.is_empty() => {
                        let name = snaps.keys().nth(rng.below(snaps.len() as u64) as usize).unwrap().clone();
                        fs.snapshot_rollback(&name).unwrap();
                        model = snaps[&name].clone();
                        check(&mut fs, &model, "after rollback");
                    }
                    _ => {}
                }
                // every snapshot still shows its own state
                let list = fs.snapshot_list().unwrap();
                assert_eq!(list.len(), snaps.len());
                for s in list {
                    let d = dump_at(&mut fs, s.root).unwrap_or_else(|e| panic!("seed {} op {} snapshot {} (gen {}): {:?}; snaps {:?}", seed, i, s.name, s.gen, e, snaps.keys().collect::<Vec<_>>()));
                    assert_eq!(&d, &snaps[&s.name], "snapshot {} changed", s.name);
                }
                if i % 160 == 159 {
                    fs = remount(fs);
                }
                let r = fs.fsck(false).unwrap();
                assert!(r.is_ok(), "seed {} op {}: {:?}", seed, i, r);
            }
        }
        check(&mut fs, &model, "final");
        // deleting all snapshots gives back all space
        for name in snaps.keys().cloned().collect::<Vec<_>>() {
            fs.snapshot_delete(&name).unwrap();
        }
        let r = fs.fsck(true).unwrap();
        assert!(r.is_ok(), "seed {}: {:?}", seed, r);
        check(&mut fs, &model, "after deleting snapshots");
    }
}

#[test]
fn snapshot_view_and_names() {
    let mut fs = new_fs(2048);
    fs.write_file("/a", b"one").unwrap();
    fs.snapshot_create("before-update").unwrap();
    fs.write_file("/a", b"two!").unwrap();
    assert!(matches!(fs.snapshot_create("before-update"), Err(Error::Exists)));
    assert!(matches!(fs.snapshot_delete("zzz"), Err(Error::NoSuchSnapshot)));
    {
        let mut v = fs.snapshot_view("before-update").unwrap();
        let i = v.resolve("/a").unwrap();
        let mut b = [0u8; 8];
        let n = v.read(i, 0, &mut b).unwrap();
        assert_eq!(&b[..n], b"one");
    }
    assert_eq!(fs.read_file("/a").unwrap(), b"two!");
    fs.snapshot_rollback("before-update").unwrap();
    assert_eq!(fs.read_file("/a").unwrap(), b"one");
    assert_eq!(fs.snapshot_list().unwrap().len(), 1);
}
