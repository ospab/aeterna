// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// Performance sanity. Run with:
//   cargo test --release --test perf -- --ignored --nocapture --test-threads=1
// AETERNA_PERF_DIR selects where the 1 GiB image is created.
use aeternafs::dev::host::{FileDevice, MemDevice};
use aeternafs::{BlockDevice, Fs};
use std::time::Instant;

#[test]
#[ignore]
fn hundred_thousand_small_files() {
    let t = Instant::now();
    let dev = Fs::mkfs(MemDevice::new(262_144), "perf", 1).unwrap();
    let mut fs = Fs::mount(dev).unwrap();
    let body = [0x42u8; 100];
    for d in 0..100 {
        let dir = fs.mkdir_path(&format!("/d{:03}", d), 0o755).unwrap();
        for f in 0..1000 {
            let ino = fs.create(dir, &format!("file-{:05}.txt", f), 0o644).unwrap();
            fs.write(ino, 0, &body).unwrap();
        }
    }
    let t_create = t.elapsed();
    let t = Instant::now();
    fs.commit().unwrap();
    let t_commit = t.elapsed();
    let t = Instant::now();
    let mut fs = Fs::mount(fs.into_device()).unwrap();
    let t_mount = t.elapsed();
    let t = Instant::now();
    let mut n = 0;
    let mut buf = [0u8; 100];
    for d in 0..100 {
        let dir = fs.resolve(&format!("/d{:03}", d)).unwrap();
        for e in fs.readdir(dir).unwrap() {
            assert_eq!(fs.read(e.ino, 0, &mut buf).unwrap(), 100);
            n += 1;
        }
    }
    let t_scan = t.elapsed();
    assert_eq!(n, 100_000);
    let t = Instant::now();
    for d in 0..100 {
        let dir = fs.resolve(&format!("/d{:03}", d)).unwrap();
        for f in (0..1000).step_by(10) {
            fs.lookup(dir, &format!("file-{:05}.txt", f)).unwrap();
        }
    }
    let t_lookup = t.elapsed();
    let t = Instant::now();
    let r = fs.fsck(false).unwrap();
    assert!(r.is_ok(), "{:?}", r);
    let t_fsck = t.elapsed();
    println!("PERF small files: create+write 100k: {:?}, commit: {:?}, mount: {:?}", t_create, t_commit, t_mount);
    println!("PERF small files: readdir+read 100k: {:?}, 10k lookups: {:?}, fsck: {:?}", t_scan, t_lookup, t_fsck);
    println!("PERF fsck: {} inodes, {} tree nodes", r.inodes, r.nodes);
}

#[test]
#[ignore]
fn one_gib_file() {
    let dir = std::env::var("AETERNA_PERF_DIR").unwrap_or_else(|_| ".".into());
    let path = std::path::Path::new(&dir).join("aeterna-perf.img");
    let size: u64 = 1 << 30;
    let img = size + (96 << 20);
    {
        let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        f.set_len(img).unwrap();
    }
    let open = || FileDevice::new(std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap(), 0, img);
    let dev = Fs::mkfs(open(), "big", 1).unwrap();
    let mut fs = Fs::mount(dev).unwrap();
    let ino = fs.create_path("/big.bin", 0o644).unwrap();
    let chunk: Vec<u8> = (0..1 << 20).map(|i: usize| (i.wrapping_mul(2654435761) >> 7) as u8).collect();
    let t = Instant::now();
    for i in 0..1024u64 {
        fs.write(ino, i << 20, &chunk).unwrap();
    }
    fs.commit().unwrap();
    let w = t.elapsed();
    let mut fs = Fs::mount(fs.into_device()).unwrap();
    let t = Instant::now();
    let mut buf = vec![0u8; 1 << 20];
    for i in 0..1024u64 {
        let n = fs.read(ino, i << 20, &mut buf).unwrap();
        assert_eq!(n, 1 << 20);
        assert!(buf == chunk, "mismatch at MiB {}", i);
    }
    let r = t.elapsed();
    let t = Instant::now();
    let rep = fs.fsck(true).unwrap();
    let f = t.elapsed();
    assert!(rep.is_ok(), "{:?}", rep);
    let t = Instant::now();
    fs.unlink_path("/big.bin").unwrap();
    fs.commit().unwrap();
    let u = t.elapsed();
    let free = fs.statfs().free_blocks;
    println!("PERF 1 GiB: write+commit {:?} ({:.0} MiB/s), read+verify {:?} ({:.0} MiB/s), deep fsck {:?}, unlink+commit {:?}",
        w, 1024.0 / w.as_secs_f64(), r, 1024.0 / r.as_secs_f64(), f, u);
    println!("PERF 1 GiB: free blocks after delete {} of {}", free, fs.device().block_count());
    drop(fs);
    let _ = std::fs::remove_file(&path);
}
