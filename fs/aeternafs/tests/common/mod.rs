// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// Shared test helpers: model filesystem, random operations, dump.
#![allow(dead_code)]

use aeternafs::dev::host::{MemDevice, Rng};
use aeternafs::{BlockDevice, Error, Fs, S_IFDIR, S_IFLNK, S_IFMT};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Dir,
    File(Vec<u8>),
    Link(String),
}

pub type Model = BTreeMap<String, Entry>;

pub fn new_fs(blocks: u64) -> Fs<MemDevice> {
    let dev = Fs::mkfs(MemDevice::new(blocks), "test", 1_000_000).unwrap();
    Fs::mount(dev).unwrap()
}

pub fn remount<D: BlockDevice>(fs: Fs<D>) -> Fs<D> {
    let mut fs = fs;
    fs.commit().unwrap();
    Fs::mount(fs.into_device()).unwrap()
}

/// Reads the whole tree below `root` into a model-shaped map.
pub fn dump_at<D: BlockDevice>(fs: &mut Fs<D>, root: u64) -> Result<Model, Error> {
    let mut out = Model::new();
    let mut stack = vec![(String::new(), 1u64)];
    while let Some((path, ino)) = stack.pop() {
        for e in fs.readdir_in(root, ino)? {
            let p = format!("{}/{}", path, e.name);
            match e.mode_type & S_IFMT {
                S_IFDIR => {
                    out.insert(p.clone(), Entry::Dir);
                    stack.push((p, e.ino));
                }
                S_IFLNK => {
                    out.insert(p, Entry::Link(fs.readlink_in(root, e.ino)?));
                }
                _ => {
                    let st = fs.stat_in(root, e.ino)?;
                    let mut v = vec![0u8; st.size as usize];
                    let n = fs.read_in(root, e.ino, 0, &mut v)?;
                    assert_eq!(n, v.len());
                    out.insert(p, Entry::File(v));
                }
            }
        }
    }
    Ok(out)
}

pub fn dump<D: BlockDevice>(fs: &mut Fs<D>) -> Result<Model, Error> {
    let root = fs.live_root();
    dump_at(fs, root)
}

fn parent(p: &str) -> &str {
    &p[..p.rfind('/').unwrap()]
}

pub struct Gen {
    pub rng: Rng,
    pub big: bool,
    pool: Vec<&'static str>,
}

impl Gen {
    pub fn new(seed: u64) -> Gen {
        Gen { rng: Rng::new(seed), big: true, pool: vec!["a", "b", "c", "d", "e", "f"] }
    }
    pub fn path(&mut self) -> String {
        let depth = 1 + self.rng.below(3) as usize;
        let mut s = String::new();
        for _ in 0..depth {
            s.push('/');
            s.push_str(self.pool[self.rng.below(self.pool.len() as u64) as usize]);
        }
        s
    }
    /// Prefers existing paths.
    pub fn existing_or_new(&mut self, m: &Model) -> String {
        if !m.is_empty() && self.rng.below(4) != 0 {
            let i = self.rng.below(m.len() as u64) as usize;
            m.keys().nth(i).unwrap().clone()
        } else {
            self.path()
        }
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let kind = self.rng.below(3);
        let b = self.rng.next() as u8;
        (0..n)
            .map(|i| match kind {
                0 => b,
                1 => (i as u8).wrapping_add(b),
                _ => self.rng.next() as u8,
            })
            .collect()
    }
}

fn parent_is_dir(m: &Model, p: &str) -> bool {
    let par = parent(p);
    par.is_empty() || m.get(par) == Some(&Entry::Dir)
}

fn has_children(m: &Model, p: &str) -> bool {
    let pre = format!("{}/", p);
    m.keys().any(|k| k.starts_with(&pre))
}

/// Applies one random operation to the filesystem and the model.
/// Returns Err only for filesystem errors that the model does not predict.
pub fn random_op<D: BlockDevice>(fs: &mut Fs<D>, m: &mut Model, g: &mut Gen) -> Result<(), Error> {
    let op = g.rng.below(100);
    if op < 12 {
        let p = g.path();
        let expect = !m.contains_key(&p) && parent_is_dir(m, &p);
        let r = fs.mkdir_path(&p, 0o755);
        match (r, expect) {
            (Ok(_), true) => { m.insert(p, Entry::Dir); }
            (Err(Error::Io), _) => return Err(Error::Io),
            (Err(Error::Poisoned), _) => return Err(Error::Poisoned),
            (r, e) => assert_eq!(r.is_ok(), e, "mkdir {}: {:?}", p, r),
        }
    } else if op < 50 {
        let p = g.existing_or_new(m);
        let off = if g.rng.below(3) == 0 { 0 } else { g.rng.below(20000) as usize };
        let big = g.big && g.rng.below(40) == 0;
        let len = if big { 300_000 + g.rng.below(800_000) as usize } else { g.rng.below(12000) as usize };
        let data = g.bytes(len);
        let ok_target = match m.get(&p) {
            None => parent_is_dir(m, &p),
            Some(Entry::File(_)) => true,
            _ => false,
        };
        let r = (|| -> Result<(), Error> {
            let ino = match fs.resolve(&p) {
                Ok(i) => i,
                Err(Error::NotFound) | Err(Error::NotDir) => fs.create_path(&p, 0o644)?,
                Err(e) => return Err(e),
            };
            fs.write(ino, off as u64, &data)
        })();
        match r {
            Ok(()) => {
                assert!(ok_target, "write to {} succeeded unexpectedly", p);
                let e = m.entry(p).or_insert(Entry::File(Vec::new()));
                if let Entry::File(v) = e {
                    if !data.is_empty() && v.len() < off + data.len() { v.resize(off + data.len(), 0); }
                    v[off..off + data.len()].copy_from_slice(&data);
                }
            }
            Err(Error::Io) => return Err(Error::Io),
            Err(Error::Poisoned) => return Err(Error::Poisoned),
            Err(e) => assert!(!ok_target || data.is_empty(), "write {} failed: {:?}", p, e),
        }
    } else if op < 60 {
        let p = g.existing_or_new(m);
        let size = g.rng.below(30000) as usize;
        let r = fs.resolve(&p).and_then(|i| fs.truncate(i, size as u64));
        match (r, m.get_mut(&p)) {
            (Ok(()), Some(Entry::File(v))) => v.resize(size, 0),
            (Err(Error::Io), _) => return Err(Error::Io),
            (Err(Error::Poisoned), _) => return Err(Error::Poisoned),
            (r, Some(Entry::File(_))) => panic!("truncate failed {:?}", r),
            (r, _) => assert!(r.is_err()),
        }
    } else if op < 72 {
        let p = g.existing_or_new(m);
        let expect = matches!(m.get(&p), Some(Entry::File(_)) | Some(Entry::Link(_)));
        match fs.unlink_path(&p) {
            Ok(()) => { assert!(expect, "unlink {}", p); m.remove(&p); }
            Err(Error::Io) => return Err(Error::Io),
            Err(Error::Poisoned) => return Err(Error::Poisoned),
            Err(e) => assert!(!expect, "unlink {} failed {:?}", p, e),
        }
    } else if op < 80 {
        let p = g.existing_or_new(m);
        let expect = m.get(&p) == Some(&Entry::Dir) && !has_children(m, &p);
        match fs.rmdir_path(&p) {
            Ok(()) => { assert!(expect, "rmdir {}", p); m.remove(&p); }
            Err(Error::Io) => return Err(Error::Io),
            Err(Error::Poisoned) => return Err(Error::Poisoned),
            Err(e) => assert!(!expect, "rmdir {} failed {:?}", p, e),
        }
    } else if op < 92 {
        let a = g.existing_or_new(m);
        let b = g.existing_or_new(m);
        let expect = rename_ok(m, &a, &b);
        match fs.rename_path(&a, &b) {
            Ok(()) => {
                assert!(expect, "rename {} -> {} should fail", a, b);
                if a != b {
                    let pre = format!("{}/", a);
                    let moved: Vec<(String, Entry)> = m
                        .iter()
                        .filter(|(k, _)| **k == a || k.starts_with(&pre))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    for (k, _) in &moved { m.remove(k); }
                    m.remove(&b);
                    for (k, v) in moved { m.insert(format!("{}{}", b, &k[a.len()..]), v); }
                }
            }
            Err(Error::Io) => return Err(Error::Io),
            Err(Error::Poisoned) => return Err(Error::Poisoned),
            Err(e) => assert!(!expect, "rename {} -> {} failed {:?}", a, b, e),
        }
    } else {
        let p = g.path();
        let t = format!("target{}", g.rng.below(100));
        let expect = !m.contains_key(&p) && parent_is_dir(m, &p);
        let r = fs.split_parent(&p).and_then(|(d, n)| fs.symlink(d, &n, &t));
        match r {
            Ok(_) => { assert!(expect); m.insert(p, Entry::Link(t)); }
            Err(Error::Io) => return Err(Error::Io),
            Err(Error::Poisoned) => return Err(Error::Poisoned),
            Err(e) => assert!(!expect, "symlink {} failed {:?}", p, e),
        }
    }
    Ok(())
}

fn rename_ok(m: &Model, a: &str, b: &str) -> bool {
    let src = match m.get(a) { Some(s) => s, None => return false };
    if a == b { return true; }
    if !parent_is_dir(m, b) { return false; }
    if !parent_is_dir(m, a) { return false; }
    let is_dir = *src == Entry::Dir;
    if is_dir && b.starts_with(&format!("{}/", a)) { return false; }
    match m.get(b) {
        None => true,
        Some(d) => {
            let dd = *d == Entry::Dir;
            if dd != is_dir { return false; }
            !(dd && has_children(m, b))
        }
    }
}
