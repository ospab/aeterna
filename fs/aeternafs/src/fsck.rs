// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// Deep consistency check: trees, checksums, directory structure, extents,
// free-space accounting.

use crate::crc::crc32c;
use crate::dev::{BlockDevice, BLOCK_SIZE};
use crate::freemap::Bitmap;
use crate::fs::Fs;
use crate::layout::*;
use crate::ops::{Ext, Stat};
use crate::Result;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug, Default, Clone)]
pub struct FsckReport {
    pub errors: Vec<String>,
    pub trees: u64,
    pub inodes: u64,
    pub dirs: u64,
    pub files: u64,
    pub symlinks: u64,
    pub nodes: u64,
    pub data_blocks: u64,
    pub free_blocks: u64,
    pub snapshots: u64,
}

impl FsckReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
    fn err(&mut self, s: String) {
        if self.errors.len() < 200 { self.errors.push(s); }
    }
}

#[derive(Default)]
struct Collected {
    inodes: BTreeMap<u64, Stat>,
    dirents: Vec<(u64, u64, u8, Vec<u8>)>,
    exts: Vec<(u64, Ext)>,
    links: BTreeSet<u64>,
}

impl<D: BlockDevice> Fs<D> {
    /// Checks the filesystem. With `deep`, every data page is read and its
    /// checksum verified. Call on a committed state (after mount or commit).
    pub fn fsck(&mut self, deep: bool) -> Result<FsckReport> {
        let mut rep = FsckReport::default();
        let bc = self.block_count;
        let mut all = Bitmap::new(bc);
        all.set(0);
        all.set(1);
        for &c in &self.chain { all.set(c); }
        let mut roots: Vec<(String, u64)> = vec![(String::from("live"), self.root)];
        match self.snapshot_list() {
            Ok(l) => {
                rep.snapshots = l.len() as u64;
                for s in l { roots.push((format!("snapshot '{}'", s.name), s.root)); }
            }
            Err(e) => rep.err(format!("snapshot table: {}", e)),
        }
        for (label, root) in roots {
            rep.trees += 1;
            let mut local = Bitmap::new(bc);
            let mut dups = 0u64;
            let mut col = Collected::default();
            let mut prev: Option<Key> = None;
            let mut order_bad = 0u64;
            let mut item_err: Vec<String> = Vec::new();
            let g = self.cur_gen;
            let r = self.walk(root, g, &mut local, false, &mut dups, &mut |k, v| {
                if prev.map_or(false, |p| p >= *k) { order_bad += 1; }
                prev = Some(*k);
                match k.kind {
                    KIND_INODE => match Stat::decode_pub(k.obj, v) {
                        Ok(s) => { col.inodes.insert(k.obj, s); }
                        Err(_) => item_err.push(format!("bad inode item {}", k.obj)),
                    },
                    KIND_DIR => match crate::ops::parse_dir_pub(v) {
                        Ok(l) => { for (i, t, n) in l { col.dirents.push((k.obj, i, t, n)); } }
                        Err(_) => item_err.push(format!("bad dir item {}", k.obj)),
                    },
                    KIND_EXT => match Ext::parse(k, v, bc) {
                        Ok(e) => col.exts.push((k.obj, e)),
                        Err(_) => item_err.push(format!("bad extent item {}/{}", k.obj, k.off)),
                    },
                    KIND_LINK => { col.links.insert(k.obj); }
                    KIND_SNAP => {}
                    _ => item_err.push(format!("unknown item kind {}", k.kind)),
                }
                Ok(())
            });
            if let Err(e) = r {
                rep.err(format!("{}: tree walk failed: {}", label, e));
                continue;
            }
            for e in item_err { rep.err(format!("{}: {}", label, e)); }
            if order_bad > 0 { rep.err(format!("{}: {} keys out of order", label, order_bad)); }
            if dups > 0 { rep.err(format!("{}: {} blocks referenced twice in one tree", label, dups)); }
            let nodes = (0..bc).filter(|&b| local.get(b)).count() as u64;
            if label == "live" { rep.nodes = nodes; }
            self.check_logic(&label, &col, deep, &mut local, &mut rep)?;
            if label == "live" {
                rep.inodes = col.inodes.len() as u64;
                for s in col.inodes.values() {
                    if s.is_dir() { rep.dirs += 1 } else if s.is_symlink() { rep.symlinks += 1 } else { rep.files += 1 }
                }
                rep.data_blocks = (0..bc).filter(|&b| local.get(b)).count() as u64 - nodes;
            }
            all.or_with(&local);
        }
        // free-space accounting
        let free = self.free.to_bitmap(bc);
        let mut pend = Bitmap::new(bc);
        for &(s, l) in &self.pending { pend.set_range(s, l); }
        let (mut both, mut leaked) = (Vec::new(), Vec::new());
        for b in 2..bc {
            let u = all.get(b);
            let f = free.get(b) || pend.get(b);
            if u && f { both.push(b); }
            if !u && !f { leaked.push(b); }
        }
        if !both.is_empty() {
            rep.err(format!("{} blocks are both in use and free, first {}", both.len(), both[0]));
        }
        if !leaked.is_empty() {
            rep.err(format!("{} blocks leaked (neither used nor free), first {}", leaked.len(), leaked[0]));
        }
        rep.free_blocks = self.free.total;
        Ok(rep)
    }

    fn check_logic(&mut self, label: &str, col: &Collected, deep: bool, local: &mut Bitmap, rep: &mut FsckReport) -> Result<()> {
        match col.inodes.get(&1) {
            Some(s) if s.is_dir() => {}
            _ => rep.err(format!("{}: root directory missing", label)),
        }
        let mut refs: BTreeMap<u64, u32> = BTreeMap::new();
        let mut counts: BTreeMap<u64, u64> = BTreeMap::new();
        for (dir, ino, t, _) in &col.dirents {
            match col.inodes.get(dir) {
                Some(d) if d.is_dir() => {}
                _ => rep.err(format!("{}: directory entry in non-directory {}", label, dir)),
            }
            *counts.entry(*dir).or_insert(0) += 1;
            *refs.entry(*ino).or_insert(0) += 1;
            match col.inodes.get(ino) {
                None => rep.err(format!("{}: entry in dir {} points to missing inode {}", label, dir, ino)),
                Some(s) => {
                    if ((s.mode & crate::S_IFMT) >> 12) as u8 != *t { rep.err(format!("{}: type mismatch for inode {}", label, ino)); }
                    if s.is_dir() && s.parent != *dir { rep.err(format!("{}: dir {} has wrong parent", label, ino)); }
                }
            }
        }
        for (ino, s) in &col.inodes {
            if *ino != 1 && refs.get(ino).copied().unwrap_or(0) != 1 {
                rep.err(format!("{}: inode {} has {} directory entries", label, ino, refs.get(ino).copied().unwrap_or(0)));
            }
            if s.is_dir() && s.size != counts.get(ino).copied().unwrap_or(0) {
                rep.err(format!("{}: dir {} size {} != entries {}", label, ino, s.size, counts.get(ino).copied().unwrap_or(0)));
            }
            if s.is_symlink() != col.links.contains(ino) {
                rep.err(format!("{}: inode {} symlink target mismatch", label, ino));
            }
        }
        let mut last: Option<(u64, u64)> = None; // (ino, end page)
        for (ino, e) in &col.exts {
            match col.inodes.get(ino) {
                Some(s) if s.is_file() => {
                    let pages = (s.size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64;
                    if e.file_pg + e.n as u64 > pages { rep.err(format!("{}: inode {} extent beyond end of file", label, ino)); }
                }
                _ => rep.err(format!("{}: extent of non-file inode {}", label, ino)),
            }
            if let Some((li, le)) = last {
                if li == *ino && le > e.file_pg { rep.err(format!("{}: inode {} extents overlap", label, ino)); }
            }
            last = Some((*ino, e.file_pg + e.n as u64));
            let mut dup = 0;
            for b in e.start..e.start + e.n as u64 {
                if local.get(b) { dup += 1; }
                local.set(b);
            }
            if dup > 0 { rep.err(format!("{}: inode {} extent shares {} blocks with other data", label, ino, dup)); }
            if deep {
                let mut buf = vec![0u8; e.n as usize * BLOCK_SIZE];
                if self.dev_read(e.start, &mut buf).is_err() {
                    rep.err(format!("{}: inode {} data unreadable", label, ino));
                    continue;
                }
                for (i, pg) in buf.chunks(BLOCK_SIZE).enumerate() {
                    if crc32c(pg) != e.csum[i] {
                        rep.err(format!("{}: inode {} data checksum error in block {}", label, ino, e.start + i as u64));
                    }
                }
            }
        }
        Ok(())
    }
}
