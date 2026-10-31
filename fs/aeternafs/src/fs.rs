// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// Filesystem core: cache, allocation, mkfs, mount, atomic commit, snapshots.

use crate::dev::{BlockDevice, BLOCK_SIZE};
use crate::freemap::{Bitmap, FreeMap};
use crate::layout::*;
use crate::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

const CACHE_CAP: usize = 4096;
/// Blocks that data allocation never touches, so metadata can always be written.
pub(crate) const RESERVE: u64 = 64;

struct CEnt {
    node: Rc<Node>,
    dirty: bool,
    tick: u64,
}

#[derive(Clone, Debug)]
pub struct SnapInfo {
    pub id: u64,
    pub name: String,
    pub gen: u64,
    pub time: i64,
    pub root: u64,
}

#[derive(Clone, Debug)]
pub struct StatFs {
    pub block_size: u32,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub generation: u64,
    pub snapshots: u64,
    pub label: String,
}

pub struct Fs<D: BlockDevice> {
    pub(crate) dev: D,
    pub(crate) sb: Super,
    pub(crate) root: u64,
    pub(crate) cur_gen: u64,
    pub(crate) block_count: u64,
    pub(crate) free: FreeMap,
    pub(crate) pending: Vec<(u64, u64)>,
    pub(crate) chain: Vec<u64>,
    cache: BTreeMap<u64, CEnt>,
    tick: u64,
    pub(crate) last_snap_gen: u64,
    pub(crate) next_ino: u64,
    pub(crate) next_snap: u64,
    pub(crate) hash_seed: u64,
    pub(crate) txn_dirty: bool,
    poisoned: bool,
    pub(crate) now: i64,
    last_meta: u64,
}

pub struct SnapView<'a, D: BlockDevice> {
    pub(crate) fs: &'a mut Fs<D>,
    pub(crate) root: u64,
    pub info: SnapInfo,
}

impl<D: BlockDevice> Fs<D> {
    // ---- device access -------------------------------------------------

    pub(crate) fn dev_read(&mut self, start: u64, buf: &mut [u8]) -> Result<()> {
        if start + (buf.len() / BLOCK_SIZE) as u64 > self.block_count { return Err(Error::Corrupt("read range")); }
        self.dev.read_blocks(start, buf).map_err(|_| Error::Io)
    }
    pub(crate) fn dev_write(&mut self, start: u64, buf: &[u8]) -> Result<()> {
        let r = self.dev.write_blocks(start, buf).map_err(|_| Error::Io);
        if r.is_err() { self.poisoned = true; }
        r
    }

    pub fn into_device(self) -> D {
        self.dev
    }
    pub fn device(&mut self) -> &mut D {
        &mut self.dev
    }
    /// Current time for new timestamps: ns since the ospab epoch.
    pub fn set_time(&mut self, now_ns: i64) {
        self.now = now_ns;
    }
    /// Block number of the live tree root (for `*_in` read functions).
    pub fn live_root(&self) -> u64 {
        self.root
    }
    pub fn generation(&self) -> u64 {
        self.sb.generation
    }

    // ---- node cache -----------------------------------------------------

    pub(crate) fn load(&mut self, blk: u64, maxg: u64) -> Result<Rc<Node>> {
        if blk < 2 || blk >= self.block_count { return Err(Error::Corrupt("node pointer")); }
        self.tick += 1;
        let t = self.tick;
        if let Some(e) = self.cache.get_mut(&blk) {
            e.tick = t;
            if e.node.gen > maxg { return Err(Error::Corrupt("node generation")); }
            return Ok(e.node.clone());
        }
        let mut buf = vec![0u8; BLOCK_SIZE];
        self.dev_read(blk, &mut buf)?;
        let node = Node::decode(&buf, blk)?;
        if node.gen > maxg { return Err(Error::Corrupt("node generation")); }
        let rc = Rc::new(node);
        self.cache_put(blk, rc.clone(), false)?;
        Ok(rc)
    }

    fn cache_put(&mut self, blk: u64, node: Rc<Node>, dirty: bool) -> Result<()> {
        self.tick += 1;
        let tick = self.tick;
        self.cache.insert(blk, CEnt { node, dirty, tick });
        if self.cache.len() > CACHE_CAP {
            let mut v: Vec<(u64, u64)> = self.cache.iter().map(|(b, e)| (e.tick, *b)).collect();
            v.sort();
            for (_, b) in v.into_iter().take(CACHE_CAP / 4) {
                if let Some(e) = self.cache.remove(&b) {
                    if e.dirty {
                        let buf = e.node.encode(b);
                        self.dev_write(b, &buf)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn flush_dirty(&mut self) -> Result<()> {
        let dirty: Vec<u64> = self.cache.iter().filter(|(_, e)| e.dirty).map(|(b, _)| *b).collect();
        for b in dirty {
            let buf = self.cache[&b].node.encode(b);
            self.dev_write(b, &buf)?;
            if let Some(e) = self.cache.get_mut(&b) { e.dirty = false; }
        }
        Ok(())
    }

    fn cache_drop_range(&mut self, start: u64, len: u64) {
        if self.cache.is_empty() { return; }
        let keys: Vec<u64> = self.cache.range(start..start + len).map(|(b, _)| *b).collect();        for k in keys { self.cache.remove(&k); }
    }

    /// Writes a node. Nodes born in this transaction are updated in place,
    /// older ones get a new block and the old one is released.
    pub(crate) fn write_node(&mut self, old: Option<(u64, u64)>, mut node: Node) -> Result<u64> {
        let blk = match old {
            Some((b, g)) if g == self.cur_gen => b,
            other => {
                let nb = self.alloc_meta()?;
                if let Some((b, g)) = other { self.release(b, 1, g); }
                nb
            }
        };
        node.gen = self.cur_gen;
        self.txn_dirty = true;
        self.cache_put(blk, Rc::new(node), true)?;
        Ok(blk)
    }

    // ---- allocation -------------------------------------------------------

    pub(crate) fn alloc_meta(&mut self) -> Result<u64> {
        let (s, _) = self.free.alloc(1, self.last_meta).ok_or(Error::NoSpace)?;
        self.last_meta = s + 1;
        Ok(s)
    }

    pub(crate) fn alloc_data(&mut self, want: u64, hint: u64) -> Result<(u64, u64)> {
        if self.free.total <= RESERVE { return Err(Error::NoSpace); }
        let cap = want.min(self.free.total - RESERVE);
        self.free.alloc(cap, hint).ok_or(Error::NoSpace)
    }

    pub(crate) fn free_blocks(&self) -> u64 {
        self.free.total
    }

    /// Releases blocks of birth generation `gen`. Blocks that a snapshot may
    /// reference are kept (the sweep at snapshot delete reclaims them).
    pub(crate) fn release(&mut self, start: u64, len: u64, gen: u64) {
        if gen <= self.last_snap_gen { return; }
        if gen == self.cur_gen {
            self.cache_drop_range(start, len);
            if !self.free.insert(start, len) {
                // Cannot happen in a consistent filesystem; never reuse such a block twice.
                self.poisoned = true;
            }
        } else {
            self.pending.push((start, len));
        }
        self.txn_dirty = true;
    }

    // ---- mkfs / mount -----------------------------------------------------

    /// Formats the device. Returns the device.
    pub fn mkfs(dev: D, label: &str, now_ns: i64) -> Result<D> {
        let n = dev.block_count();
        if n < 128 { return Err(Error::TooSmall); }
        let mut sb = Super {
            generation: 0,
            block_count: n,
            root: 0,
            free_head: 0,
            free_pages: 0,
            last_snap_gen: 0,
            next_ino: 2,
            next_snap: 1,
            hash_seed: (now_ns as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_5A5A_1234_5678,
            created: now_ns,
            label: label.as_bytes()[..label.len().min(63)].to_vec(),
        };
        let mut free = FreeMap::new();
        free.insert(2, n - 2);
        let mut fs = Fs {
            dev, root: 0, cur_gen: 1, block_count: n, free, pending: Vec::new(), chain: Vec::new(),
            cache: BTreeMap::new(), tick: 0, last_snap_gen: 0, next_ino: 2, next_snap: 1,
            hash_seed: sb.hash_seed, txn_dirty: true, poisoned: false, now: now_ns, last_meta: 2,
            sb: sb.clone(),
        };
        let zero = vec![0u8; BLOCK_SIZE];
        fs.dev_write(0, &zero)?;
        fs.dev_write(1, &zero)?;
        fs.root = fs.write_node(None, Node::new_leaf())?;
        fs.make_root_inode()?;
        sb.generation = 0;
        fs.sb = sb;
        fs.commit()?;
        Ok(fs.dev)
    }

    pub fn mount(mut dev: D) -> Result<Fs<D>> {
        let mut best: Option<Super> = None;
        let mut first_err = None;
        let mut buf = vec![0u8; BLOCK_SIZE];
        for slot in 0..2u64 {
            if dev.read_blocks(slot, &mut buf).is_err() { return Err(Error::Io); }
            match Super::decode(&buf) {
                Ok(s) => {
                    if best.as_ref().map_or(true, |b| s.generation > b.generation) { best = Some(s); }
                }
                Err(e) => { if first_err.is_none() { first_err = Some(e); } }
            }
        }
        let sb = match best {
            Some(s) => s,
            None => return Err(first_err.unwrap_or(Error::NotFormatted)),
        };
        if sb.block_count > dev.block_count() { return Err(Error::TooSmall); }
        let n = sb.block_count;
        let mut fs = Fs {
            dev, root: sb.root, cur_gen: sb.generation + 1, block_count: n, free: FreeMap::new(),
            pending: Vec::new(), chain: Vec::new(), cache: BTreeMap::new(), tick: 0,
            last_snap_gen: sb.last_snap_gen, next_ino: sb.next_ino, next_snap: sb.next_snap,
            hash_seed: sb.hash_seed, txn_dirty: false, poisoned: false, now: 0, last_meta: 2,
            sb: sb.clone(),
        };
        // free-space chain
        let mut blk = sb.free_head;
        let mut pages = 0u32;
        let mut last_end = 2u64;
        while blk != 0 {
            pages += 1;
            if pages > sb.free_pages { return Err(Error::Corrupt("free chain length")); }
            if blk < 2 || blk >= n { return Err(Error::Corrupt("free chain pointer")); }
            fs.dev_read(blk, &mut buf)?;
            let p = FreePage::decode(&buf, blk)?;
            if p.gen > sb.generation { return Err(Error::Corrupt("free page generation")); }
            for (s, l) in p.entries {
                if l == 0 || s < last_end || s.checked_add(l).map_or(true, |e| e > n) {
                    return Err(Error::Corrupt("free extent"));
                }
                last_end = s + l;
                if !fs.free.insert(s, l) { return Err(Error::Corrupt("free overlap")); }
            }
            fs.chain.push(blk);
            blk = p.next;
        }
        if pages != sb.free_pages { return Err(Error::Corrupt("free chain length")); }
        // validate the root
        let g = fs.cur_gen;
        fs.load(sb.root, g)?;
        Ok(fs)
    }

    pub fn label(&self) -> String {
        String::from_utf8_lossy(&self.sb.label).into_owned()
    }

    pub fn statfs(&self) -> StatFs {
        StatFs {
            block_size: BLOCK_SIZE as u32,
            total_blocks: self.block_count,
            free_blocks: self.free.total,
            generation: self.sb.generation,
            snapshots: 0,
            label: self.label(),
        }
    }

    // ---- commit -----------------------------------------------------------

    fn persist_list(&self) -> Result<Vec<(u64, u64)>> {
        let mut v: Vec<(u64, u64)> = self
            .free
            .map
            .iter()
            .map(|(&s, &l)| (s, l))
            .chain(self.pending.iter().cloned())
            .collect();
        v.sort();
        let mut out: Vec<(u64, u64)> = Vec::new();
        for (s, l) in v {
            if let Some(last) = out.last_mut() {
                if last.0 + last.1 > s { return Err(Error::Corrupt("double free")); }
                if last.0 + last.1 == s { last.1 += l; continue; }
            }
            out.push((s, l));
        }
        Ok(out)
    }

    /// Atomically makes all changes since the last commit durable.
    pub fn commit(&mut self) -> Result<()> {
        if self.poisoned { return Err(Error::Poisoned); }
        if !self.txn_dirty && self.pending.is_empty() { return Ok(()); }
        let r = self.commit_inner();
        if r.is_err() { self.poisoned = true; }
        r
    }

    fn commit_inner(&mut self) -> Result<()> {
        // The old chain pages become free once this commit is durable.
        let old_chain = core::mem::take(&mut self.chain);
        for p in old_chain { self.pending.push((p, 1)); }
        // Allocate pages for the new free list. The list changes while pages are
        // taken from it, so repeat until the page count is stable.
        let mut pages: Vec<u64> = Vec::new();
        let list = loop {
            let list = self.persist_list()?;
            let need = (list.len() + FREE_PER_PAGE - 1) / FREE_PER_PAGE;
            if pages.len() >= need { break list; }
            let p = self.alloc_meta()?;
            pages.push(p);
        };
        let gen = self.cur_gen;
        for (i, &p) in pages.iter().enumerate() {
            let lo = i * FREE_PER_PAGE;
            let hi = ((i + 1) * FREE_PER_PAGE).min(list.len());
            let page = FreePage {
                gen,
                next: if i + 1 < pages.len() { pages[i + 1] } else { 0 },
                entries: if lo < hi { list[lo..hi].to_vec() } else { Vec::new() },
            };
            let buf = page.encode(p);
            self.dev_write(p, &buf)?;
        }
        self.flush_dirty()?;
        self.dev.flush().map_err(|_| Error::Io)?;
        let sb = Super {
            generation: gen,
            block_count: self.block_count,
            root: self.root,
            free_head: pages.first().copied().unwrap_or(0),
            free_pages: pages.len() as u32,
            last_snap_gen: self.last_snap_gen,
            next_ino: self.next_ino,
            next_snap: self.next_snap,
            hash_seed: self.hash_seed,
            created: self.sb.created,
            label: self.sb.label.clone(),
        };
        let buf = sb.encode();
        self.dev_write(gen & 1, &buf)?;
        self.dev.flush().map_err(|_| Error::Io)?;
        // Durable. Blocks freed by this transaction can be reused now.
        let pend = core::mem::take(&mut self.pending);
        for (s, l) in pend {
            self.cache_drop_range(s, l);
            if !self.free.insert(s, l) { return Err(Error::Corrupt("double free")); }
        }
        self.chain = pages;
        self.sb = sb;
        self.cur_gen = gen + 1;
        self.txn_dirty = false;
        Ok(())
    }

    // ---- snapshots --------------------------------------------------------

    fn valid_snap_name(name: &str) -> Result<()> {
        if name.is_empty() || name.len() > crate::MAX_NAME || name.contains('\0') { return Err(Error::InvalidName); }
        Ok(())
    }

    fn snap_encode(i: &SnapInfo) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&i.root.to_le_bytes());
        v.extend_from_slice(&i.gen.to_le_bytes());
        v.extend_from_slice(&i.time.to_le_bytes());
        v.push(i.name.len() as u8);
        v.extend_from_slice(i.name.as_bytes());
        v
    }

    pub fn snapshot_list(&mut self) -> Result<Vec<SnapInfo>> {
        let root = self.root;
        self.snapshot_list_in(root)
    }

    pub(crate) fn snapshot_list_in(&mut self, root: u64) -> Result<Vec<SnapInfo>> {
        let items = self.tcollect(root, Key::new(0, KIND_SNAP, 0), Key::new(0, KIND_SNAP, u64::MAX), usize::MAX)?;
        let mut out = Vec::new();
        for (k, v) in items {
            if v.len() < 25 || v.len() != 25 + v[24] as usize { return Err(Error::Corrupt("snapshot item")); }
            let name = core::str::from_utf8(&v[25..]).map_err(|_| Error::Corrupt("snapshot name"))?;
            out.push(SnapInfo {
                id: k.off,
                name: String::from(name),
                root: u64::from_le_bytes(v[0..8].try_into().unwrap()),
                gen: u64::from_le_bytes(v[8..16].try_into().unwrap()),
                time: i64::from_le_bytes(v[16..24].try_into().unwrap()),
            });
        }
        Ok(out)
    }

    fn snap_find(&mut self, name: &str) -> Result<SnapInfo> {
        self.snapshot_list()?.into_iter().find(|s| s.name == name).ok_or(Error::NoSuchSnapshot)
    }

    pub fn snapshot_create(&mut self, name: &str) -> Result<()> {
        Self::valid_snap_name(name)?;
        if self.snapshot_list()?.iter().any(|s| s.name == name) { return Err(Error::Exists); }
        self.commit()?;
        let info = SnapInfo { id: self.next_snap, name: String::from(name), gen: self.sb.generation, time: self.now, root: self.root };
        self.next_snap += 1;
        self.last_snap_gen = self.last_snap_gen.max(info.gen);
        self.tput(Key::new(0, KIND_SNAP, info.id), &Self::snap_encode(&info))?;
        self.txn_dirty = true;
        self.commit()
    }

    pub fn snapshot_delete(&mut self, name: &str) -> Result<()> {
        let info = self.snap_find(name)?;
        self.tdel(Key::new(0, KIND_SNAP, info.id))?;
        self.recompute_last_snap()?;
        self.sweep()?;
        self.txn_dirty = true;
        self.commit()
    }

    pub fn snapshot_rollback(&mut self, name: &str) -> Result<()> {
        let info = self.snap_find(name)?;
        let all = self.snapshot_list()?;
        self.root = info.root;
        // The old tree may list snapshots that were deleted later: drop them.
        for s in self.snapshot_list()? {
            if !all.iter().any(|a| a.id == s.id) {
                self.tdel(Key::new(0, KIND_SNAP, s.id))?;
            }
        }
        for s in &all {
            self.tput(Key::new(0, KIND_SNAP, s.id), &Self::snap_encode(s))?;
        }
        self.recompute_last_snap()?;
        self.sweep()?;
        self.txn_dirty = true;
        self.commit()
    }

    fn recompute_last_snap(&mut self) -> Result<()> {
        self.last_snap_gen = self.snapshot_list()?.iter().map(|s| s.gen).max().unwrap_or(0);
        Ok(())
    }

    /// Read-only view of a snapshot.
    pub fn snapshot_view(&mut self, name: &str) -> Result<SnapView<'_, D>> {
        let info = self.snap_find(name)?;
        Ok(SnapView { root: info.root, info, fs: self })
    }

    /// Marks every block reachable from the live tree and all snapshots; blocks
    /// that are neither reachable nor free go to the pending list.
    pub(crate) fn sweep(&mut self) -> Result<()> {
        let mut used = Bitmap::new(self.block_count);
        used.set(0);
        used.set(1);
        for &c in &self.chain { used.set(c); }
        let mut roots = vec![self.root];
        for s in self.snapshot_list()? { roots.push(s.root); }
        let bc = self.block_count;
        for r in roots {
            let mut dups = 0u64;
            let mut ext: Vec<(u64, u64)> = Vec::new();
            let g = self.cur_gen;
            self.walk(r, g, &mut used, true, &mut dups, &mut |k, v| {
                if k.kind == KIND_EXT {
                    let e = crate::ops::Ext::parse(k, v, bc)?;
                    ext.push((e.start, e.n as u64));
                }
                Ok(())
            })?;
            for (s, l) in ext { used.set_range(s, l); }
        }
        let mut hold = self.free.to_bitmap(self.block_count);
        for &(s, l) in &self.pending { hold.set_range(s, l); }
        let mut run: Option<(u64, u64)> = None;
        for b in 2..self.block_count {
            if !used.get(b) && !hold.get(b) {
                match &mut run {
                    Some((s, l)) if *s + *l == b => *l += 1,
                    _ => {
                        if let Some(r) = run.take() { self.pending.push(r); }
                        run = Some((b, 1));
                    }
                }
            }
        }
        if let Some(r) = run { self.pending.push(r); }
        self.txn_dirty = true;
        Ok(())
    }
}

impl<'a, D: BlockDevice> SnapView<'a, D> {
    pub fn resolve(&mut self, path: &str) -> Result<u64> {
        self.fs.resolve_in(self.root, path)
    }
    pub fn stat(&mut self, ino: u64) -> Result<crate::ops::Stat> {
        self.fs.stat_in(self.root, ino)
    }
    pub fn read(&mut self, ino: u64, off: u64, buf: &mut [u8]) -> Result<usize> {
        self.fs.read_in(self.root, ino, off, buf)
    }
    pub fn readdir(&mut self, ino: u64) -> Result<Vec<crate::ops::DirEntry>> {
        self.fs.readdir_in(self.root, ino)
    }
    pub fn readlink(&mut self, ino: u64) -> Result<String> {
        self.fs.readlink_in(self.root, ino)
    }
}
