/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Kernel side of AeternaFS v2 (crate `fs/aeternafs`, docs/en/aeternafs.md).

  * `KDisk`   the crate's BlockDevice over the storage drivers: 4096-byte blocks on top of
              512-byte sectors, flush = the driver's cache flush command.
  * `AeFs`    the kernel `FileSystem` (path API of the VFS) on top of the crate. One writer:
              every operation holds the volume mutex. Changes are in memory and in free
              blocks until `commit`, which is atomic.
  * commit policy: `tick` commits 3 s after the last change, at the latest 15 s after the
              first uncommitted change. `sync_all` (the `sync` command, reboot, power-off)
              commits at once. A kernel thread (vfs/persist.rs) calls `tick` every second,
              so it also runs while a full-screen program owns the console.
*/

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ::aeternafs::{BlockDevice, Error, Fs, FsckReport, IoError, BLOCK_SIZE};

use super::{DirEntry, FileSystem, NodeType};
use crate::core::sync::Mutex;

type AResult<T> = core::result::Result<T, Error>;
type Vol = Fs<KDisk>;

/// Commit this long after the last change (timer ticks, 100 Hz).
const QUIET_TICKS: u64 = 300;
/// Commit at the latest this long after the first uncommitted change.
const MAX_TICKS: u64 = 1500;

fn log(s: &str) {
    crate::arch::x86_64::serial::write_str(s);
}

// ─── Block device ───────────────────────────────────────────────────────────

/// A range of a disk as an array of 4096-byte blocks.
pub struct KDisk {
    disk: usize,
    start: u64,
    blocks: u64,
}

impl KDisk {
    /// `start` and `sectors` in 512-byte sectors of disk `disk` (see `drivers`).
    pub fn new(disk: usize, start: u64, sectors: u64) -> KDisk {
        KDisk { disk, start, blocks: sectors / 8 }
    }
}

impl BlockDevice for KDisk {
    fn block_count(&self) -> u64 {
        self.blocks
    }

    fn read_blocks(&mut self, start: u64, buf: &mut [u8]) -> Result<(), IoError> {
        if buf.len() % BLOCK_SIZE != 0 { return Err(IoError); }
        let n = (buf.len() / BLOCK_SIZE) as u64;
        if start.checked_add(n).map_or(true, |e| e > self.blocks) { return Err(IoError); }
        let lba = self.start + start * 8;
        let cnt = (n * 8) as u32;
        if crate::drivers::read(self.disk, lba, cnt, buf) { return Ok(()); }
        // one retry: the drivers reset the port after an error
        if crate::drivers::read(self.disk, lba, cnt, buf) { Ok(()) } else { Err(IoError) }
    }

    fn write_blocks(&mut self, start: u64, buf: &[u8]) -> Result<(), IoError> {
        if buf.len() % BLOCK_SIZE != 0 { return Err(IoError); }
        let n = (buf.len() / BLOCK_SIZE) as u64;
        if start.checked_add(n).map_or(true, |e| e > self.blocks) { return Err(IoError); }
        let lba = self.start + start * 8;
        let cnt = (n * 8) as u32;
        if crate::drivers::write(self.disk, lba, cnt, buf) { Ok(()) } else { Err(IoError) }
    }

    fn flush(&mut self) -> Result<(), IoError> {
        if crate::drivers::flush(self.disk) { Ok(()) } else { Err(IoError) }
    }
}

// ─── Volume ─────────────────────────────────────────────────────────────────

/// Numbers for `df`.
#[derive(Clone)]
pub struct VolInfo {
    pub name: String,
    pub label: String,
    pub disk: usize,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub generation: u64,
    pub snapshots: u64,
    pub commits: u64,
    pub dirty: bool,
    pub is_root: bool,
}

/// The crate's `Fs` keeps `Rc` nodes in its cache. They never leave the volume: every use of
/// the `Fs` goes through the mutex that owns it, so moving the whole thing is sound.
struct Holder(Option<Vol>);
unsafe impl Send for Holder {}

pub struct AeFs {
    vol: Mutex<Holder>,
    name: String,
    disk: usize,
    is_root: bool,
    dirty: AtomicBool,
    first_dirty: AtomicU64,
    last_change: AtomicU64,
    commits: AtomicU64,
    errors: AtomicU64,
}

static VOLS: crate::core::sync::IrqSpinLock<Vec<&'static AeFs>> =
    crate::core::sync::IrqSpinLock::new("VFS.aeternafs", crate::core::sync::rank::VFS, Vec::new());

fn volumes() -> Vec<&'static AeFs> {
    VOLS.lock().clone()
}

/// The volume that holds the persistent layer of `/`.
pub fn root_volume() -> Option<&'static AeFs> {
    volumes().into_iter().find(|v| v.is_root)
}

pub fn root_volume_info() -> Option<VolInfo> {
    root_volume().and_then(|v| v.info())
}

/// All mounted AeternaFS volumes.
pub fn volumes_info() -> Vec<VolInfo> {
    volumes().iter().filter_map(|v| v.info()).collect()
}

fn ticks() -> u64 {
    crate::arch::x86_64::idt::timer_ticks()
}

fn norm(path: &str) -> String {
    let mut p = String::new();
    for c in path.split('/') {
        if c.is_empty() || c == "." { continue; }
        p.push('/');
        p.push_str(c);
    }
    if p.is_empty() { p.push('/'); }
    p
}

fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
}

fn last_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

impl AeFs {
    fn from_fs(fs: Vol, name: String, disk: usize, is_root: bool) -> &'static AeFs {
        let v = alloc::boxed::Box::leak(alloc::boxed::Box::new(AeFs {
            vol: Mutex::new(Holder(Some(fs))),
            name,
            disk,
            is_root,
            dirty: AtomicBool::new(false),
            first_dirty: AtomicU64::new(0),
            last_change: AtomicU64::new(0),
            commits: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }));
        VOLS.lock().push(v);
        v
    }

    /// Wrap a mounted volume as a `FileSystem` and register it for the commit timer.
    pub fn register(fs: Vol, name: &str, disk: usize, is_root: bool) -> &'static AeFs {
        Self::from_fs(fs, String::from(name), disk, is_root)
    }

    fn note_change(&self) {
        let t = ticks();
        self.last_change.store(t, Ordering::Relaxed);
        if !self.dirty.swap(true, Ordering::AcqRel) {
            self.first_dirty.store(t, Ordering::Relaxed);
        }
    }

    /// Run `f` on the volume under the writer lock. `write` marks the volume changed.
    fn run<R>(&self, write: bool, f: impl FnOnce(&mut Vol) -> AResult<R>) -> AResult<R> {
        let mut g = self.vol.lock();
        let v = g.0.as_mut().ok_or(Error::Io)?;
        v.set_time(crate::time::now());
        let r = f(v);
        match &r {
            Ok(_) => { if write { self.note_change(); } }
            Err(e) => {
                // An error half-way through an operation may have changed the volume.
                if write { self.note_change(); }
                if matches!(e, Error::Io | Error::Checksum(_) | Error::Corrupt(_) | Error::Poisoned) {
                    let n = self.errors.fetch_add(1, Ordering::Relaxed);
                    if n < 5 { log(&format!("[AeternaFS] {}: {}\r\n", self.name, e)); }
                }
            }
        }
        r
    }

    /// Commit now. `block` = wait for the writer lock. True when nothing is left uncommitted.
    pub fn commit(&self, block: bool) -> bool {
        let mut g = if block {
            self.vol.lock()
        } else {
            match self.vol.try_lock() { Some(g) => g, None => return false }
        };
        let v = match g.0.as_mut() { Some(v) => v, None => return false };
        if !self.dirty.load(Ordering::Acquire) { return true; }
        if super::disk_sync::is_read_only() { return false; }
        v.set_time(crate::time::now());
        match v.commit() {
            Ok(()) => {
                self.dirty.store(false, Ordering::Release);
                self.commits.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(e) => {
                let n = self.errors.fetch_add(1, Ordering::Relaxed);
                if n < 5 { log(&format!("[AeternaFS] {}: commit failed: {}\r\n", self.name, e)); }
                // back off: the next try is a full quiet period away
                self.last_change.store(ticks(), Ordering::Relaxed);
                false
            }
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    /// Commit when the quiet period or the maximum delay is over.
    fn tick_one(&self, block: bool) {
        if !self.is_dirty() { return; }
        let now = ticks();
        let quiet = now.wrapping_sub(self.last_change.load(Ordering::Relaxed)) >= QUIET_TICKS;
        let late = now.wrapping_sub(self.first_dirty.load(Ordering::Relaxed)) >= MAX_TICKS;
        if quiet || late { self.commit(block); }
    }

    pub fn info(&self) -> Option<VolInfo> {
        let mut g = self.vol.lock();
        let v = g.0.as_mut()?;
        let st = v.statfs();
        let snaps = v.snapshot_list().map(|l| l.len() as u64).unwrap_or(0);
        Some(VolInfo {
            name: self.name.clone(),
            label: st.label,
            disk: self.disk,
            total_blocks: st.total_blocks,
            free_blocks: st.free_blocks,
            generation: st.generation,
            snapshots: snaps,
            commits: self.commits.load(Ordering::Relaxed),
            dirty: self.is_dirty(),
            is_root: self.is_root,
        })
    }

    /// Commit, then check the volume. `deep` reads every data page.
    pub fn fsck(&self, deep: bool) -> AResult<FsckReport> {
        if self.is_dirty() { self.commit(true); }
        let mut g = self.vol.lock();
        let v = g.0.as_mut().ok_or(Error::Io)?;
        v.fsck(deep)
    }

    pub fn snapshot_create(&self, name: &str) -> AResult<()> {
        let r = self.run(true, |v| v.snapshot_create(name));
        if r.is_ok() { self.dirty.store(false, Ordering::Release); }
        r
    }

    pub fn snapshot_delete(&self, name: &str) -> AResult<()> {
        let r = self.run(true, |v| v.snapshot_delete(name));
        if r.is_ok() { self.dirty.store(false, Ordering::Release); }
        r
    }

    pub fn snapshot_list(&self) -> AResult<Vec<::aeternafs::SnapInfo>> {
        self.run(false, |v| v.snapshot_list())
    }

    /// Give the device back (unmount). Commits first.
    pub fn disk_index(&self) -> usize {
        self.disk
    }

    fn mkdir_p(v: &mut Vol, path: &str) -> AResult<u64> {
        if let Ok(i) = v.resolve(path) {
            return if v.stat(i)?.is_dir() { Ok(i) } else { Err(Error::NotDir) };
        }
        let mut cur = v.resolve("/")?;
        for c in path.split('/') {
            if c.is_empty() { continue; }
            cur = match v.lookup(cur, c) {
                Ok(i) => {
                    if !v.stat(i)?.is_dir() { return Err(Error::NotDir); }
                    i
                }
                Err(Error::NotFound) => v.mkdir(cur, c, 0o755)?,
                Err(e) => return Err(e),
            };
        }
        Ok(cur)
    }

    /// Inode of a file, created (with its parents) when missing.
    fn file_ino(v: &mut Vol, path: &str) -> AResult<u64> {
        match v.resolve(path) {
            Ok(i) => Ok(i),
            Err(Error::NotFound) => {
                let d = Self::mkdir_p(v, parent_of(path))?;
                v.create(d, last_name(path), 0o644)
            }
            Err(e) => Err(e),
        }
    }
}

impl FileSystem for AeFs {
    fn name(&self) -> &str {
        &self.name
    }

    fn read_at(&self, path: &str, offset: usize, buf: &mut [u8]) -> Option<usize> {
        let p = norm(path);
        self.run(false, |v| {
            let i = v.resolve(&p)?;
            if v.stat(i)?.is_dir() { return Err(Error::IsDir); }
            v.read(i, offset as u64, buf)
        }).ok()
    }

    fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        let p = norm(path);
        self.run(false, |v| {
            let i = v.resolve(&p)?;
            let st = v.stat(i)?;
            if st.is_dir() { return Err(Error::IsDir); }
            let mut data = alloc::vec![0u8; st.size as usize];
            let n = v.read(i, 0, &mut data)?;
            data.truncate(n);
            Ok(data)
        }).ok()
    }

    fn write_at(&self, path: &str, offset: usize, data: &[u8]) -> bool {
        let p = norm(path);
        self.run(true, |v| {
            let i = Self::file_ino(v, &p)?;
            v.write(i, offset as u64, data)
        }).is_ok()
    }

    fn write_file(&self, path: &str, data: &[u8]) -> bool {
        let p = norm(path);
        if p == "/" { return false; }
        self.run(true, |v| {
            let d = Self::mkdir_p(v, parent_of(&p))?;
            let n = last_name(&p);
            let i = match v.lookup(d, n) {
                Ok(i) => {
                    v.truncate(i, 0)?;
                    i
                }
                Err(Error::NotFound) => v.create(d, n, 0o644)?,
                Err(e) => return Err(e),
            };
            v.write(i, 0, data)
        }).is_ok()
    }

    fn append_file(&self, path: &str, data: &[u8]) -> bool {
        let p = norm(path);
        self.run(true, |v| {
            let i = Self::file_ino(v, &p)?;
            let size = v.stat(i)?.size;
            v.write(i, size, data)
        }).is_ok()
    }

    fn readdir(&self, path: &str) -> Option<Vec<DirEntry>> {
        let p = norm(path);
        self.run(false, |v| {
            let d = v.resolve(&p)?;
            if !v.stat(d)?.is_dir() { return Err(Error::NotDir); }
            let mut out = Vec::new();
            for e in v.readdir(d)? {
                let st = v.stat(e.ino)?;
                out.push(DirEntry {
                    name: e.name,
                    node_type: if st.is_dir() { NodeType::Directory } else { NodeType::File },
                    size: if st.is_dir() { 0 } else { st.size as usize },
                });
            }
            out.sort_by(|a, b| match (a.node_type, b.node_type) {
                (NodeType::Directory, NodeType::File) => core::cmp::Ordering::Less,
                (NodeType::File, NodeType::Directory) => core::cmp::Ordering::Greater,
                _ => a.name.cmp(&b.name),
            });
            Ok(out)
        }).ok()
    }

    fn mkdir(&self, path: &str) -> bool {
        let p = norm(path);
        self.run(true, |v| Self::mkdir_p(v, &p).map(|_| ())).is_ok()
    }

    fn touch(&self, path: &str) -> bool {
        let p = norm(path);
        if p == "/" { return true; }
        self.run(true, |v| Self::file_ino(v, &p).map(|_| ())).is_ok()
    }

    fn exists(&self, path: &str) -> bool {
        let p = norm(path);
        self.run(false, |v| v.resolve(&p).map(|_| ())).is_ok()
    }

    fn stat(&self, path: &str) -> Option<DirEntry> {
        let p = norm(path);
        self.run(false, |v| {
            let i = v.resolve(&p)?;
            let st = v.stat(i)?;
            Ok(DirEntry {
                name: String::from(last_name(&p)),
                node_type: if st.is_dir() { NodeType::Directory } else { NodeType::File },
                size: if st.is_dir() { 0 } else { st.size as usize },
            })
        }).ok()
    }

    fn remove(&self, path: &str) -> bool {
        let p = norm(path);
        if p == "/" { return false; }
        self.run(true, |v| {
            let i = v.resolve(&p)?;
            if v.stat(i)?.is_dir() { v.rmdir_path(&p) } else { v.unlink_path(&p) }
        }).is_ok()
    }

    fn rename(&self, from: &str, to: &str) -> bool {
        let f = norm(from);
        let t = norm(to);
        if f == "/" || t == "/" { return false; }
        if f == t { return true; }
        self.run(true, |v| {
            v.resolve(&f)?;
            Self::mkdir_p(v, parent_of(&t))?;
            v.rename_path(&f, &t)
        }).is_ok()
    }
}

// ─── Volume management ──────────────────────────────────────────────────────

/// Format `sectors` sectors of disk `disk` from `start` with an empty AeternaFS v2.
pub fn mkfs(disk: usize, start: u64, sectors: u64, label: &str) -> AResult<()> {
    let dev = KDisk::new(disk, start, sectors);
    Fs::mkfs(dev, label, crate::time::now()).map(|_| ())
}

/// Mount the volume without registering it (for copying out and for checks).
pub fn mount_raw(disk: usize, start: u64, sectors: u64) -> AResult<Vol> {
    Fs::mount(KDisk::new(disk, start, sectors))
}

/// True when block 0 or 1 of the range carries the AeternaFS v2 magic (valid or damaged).
pub fn has_v2_magic(disk: usize, start: u64) -> bool {
    let mut buf = alloc::vec![0u8; BLOCK_SIZE];
    for blk in 0..2u64 {
        if !crate::drivers::read(disk, start + blk * 8, 8, &mut buf) { continue; }
        if &buf[4..12] == b"AETERNA2" { return true; }
    }
    false
}

/// Copy the tree under `dir` of `src` into `dst`. Returns (files, directories, all ok).
pub fn copy_tree(src: &dyn FileSystem, dst: &dyn FileSystem, dir: &str) -> (usize, usize, bool) {
    let mut files = 0usize;
    let mut dirs = 0usize;
    let mut ok = true;
    let entries = match src.readdir(dir) { Some(e) => e, None => return (0, 0, false) };
    for e in entries {
        let p = if dir == "/" { format!("/{}", e.name) } else { format!("{}/{}", dir, e.name) };
        match e.node_type {
            NodeType::Directory => {
                if dst.mkdir(&p) { dirs += 1; } else { ok = false; }
                let (f, d, k) = copy_tree(src, dst, &p);
                files += f;
                dirs += d;
                ok &= k;
            }
            NodeType::File => {
                match src.read_file(&p) {
                    Some(data) => {
                        if dst.write_file(&p, &data) { files += 1; } else { ok = false; }
                    }
                    None => ok = false,
                }
            }
            NodeType::CharDevice => {}
        }
    }
    (files, dirs, ok)
}

// ─── Policy entry points ────────────────────────────────────────────────────

pub fn any_dirty() -> bool {
    volumes().iter().any(|v| v.is_dirty())
}

/// Commit every volume now, waiting for writers. True when all are committed.
pub fn sync_all() -> bool {
    let mut ok = true;
    for v in volumes() {
        if !v.commit(true) { ok = false; }
    }
    ok
}

/// Timer policy. Never waits for a writer.
pub fn tick() {
    for v in volumes() {
        v.tick_one(false);
    }
}

/// Before reboot or power-off, also from the power-button interrupt: commit what can be
/// committed without waiting for a lock that the interrupted code may hold.
pub fn flush_for_power() {
    if super::disk_sync::is_read_only() { return; }
    for v in volumes() {
        if v.is_dirty() && !v.commit(false) {
            log("[AeternaFS] power: volume busy or commit failed, last changes may be lost\r\n");
        }
    }
}
