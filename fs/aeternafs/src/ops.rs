// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// File, directory and symlink operations.

use crate::crc::crc32c;
use crate::dev::{BlockDevice, BLOCK_SIZE};
use crate::fs::{Fs, RESERVE};
use crate::layout::*;
use crate::{Error, Result, MAX_NAME};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

pub const ROOT_INO: u64 = 1;
/// Longest extent in pages: keeps an extent item (with checksums) under MAX_VAL.
pub const MAX_EXT: u64 = 240;
const MAX_PG: u64 = u64::MAX >> 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stat {
    pub ino: u64,
    pub mode: u32,
    pub flags: u32,
    pub size: u64,
    pub parent: u64,
    /// Times: ns since 2012-08-09 UTC.
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub crtime: i64,
}

impl Stat {
    pub fn is_dir(&self) -> bool { self.mode & S_IFMT == S_IFDIR }
    pub fn is_file(&self) -> bool { self.mode & S_IFMT == S_IFREG }
    pub fn is_symlink(&self) -> bool { self.mode & S_IFMT == S_IFLNK }
    pub fn nlink(&self) -> u32 { 1 }
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(56);
        v.extend_from_slice(&self.mode.to_le_bytes());
        v.extend_from_slice(&self.flags.to_le_bytes());
        v.extend_from_slice(&self.size.to_le_bytes());
        v.extend_from_slice(&self.parent.to_le_bytes());
        v.extend_from_slice(&self.atime.to_le_bytes());
        v.extend_from_slice(&self.mtime.to_le_bytes());
        v.extend_from_slice(&self.ctime.to_le_bytes());
        v.extend_from_slice(&self.crtime.to_le_bytes());
        v
    }
    pub(crate) fn decode_pub(ino: u64, v: &[u8]) -> Result<Stat> {
        Stat::decode(ino, v)
    }
    fn decode(ino: u64, v: &[u8]) -> Result<Stat> {
        if v.len() != 56 { return Err(Error::Corrupt("inode size")); }
        let r64 = |o: usize| u64::from_le_bytes(v[o..o + 8].try_into().unwrap());
        Ok(Stat {
            ino,
            mode: u32::from_le_bytes(v[0..4].try_into().unwrap()),
            flags: u32::from_le_bytes(v[4..8].try_into().unwrap()),
            size: r64(8),
            parent: r64(16),
            atime: r64(24) as i64,
            mtime: r64(32) as i64,
            ctime: r64(40) as i64,
            crtime: r64(48) as i64,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub ino: u64,
    /// File type bits of the mode (S_IFDIR, S_IFREG, S_IFLNK).
    pub mode_type: u32,
}

pub(crate) struct Ext {
    pub file_pg: u64,
    pub start: u64,
    pub n: u32,
    pub gen: u64,
    pub csum: Vec<u32>,
}

impl Ext {
    pub fn parse(k: &Key, v: &[u8], block_count: u64) -> Result<Ext> {
        if v.len() < 20 { return Err(Error::Corrupt("extent size")); }
        let start = u64::from_le_bytes(v[0..8].try_into().unwrap());
        let n = u32::from_le_bytes(v[8..12].try_into().unwrap());
        let gen = u64::from_le_bytes(v[12..20].try_into().unwrap());
        if n == 0 || n as u64 > MAX_EXT || v.len() != 20 + 4 * n as usize { return Err(Error::Corrupt("extent shape")); }
        if start < 2 || start.checked_add(n as u64).map_or(true, |e| e > block_count) { return Err(Error::Corrupt("extent range")); }
        let csum = v[20..].chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
        Ok(Ext { file_pg: k.off, start, n, gen, csum })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(20 + 4 * self.csum.len());
        v.extend_from_slice(&self.start.to_le_bytes());
        v.extend_from_slice(&self.n.to_le_bytes());
        v.extend_from_slice(&self.gen.to_le_bytes());
        for c in &self.csum { v.extend_from_slice(&c.to_le_bytes()); }
        v
    }
}

pub(crate) fn valid_name(name: &str) -> Result<()> {
    if name.len() > MAX_NAME { return Err(Error::NameTooLong); }
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(Error::InvalidName);
    }
    Ok(())
}

pub(crate) type DirList = Vec<(u64, u8, Vec<u8>)>;

fn parse_dir(v: &[u8]) -> Result<DirList> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < v.len() {
        if p + 10 > v.len() { return Err(Error::Corrupt("dir entry")); }
        let ino = u64::from_le_bytes(v[p..p + 8].try_into().unwrap());
        let t = v[p + 8];
        let l = v[p + 9] as usize;
        p += 10;
        if p + l > v.len() { return Err(Error::Corrupt("dir entry name")); }
        out.push((ino, t, v[p..p + l].to_vec()));
        p += l;
    }
    Ok(out)
}

pub(crate) fn parse_dir_pub(v: &[u8]) -> Result<DirList> {
    parse_dir(v)
}

fn encode_dir(l: &DirList) -> Vec<u8> {
    let mut v = Vec::new();
    for (ino, t, n) in l {
        v.extend_from_slice(&ino.to_le_bytes());
        v.push(*t);
        v.push(n.len() as u8);
        v.extend_from_slice(n);
    }
    v
}

fn type_code(mode: u32) -> u8 {
    ((mode & S_IFMT) >> 12) as u8
}

impl<D: BlockDevice> Fs<D> {
    pub(crate) fn name_hash(&self, name: &[u8]) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64 ^ self.hash_seed;
        for &b in name {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        h ^= h >> 32;
        h = h.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        h ^ (h >> 29)
    }

    pub(crate) fn make_root_inode(&mut self) -> Result<()> {
        let now = self.now;
        let st = Stat { ino: ROOT_INO, mode: S_IFDIR | 0o755, flags: 0, size: 0, parent: ROOT_INO, atime: now, mtime: now, ctime: now, crtime: now };
        self.put_inode(&st)
    }

    // ---- inodes ---------------------------------------------------------

    pub fn stat_in(&mut self, root: u64, ino: u64) -> Result<Stat> {
        match self.tget(root, &Key::new(ino, KIND_INODE, 0))? {
            Some(v) => Stat::decode(ino, &v),
            None => Err(Error::NotFound),
        }
    }
    pub fn stat(&mut self, ino: u64) -> Result<Stat> {
        let r = self.root;
        self.stat_in(r, ino)
    }
    fn put_inode(&mut self, st: &Stat) -> Result<()> {
        self.tput(Key::new(st.ino, KIND_INODE, 0), &st.encode())
    }
    pub fn set_mode(&mut self, ino: u64, perm: u32) -> Result<()> {
        let mut st = self.stat(ino)?;
        st.mode = (st.mode & S_IFMT) | (perm & 0o7777);
        st.ctime = self.now;
        self.put_inode(&st)
    }
    pub fn set_times(&mut self, ino: u64, atime: i64, mtime: i64) -> Result<()> {
        let mut st = self.stat(ino)?;
        st.atime = atime;
        st.mtime = mtime;
        st.ctime = self.now;
        self.put_inode(&st)
    }

    // ---- directories ------------------------------------------------------

    fn dir_list_at(&mut self, root: u64, dir: u64, name: &[u8]) -> Result<(Key, Option<DirList>)> {
        let key = Key::new(dir, KIND_DIR, self.name_hash(name));
        let l = match self.tget(root, &key)? {
            Some(v) => Some(parse_dir(&v)?),
            None => None,
        };
        Ok((key, l))
    }

    pub fn lookup_in(&mut self, root: u64, dir: u64, name: &str) -> Result<Option<(u64, u8)>> {
        let (_, l) = self.dir_list_at(root, dir, name.as_bytes())?;
        Ok(l.and_then(|l| l.into_iter().find(|e| e.2 == name.as_bytes()).map(|e| (e.0, e.1))))
    }

    pub fn lookup(&mut self, dir: u64, name: &str) -> Result<u64> {
        let r = self.root;
        match self.lookup_in(r, dir, name)? {
            Some((i, _)) => Ok(i),
            None => Err(Error::NotFound),
        }
    }

    fn dir_add(&mut self, dir: u64, name: &str, ino: u64, t: u8) -> Result<()> {
        let r = self.root;
        let (key, l) = self.dir_list_at(r, dir, name.as_bytes())?;
        let mut l = l.unwrap_or_default();
        if l.iter().any(|e| e.2 == name.as_bytes()) { return Err(Error::Exists); }
        l.push((ino, t, name.as_bytes().to_vec()));
        self.tput(key, &encode_dir(&l))
    }

    fn dir_remove(&mut self, dir: u64, name: &str) -> Result<()> {
        let r = self.root;
        let (key, l) = self.dir_list_at(r, dir, name.as_bytes())?;
        let mut l = l.ok_or(Error::NotFound)?;
        let i = l.iter().position(|e| e.2 == name.as_bytes()).ok_or(Error::NotFound)?;
        l.remove(i);
        if l.is_empty() { self.tdel(key)?; } else { self.tput(key, &encode_dir(&l))?; }
        Ok(())
    }

    fn touch_dir(&mut self, dir: u64, delta: i64) -> Result<()> {
        let mut st = self.stat(dir)?;
        st.size = (st.size as i64 + delta).max(0) as u64;
        st.mtime = self.now;
        st.ctime = self.now;
        self.put_inode(&st)
    }

    pub fn readdir_in(&mut self, root: u64, dir: u64) -> Result<Vec<DirEntry>> {
        let st = self.stat_in(root, dir)?;
        if !st.is_dir() { return Err(Error::NotDir); }
        let items = self.tcollect(root, Key::new(dir, KIND_DIR, 0), Key::new(dir, KIND_DIR, u64::MAX), usize::MAX)?;
        let mut out = Vec::new();
        for (_, v) in items {
            for (ino, t, n) in parse_dir(&v)? {
                let name = core::str::from_utf8(&n).map_err(|_| Error::Corrupt("dir name utf8"))?;
                out.push(DirEntry { name: String::from(name), ino, mode_type: (t as u32) << 12 });
            }
        }
        Ok(out)
    }
    pub fn readdir(&mut self, dir: u64) -> Result<Vec<DirEntry>> {
        let r = self.root;
        self.readdir_in(r, dir)
    }

    fn dir_is_empty(&mut self, dir: u64) -> Result<bool> {
        let r = self.root;
        Ok(self.tcollect(r, Key::new(dir, KIND_DIR, 0), Key::new(dir, KIND_DIR, u64::MAX), 1)?.is_empty())
    }

    // ---- paths ------------------------------------------------------------

    pub fn resolve_in(&mut self, root: u64, path: &str) -> Result<u64> {
        let mut cur = ROOT_INO;
        for c in path.split('/') {
            if c.is_empty() || c == "." { continue; }
            if c == ".." { return Err(Error::InvalidName); }
            if !self.stat_in(root, cur)?.is_dir() { return Err(Error::NotDir); }
            cur = match self.lookup_in(root, cur, c)? {
                Some((i, _)) => i,
                None => return Err(Error::NotFound),
            };
        }
        Ok(cur)
    }
    pub fn resolve(&mut self, path: &str) -> Result<u64> {
        let r = self.root;
        self.resolve_in(r, path)
    }

    /// Splits a path into (directory inode, last component).
    pub fn split_parent(&mut self, path: &str) -> Result<(u64, String)> {
        let t = path.trim_end_matches('/');
        let (dir, name) = match t.rfind('/') {
            Some(i) => (&t[..i], &t[i + 1..]),
            None => ("", t),
        };
        valid_name(name)?;
        let d = self.resolve(dir)?;
        Ok((d, String::from(name)))
    }

    // ---- create / remove --------------------------------------------------

    fn new_node(&mut self, dir: u64, name: &str, mode: u32) -> Result<u64> {
        valid_name(name)?;
        if !self.stat(dir)?.is_dir() { return Err(Error::NotDir); }
        if self.lookup(dir, name).is_ok() { return Err(Error::Exists); }
        let ino = self.next_ino;
        self.next_ino += 1;
        let now = self.now;
        let st = Stat { ino, mode, flags: 0, size: 0, parent: dir, atime: now, mtime: now, ctime: now, crtime: now };
        self.put_inode(&st)?;
        self.dir_add(dir, name, ino, type_code(mode))?;
        self.touch_dir(dir, 1)?;
        Ok(ino)
    }

    pub fn create(&mut self, dir: u64, name: &str, perm: u32) -> Result<u64> {
        self.new_node(dir, name, S_IFREG | (perm & 0o7777))
    }
    pub fn mkdir(&mut self, dir: u64, name: &str, perm: u32) -> Result<u64> {
        self.new_node(dir, name, S_IFDIR | (perm & 0o7777))
    }
    pub fn symlink(&mut self, dir: u64, name: &str, target: &str) -> Result<u64> {
        if target.is_empty() || target.len() > MAX_VAL { return Err(Error::TooLarge); }
        let ino = self.new_node(dir, name, S_IFLNK | 0o777)?;
        self.tput(Key::new(ino, KIND_LINK, 0), target.as_bytes())?;
        let mut st = self.stat(ino)?;
        st.size = target.len() as u64;
        self.put_inode(&st)?;
        Ok(ino)
    }
    pub fn readlink_in(&mut self, root: u64, ino: u64) -> Result<String> {
        if !self.stat_in(root, ino)?.is_symlink() { return Err(Error::Invalid); }
        let v = self.tget(root, &Key::new(ino, KIND_LINK, 0))?.ok_or(Error::Corrupt("symlink target"))?;
        core::str::from_utf8(&v).map(String::from).map_err(|_| Error::Corrupt("symlink utf8"))
    }
    pub fn readlink(&mut self, ino: u64) -> Result<String> {
        let r = self.root;
        self.readlink_in(r, ino)
    }

    fn drop_inode(&mut self, ino: u64) -> Result<()> {
        self.punch(ino, 0, MAX_PG)?;
        self.tdel(Key::new(ino, KIND_LINK, 0))?;
        self.tdel(Key::new(ino, KIND_INODE, 0))?;
        Ok(())
    }

    pub fn unlink(&mut self, dir: u64, name: &str) -> Result<()> {
        let r = self.root;
        let (ino, t) = self.lookup_in(r, dir, name)?.ok_or(Error::NotFound)?;
        if t == type_code(S_IFDIR) { return Err(Error::IsDir); }
        self.dir_remove(dir, name)?;
        self.drop_inode(ino)?;
        self.touch_dir(dir, -1)
    }

    pub fn rmdir(&mut self, dir: u64, name: &str) -> Result<()> {
        let r = self.root;
        let (ino, t) = self.lookup_in(r, dir, name)?.ok_or(Error::NotFound)?;
        if t != type_code(S_IFDIR) { return Err(Error::NotDir); }
        if !self.dir_is_empty(ino)? { return Err(Error::NotEmpty); }
        self.dir_remove(dir, name)?;
        self.drop_inode(ino)?;
        self.touch_dir(dir, -1)
    }

    /// Atomic rename; an existing target is replaced (files, or empty directories).
    pub fn rename(&mut self, odir: u64, oname: &str, ndir: u64, nname: &str) -> Result<()> {
        valid_name(nname)?;
        let r = self.root;
        let (ino, t) = self.lookup_in(r, odir, oname)?.ok_or(Error::NotFound)?;
        if odir == ndir && oname == nname { return Ok(()); }
        if !self.stat(ndir)?.is_dir() { return Err(Error::NotDir); }
        let is_dir = t == type_code(S_IFDIR);
        if is_dir {
            // the target directory must not be inside the moved one
            let mut d = ndir;
            for _ in 0..4096 {
                if d == ino { return Err(Error::Invalid); }
                if d == ROOT_INO { break; }
                d = self.stat(d)?.parent;
            }
        }
        if let Some((dino, dt)) = self.lookup_in(r, ndir, nname)? {
            if dino == ino { return Err(Error::Invalid); }
            let dst_dir = dt == type_code(S_IFDIR);
            if dst_dir != is_dir { return Err(if dst_dir { Error::IsDir } else { Error::NotDir }); }
            if dst_dir && !self.dir_is_empty(dino)? { return Err(Error::NotEmpty); }
            self.dir_remove(ndir, nname)?;
            self.drop_inode(dino)?;
            self.touch_dir(ndir, -1)?;
        }
        self.dir_remove(odir, oname)?;
        self.touch_dir(odir, -1)?;
        self.dir_add(ndir, nname, ino, t)?;
        self.touch_dir(ndir, 1)?;
        let mut st = self.stat(ino)?;
        st.parent = ndir;
        st.ctime = self.now;
        self.put_inode(&st)
    }

    // ---- file data --------------------------------------------------------

    /// Extents overlapping pages [a, b), at most `limit`.
    fn extents_in(&mut self, root: u64, ino: u64, a: u64, b: u64, limit: usize) -> Result<Vec<Ext>> {
        let bc = self.block_count;
        let mut out: Vec<Ext> = Vec::new();
        if let Some((k, v)) = self.tfind_le(root, &Key::new(ino, KIND_EXT, a))? {
            if k.obj == ino && k.kind == KIND_EXT {
                let e = Ext::parse(&k, &v, bc)?;
                if e.file_pg + e.n as u64 > a && e.file_pg < b { out.push(e); }
            }
        }
        if b > a {
            let items = self.tcollect(root, Key::new(ino, KIND_EXT, a), Key::new(ino, KIND_EXT, b - 1), limit)?;
            for (k, v) in items {
                if out.last().map_or(false, |l| l.file_pg == k.off) { continue; }
                out.push(Ext::parse(&k, &v, bc)?);
                if out.len() >= limit { break; }
            }
        }
        Ok(out)
    }

    /// Reads whole pages [a, a+n) into `out`; holes read as zeros.
    fn read_pages_raw(&mut self, root: u64, ino: u64, a: u64, n: u64, out: &mut [u8]) -> Result<()> {
        out.fill(0);
        let mut next = a;
        while next < a + n {
            let exts = self.extents_in(root, ino, next, a + n, 256)?;
            if exts.is_empty() { break; }
            for e in exts {
                let s = e.file_pg.max(a);
                let t = (e.file_pg + e.n as u64).min(a + n);
                next = next.max(t);
                if s >= t { continue; }
                let dst = &mut out[((s - a) as usize) * BLOCK_SIZE..((t - a) as usize) * BLOCK_SIZE];
                self.dev_read(e.start + (s - e.file_pg), dst)?;
                for (i, pg) in dst.chunks(BLOCK_SIZE).enumerate() {
                    if crc32c(pg) != e.csum[(s - e.file_pg) as usize + i] {
                        return Err(Error::Checksum(e.start + (s - e.file_pg) + i as u64));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn read_in(&mut self, root: u64, ino: u64, off: u64, buf: &mut [u8]) -> Result<usize> {
        let st = self.stat_in(root, ino)?;
        if st.is_dir() { return Err(Error::IsDir); }
        if off >= st.size { return Ok(0); }
        let n = (buf.len() as u64).min(st.size - off) as usize;
        let mut done = 0usize;
        while done < n {
            let pos = off + done as u64;
            let pg = pos / BLOCK_SIZE as u64;
            let po = (pos % BLOCK_SIZE as u64) as usize;
            let pages = ((po + (n - done) + BLOCK_SIZE - 1) / BLOCK_SIZE).min(256);
            let mut tmp = vec![0u8; pages * BLOCK_SIZE];
            self.read_pages_raw(root, ino, pg, pages as u64, &mut tmp)?;
            let take = (n - done).min(pages * BLOCK_SIZE - po);
            buf[done..done + take].copy_from_slice(&tmp[po..po + take]);
            done += take;
        }
        Ok(n)
    }
    pub fn read(&mut self, ino: u64, off: u64, buf: &mut [u8]) -> Result<usize> {
        let r = self.root;
        self.read_in(r, ino, off, buf)
    }

    /// Removes the mapping of pages [a, b) and releases their blocks.
    fn punch(&mut self, ino: u64, a: u64, b: u64) -> Result<()> {
        loop {
            let r = self.root;
            let exts = self.extents_in(r, ino, a, b, 64)?;
            if exts.is_empty() { return Ok(()); }
            for e in exts {
                let s = e.file_pg;
                let t = s + e.n as u64;
                let lo = s.max(a);
                let hi = t.min(b);
                if s < a {
                    let h = Ext { file_pg: s, start: e.start, n: (a - s) as u32, gen: e.gen, csum: e.csum[..(a - s) as usize].to_vec() };
                    self.tput(Key::new(ino, KIND_EXT, s), &h.encode())?;
                } else {
                    self.tdel(Key::new(ino, KIND_EXT, s))?;
                }
                if t > b {
                    let off = (b - s) as usize;
                    let tl = Ext { file_pg: b, start: e.start + off as u64, n: (t - b) as u32, gen: e.gen, csum: e.csum[off..].to_vec() };
                    self.tput(Key::new(ino, KIND_EXT, b), &tl.encode())?;
                }
                self.release(e.start + (lo - s), hi - lo, e.gen);
            }
        }
    }

    fn ext_insert(&mut self, ino: u64, fpg: u64, start: u64, csum: Vec<u32>) -> Result<()> {
        let bc = self.block_count;
        let gen = self.cur_gen;
        if fpg > 0 {
            let r = self.root;
            if let Some((k, v)) = self.tfind_le(r, &Key::new(ino, KIND_EXT, fpg - 1))? {
                if k.obj == ino && k.kind == KIND_EXT {
                    let mut e = Ext::parse(&k, &v, bc)?;
                    if e.file_pg + e.n as u64 == fpg && e.start + e.n as u64 == start && e.gen == gen && e.n as u64 + csum.len() as u64 <= MAX_EXT {
                        e.n += csum.len() as u32;
                        e.csum.extend_from_slice(&csum);
                        return self.tput(k, &e.encode());
                    }
                }
            }
        }
        let e = Ext { file_pg: fpg, start, n: csum.len() as u32, gen, csum };
        self.tput(Key::new(ino, KIND_EXT, fpg), &e.encode())
    }

    /// Writes whole pages (at most MAX_EXT) at page `pg`, copy-on-write.
    fn put_pages(&mut self, ino: u64, pg: u64, buf: &[u8]) -> Result<()> {
        let n = (buf.len() / BLOCK_SIZE) as u64;
        if self.free_blocks() < n + RESERVE { return Err(Error::NoSpace); }
        self.punch(ino, pg, pg + n)?;
        let bc = self.block_count;
        let mut hint = 0;
        if pg > 0 {
            let r = self.root;
            if let Some((k, v)) = self.tfind_le(r, &Key::new(ino, KIND_EXT, pg - 1))? {
                if k.obj == ino && k.kind == KIND_EXT {
                    let e = Ext::parse(&k, &v, bc)?;
                    if e.file_pg + e.n as u64 == pg { hint = e.start + e.n as u64; }
                }
            }
        }
        let mut done = 0u64;
        while done < n {
            let (s, l) = self.alloc_data(n - done, hint)?;
            let chunk = &buf[(done as usize) * BLOCK_SIZE..((done + l) as usize) * BLOCK_SIZE];
            self.dev_write(s, chunk)?;
            let csum: Vec<u32> = chunk.chunks(BLOCK_SIZE).map(crc32c).collect();
            self.ext_insert(ino, pg + done, s, csum)?;
            hint = s + l;
            done += l;
        }
        Ok(())
    }

    pub fn write(&mut self, ino: u64, off: u64, data: &[u8]) -> Result<()> {
        let mut st = self.stat(ino)?;
        if st.is_dir() { return Err(Error::IsDir); }
        if !st.is_file() { return Err(Error::Invalid); }
        if data.is_empty() { return Ok(()); }
        let end = off.checked_add(data.len() as u64).ok_or(Error::TooLarge)?;
        let mut pos = off;
        let mut rem = data;
        while !rem.is_empty() {
            let pg = pos / BLOCK_SIZE as u64;
            let po = (pos % BLOCK_SIZE as u64) as usize;
            let npages = ((po + rem.len() + BLOCK_SIZE - 1) / BLOCK_SIZE).min(MAX_EXT as usize);
            let take = rem.len().min(npages * BLOCK_SIZE - po);
            let mut buf = vec![0u8; npages * BLOCK_SIZE];
            let r = self.root;
            if po != 0 {
                self.read_pages_raw(r, ino, pg, 1, &mut buf[..BLOCK_SIZE])?;
            }
            if (po + take) % BLOCK_SIZE != 0 {
                let last = npages - 1;
                self.read_pages_raw(r, ino, pg + last as u64, 1, &mut buf[last * BLOCK_SIZE..])?;
            }
            buf[po..po + take].copy_from_slice(&rem[..take]);
            self.put_pages(ino, pg, &buf)?;
            pos += take as u64;
            rem = &rem[take..];
        }
        st.size = st.size.max(end);
        st.mtime = self.now;
        st.ctime = self.now;
        self.put_inode(&st)
    }

    pub fn truncate(&mut self, ino: u64, size: u64) -> Result<()> {
        let mut st = self.stat(ino)?;
        if st.is_dir() { return Err(Error::IsDir); }
        if !st.is_file() { return Err(Error::Invalid); }
        if size < st.size {
            self.punch(ino, (size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64, MAX_PG)?;
            let po = (size % BLOCK_SIZE as u64) as usize;
            if po != 0 {
                let pg = size / BLOCK_SIZE as u64;
                let r = self.root;
                let mapped = !self.extents_in(r, ino, pg, pg + 1, 1)?.is_empty();
                if mapped {
                    let mut buf = vec![0u8; BLOCK_SIZE];
                    self.read_pages_raw(r, ino, pg, 1, &mut buf)?;
                    buf[po..].fill(0);
                    self.put_pages(ino, pg, &buf)?;
                }
            }
        }
        st.size = size;
        st.mtime = self.now;
        st.ctime = self.now;
        self.put_inode(&st)
    }

    // ---- path conveniences ------------------------------------------------

    pub fn mkdir_path(&mut self, path: &str, perm: u32) -> Result<u64> {
        let (d, n) = self.split_parent(path)?;
        self.mkdir(d, &n, perm)
    }
    pub fn create_path(&mut self, path: &str, perm: u32) -> Result<u64> {
        let (d, n) = self.split_parent(path)?;
        self.create(d, &n, perm)
    }
    pub fn unlink_path(&mut self, path: &str) -> Result<()> {
        let (d, n) = self.split_parent(path)?;
        self.unlink(d, &n)
    }
    pub fn rmdir_path(&mut self, path: &str) -> Result<()> {
        let (d, n) = self.split_parent(path)?;
        self.rmdir(d, &n)
    }
    pub fn rename_path(&mut self, from: &str, to: &str) -> Result<()> {
        let (od, on) = self.split_parent(from)?;
        let (nd, nn) = self.split_parent(to)?;
        self.rename(od, &on, nd, &nn)
    }
    /// Creates or replaces a file with the given contents.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<u64> {
        let (d, n) = self.split_parent(path)?;
        let ino = match self.lookup(d, &n) {
            Ok(i) => { self.truncate(i, 0)?; i }
            Err(Error::NotFound) => self.create(d, &n, 0o644)?,
            Err(e) => return Err(e),
        };
        self.write(ino, 0, data)?;
        Ok(ino)
    }
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        let ino = self.resolve(path)?;
        let st = self.stat(ino)?;
        let mut v = vec![0u8; st.size as usize];
        self.read(ino, 0, &mut v)?;
        Ok(v)
    }
}
