/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Reading the boot medium through INT 13h extensions: raw sectors, GPT/MBR partitions,
FAT32 and ISO9660. `Volume` is what the rest of the loader sees.

Paths use '/' and start at the volume root. Names compare case-insensitively.
*/
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;

use crate::mem::{PageKind, PAGE};
use crate::rm::{self, Regs};

const DAP: u32 = 0x2400;
const PARAMS: u32 = 0x2500;
/// Bounce buffer below 1 MiB (the BIOS cannot write above it): 64 KiB at 0x70000.
const BOUNCE: u32 = 0x70000;
const BOUNCE_LEN: u32 = 0x10000;

#[derive(Clone, Copy)]
pub struct Disk {
    pub drive: u8,
    /// Bytes per sector (512, or 2048 on optical media).
    pub bps: u32,
    pub sectors: u64,
}

impl Disk {
    pub fn open(drive: u8) -> Disk {
        let mut d = Disk { drive, bps: 512, sectors: 0 };
        unsafe {
            ptr::write_bytes(PARAMS as *mut u8, 0, 0x20);
            ptr::write(PARAMS as *mut u16, 0x1E);
        }
        let mut r = Regs::new();
        r.eax = 0x4800;
        r.edx = drive as u32;
        r.ds_si(PARAMS);
        rm::int(0x13, &mut r);
        if !r.carry() {
            let bps = unsafe { ptr::read((PARAMS + 0x18) as *const u16) } as u32;
            if bps.is_power_of_two() && (512..=4096).contains(&bps) {
                d.bps = bps;
            }
            d.sectors = unsafe { ptr::read_unaligned((PARAMS + 0x10) as *const u64) };
        }
        d
    }

    /// Read `count` sectors (at most what fits the bounce buffer) into the bounce buffer.
    fn read_bounce(&self, lba: u64, count: u32) -> bool {
        for attempt in 0..3 {
            unsafe {
                ptr::write(DAP as *mut u8, 16);
                ptr::write((DAP + 1) as *mut u8, 0);
                ptr::write((DAP + 2) as *mut u16, count as u16);
                ptr::write((DAP + 4) as *mut u16, (BOUNCE & 15) as u16);
                ptr::write((DAP + 6) as *mut u16, (BOUNCE >> 4) as u16);
                ptr::write_unaligned((DAP + 8) as *mut u64, lba);
            }
            let mut r = Regs::new();
            r.eax = 0x4200;
            r.edx = self.drive as u32;
            r.ds_si(DAP);
            rm::int(0x13, &mut r);
            if !r.carry() {
                return true;
            }
            if attempt < 2 {
                let mut r = Regs::new();
                r.eax = 0;
                r.edx = self.drive as u32;
                rm::int(0x13, &mut r);
            }
        }
        false
    }

    /// Read bytes at any offset.
    pub fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> bool {
        let max_sectors = (BOUNCE_LEN / self.bps).min(127);
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let lba = pos / self.bps as u64;
            let skip = (pos % self.bps as u64) as usize;
            let want = buf.len() - done;
            let n = (((skip + want) as u64 + self.bps as u64 - 1) / self.bps as u64).min(max_sectors as u64) as u32;
            if !self.read_bounce(lba, n) {
                return false;
            }
            let take = (n as usize * self.bps as usize - skip).min(want);
            unsafe { ptr::copy_nonoverlapping((BOUNCE as usize + skip) as *const u8, buf.as_mut_ptr().add(done), take) };
            done += take;
        }
        true
    }
}

fn le16(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }
fn le32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn le64(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

// ─── FAT32 ──────────────────────────────────────────────────────────────────

pub struct Fat {
    disk: Disk,
    bps: u64,
    spc: u64,
    fat_off: u64,
    data_off: u64,
    root: u32,
    clusters: u32,
    cache_sector: u64,
    cache: Vec<u8>,
}

struct DirEnt {
    name: String,
    cluster: u32,
    size: u32,
    dir: bool,
}

impl Fat {
    /// FAT32 file system whose boot sector is at byte `base` of the disk.
    pub fn open(disk: Disk, base: u64) -> Option<Fat> {
        let mut b = [0u8; 512];
        if !disk.read_bytes(base, &mut b) || b[510] != 0x55 || b[511] != 0xAA {
            return None;
        }
        let bps = le16(&b, 11) as u64;
        let spc = b[13] as u64;
        let rsvd = le16(&b, 14) as u64;
        let nfats = b[16] as u64;
        let fatsz = le32(&b, 36) as u64;
        let total = if le16(&b, 19) != 0 { le16(&b, 19) as u64 } else { le32(&b, 32) as u64 };
        if !(512..=4096).contains(&bps) || !bps.is_power_of_two() || spc == 0 || !spc.is_power_of_two() {
            return None;
        }
        if le16(&b, 17) != 0 || le16(&b, 22) != 0 || fatsz == 0 || nfats == 0 || total == 0 {
            return None; // FAT12/16
        }
        let root = le32(&b, 44);
        let data_sectors = total.checked_sub(rsvd + nfats * fatsz)?;
        let clusters = (data_sectors / spc) as u32;
        if clusters < 65525 || root < 2 {
            return None;
        }
        Some(Fat {
            disk,
            bps,
            spc,
            fat_off: base + rsvd * bps,
            data_off: base + (rsvd + nfats * fatsz) * bps,
            root,
            clusters,
            cache_sector: u64::MAX,
            cache: alloc::vec![0u8; bps as usize],
        })
    }

    fn cluster_bytes(&self) -> u64 {
        self.spc * self.bps
    }

    fn next(&mut self, c: u32) -> u32 {
        let off = c as u64 * 4;
        let sector = off / self.bps;
        if self.cache_sector != sector {
            let at = self.fat_off + sector * self.bps;
            if !self.disk.read_bytes(at, &mut self.cache) {
                return 0x0FFF_FFFF;
            }
            self.cache_sector = sector;
        }
        le32(&self.cache, (off % self.bps) as usize) & 0x0FFF_FFFF
    }

    fn is_data(&self, c: u32) -> bool {
        c >= 2 && c < self.clusters + 2
    }

    /// Read `size` bytes of the chain starting at `cluster` to `dst`.
    fn read_chain(&mut self, cluster: u32, size: u64, dst: *mut u8) -> bool {
        let cb = self.cluster_bytes();
        let (mut c, mut left, mut p) = (cluster, size, dst);
        while left > 0 {
            if !self.is_data(c) {
                return false;
            }
            let (first, mut run) = (c, 1u64);
            let mut nxt = self.next(c);
            while nxt == c + 1 && run * cb < left {
                run += 1;
                c = nxt;
                nxt = self.next(c);
            }
            let bytes = (run * cb).min(left);
            let buf = unsafe { core::slice::from_raw_parts_mut(p, bytes as usize) };
            if !self.disk.read_bytes(self.data_off + (first as u64 - 2) * cb, buf) {
                return false;
            }
            p = unsafe { p.add(bytes as usize) };
            left -= bytes;
            c = nxt;
        }
        true
    }

    fn read_dir(&mut self, cluster: u32) -> Vec<DirEnt> {
        let mut data: Vec<u8> = Vec::new();
        let cb = self.cluster_bytes() as usize;
        let mut c = cluster;
        let mut guard = 0;
        while self.is_data(c) && guard < 4096 {
            let at = data.len();
            data.resize(at + cb, 0);
            let off = self.data_off + (c as u64 - 2) * cb as u64;
            if !self.disk.read_bytes(off, &mut data[at..]) {
                break;
            }
            c = self.next(c);
            guard += 1;
        }
        let mut out = Vec::new();
        let mut lfn: Vec<u16> = Vec::new();
        for e in data.chunks_exact(32) {
            if e[0] == 0 {
                break;
            }
            if e[0] == 0xE5 {
                lfn.clear();
                continue;
            }
            let attr = e[11];
            if attr == 0x0F {
                let seq = (e[0] & 0x1F) as usize;
                if e[0] & 0x40 != 0 {
                    lfn.clear();
                    lfn.resize(seq * 13, 0xFFFF);
                }
                if seq >= 1 && seq * 13 <= lfn.len() {
                    let base = (seq - 1) * 13;
                    for (i, o) in [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30].iter().enumerate() {
                        lfn[base + i] = le16(e, *o);
                    }
                }
                continue;
            }
            if attr & 0x08 != 0 {
                lfn.clear();
                continue;
            }
            let name = if !lfn.is_empty() {
                let units: Vec<u16> = lfn.iter().cloned().take_while(|&u| u != 0 && u != 0xFFFF).collect();
                String::from_utf16_lossy(&units)
            } else {
                let base: String = e[0..8].iter().map(|&b| b as char).collect::<String>().trim_end().into();
                let ext: String = e[8..11].iter().map(|&b| b as char).collect::<String>().trim_end().into();
                let mut n = base;
                if !ext.is_empty() {
                    n.push('.');
                    n.push_str(&ext);
                }
                n
            };
            lfn.clear();
            let cluster = ((le16(e, 20) as u32) << 16) | le16(e, 26) as u32;
            out.push(DirEnt { name, cluster, size: le32(e, 28), dir: attr & 0x10 != 0 });
        }
        out
    }

    fn lookup(&mut self, path: &str) -> Option<DirEnt> {
        let mut cur = DirEnt { name: String::new(), cluster: self.root, size: 0, dir: true };
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            if !cur.dir {
                return None;
            }
            let ents = self.read_dir(if cur.cluster == 0 { self.root } else { cur.cluster });
            cur = ents.into_iter().find(|e| e.name.eq_ignore_ascii_case(comp))?;
        }
        Some(cur)
    }
}

// ─── ISO9660 ────────────────────────────────────────────────────────────────

pub struct Iso {
    disk: Disk,
    root_lba: u32,
    root_len: u32,
}

impl Iso {
    /// ISO9660 on the whole device (CD, or a hybrid image written to a stick).
    pub fn open(disk: Disk) -> Option<Iso> {
        let mut pvd = [0u8; 2048];
        if !disk.read_bytes(16 * 2048, &mut pvd) || pvd[0] != 1 || &pvd[1..6] != b"CD001" {
            return None;
        }
        Some(Iso { disk, root_lba: le32(&pvd, 156 + 2), root_len: le32(&pvd, 156 + 10) })
    }

    fn lookup(&mut self, path: &str) -> Option<(u32, u32, bool)> {
        let mut cur = (self.root_lba, self.root_len, true);
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            if !cur.2 {
                return None;
            }
            let mut dir = alloc::vec![0u8; cur.1 as usize];
            if !self.disk.read_bytes(cur.0 as u64 * 2048, &mut dir) {
                return None;
            }
            let mut off = 0usize;
            let mut found = None;
            while off < dir.len() {
                let len = dir[off] as usize;
                if len == 0 {
                    off = (off / 2048 + 1) * 2048;
                    continue;
                }
                if off + len > dir.len() || len < 34 {
                    break;
                }
                let nlen = dir[off + 32] as usize;
                let raw = &dir[off + 33..off + 33 + nlen.min(len - 33)];
                let mut name: String = raw.iter().map(|&b| b as char).collect();
                if let Some(p) = name.find(';') {
                    name.truncate(p);
                }
                if name.ends_with('.') && name.len() > 1 {
                    name.pop();
                }
                if name.eq_ignore_ascii_case(comp) {
                    found = Some((le32(&dir, off + 2), le32(&dir, off + 10), dir[off + 25] & 2 != 0));
                    break;
                }
                off += len;
            }
            cur = found?;
        }
        Some(cur)
    }
}

// ─── Volume ─────────────────────────────────────────────────────────────────

pub enum Volume {
    Fat(Fat),
    Iso(Iso),
}

/// A file loaded into page-aligned memory.
#[derive(Clone, Copy)]
pub struct Loaded {
    pub addr: u64,
    pub size: u64,
}

impl Volume {
    pub fn kind(&self) -> &'static str {
        match self {
            Volume::Fat(_) => "FAT32",
            Volume::Iso(_) => "ISO9660",
        }
    }

    pub fn exists(&mut self, path: &str) -> bool {
        match self {
            Volume::Fat(f) => f.lookup(path).map_or(false, |e| !e.dir),
            Volume::Iso(i) => i.lookup(path).map_or(false, |e| !e.2),
        }
    }

    fn size_of(&mut self, path: &str) -> Option<u64> {
        match self {
            Volume::Fat(f) => f.lookup(path).filter(|e| !e.dir).map(|e| e.size as u64),
            Volume::Iso(i) => i.lookup(path).filter(|e| !e.2).map(|e| e.1 as u64),
        }
    }

    fn read_into(&mut self, path: &str, size: u64, dst: *mut u8) -> bool {
        match self {
            Volume::Fat(f) => match f.lookup(path) {
                Some(e) => size == 0 || f.read_chain(e.cluster, size, dst),
                None => false,
            },
            Volume::Iso(i) => match i.lookup(path) {
                Some((lba, _, _)) => {
                    let buf = unsafe { core::slice::from_raw_parts_mut(dst, size as usize) };
                    i.disk.read_bytes(lba as u64 * 2048, buf)
                }
                None => false,
            },
        }
    }

    /// Whole file into fresh pages.
    pub fn load(&mut self, path: &str, kind: PageKind) -> Option<Loaded> {
        let size = self.size_of(path)?;
        let pages = ((size + PAGE - 1) / PAGE).max(1) as usize;
        let addr = crate::pmem::alloc_pages(pages, kind);
        if self.read_into(path, size, addr as *mut u8) { Some(Loaded { addr, size }) } else { None }
    }

    /// Small files (the configuration) into the heap.
    pub fn read_small(&mut self, path: &str) -> Option<Vec<u8>> {
        let size = self.size_of(path)?;
        if size > 1 << 20 {
            return None;
        }
        let mut v = alloc::vec![0u8; size as usize];
        if self.read_into(path, size, v.as_mut_ptr()) { Some(v) } else { None }
    }
}

/// Partition start offsets (bytes) from GPT, else from the MBR.
fn partitions(disk: &Disk) -> Vec<u64> {
    let mut out = Vec::new();
    let bps = disk.bps as u64;
    let mut hdr = alloc::vec![0u8; 512];
    if disk.read_bytes(bps, &mut hdr) && &hdr[0..8] == b"EFI PART" {
        let entries_lba = le64(&hdr, 72);
        let count = (le32(&hdr, 80) as usize).min(256);
        let esize = (le32(&hdr, 84) as usize).clamp(128, 1024);
        let mut table = alloc::vec![0u8; count * esize];
        if disk.read_bytes(entries_lba * bps, &mut table) {
            for e in table.chunks_exact(esize) {
                if e[0..16].iter().any(|&b| b != 0) {
                    out.push(le64(e, 32) * bps);
                }
            }
        }
        return out;
    }
    let mut mbr = alloc::vec![0u8; 512];
    if disk.read_bytes(0, &mut mbr) && mbr[510] == 0x55 && mbr[511] == 0xAA {
        for i in 0..4 {
            let e = &mbr[446 + i * 16..446 + i * 16 + 16];
            if e[4] != 0 && e[4] != 0xEE && e[4] != 0x05 && e[4] != 0x0F {
                out.push(le32(e, 8) as u64 * bps);
            }
        }
    }
    out
}

/// The volume of the boot drive that holds any of `probes`: ISO9660 on the whole device,
/// then FAT32 partitions (GPT or MBR), then FAT32 without a partition table.
pub fn find_volume(drive: u8, probes: &[&str]) -> Option<Volume> {
    let disk = Disk::open(drive);
    let has = |v: &mut Volume| probes.iter().any(|p| v.exists(p));
    if let Some(i) = Iso::open(disk) {
        let mut v = Volume::Iso(i);
        if has(&mut v) {
            return Some(v);
        }
    }
    for off in partitions(&disk) {
        if let Some(f) = Fat::open(disk, off) {
            let mut v = Volume::Fat(f);
            if has(&mut v) {
                return Some(v);
            }
        }
    }
    if let Some(f) = Fat::open(disk, 0) {
        let mut v = Volume::Fat(f);
        if has(&mut v) {
            return Some(v);
        }
    }
    None
}
