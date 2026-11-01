/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
System updates on the EFI System Partition (ESP) of the running installation.

`tomato install ospab-base` / `tomato upgrade` hand the kernel, the UEFI loader and the BIOS
loader of a signed `kind = system` package to `prepare()`, which only reads; `Plan::apply()` then
writes. Rules that keep the ESP safe (it may be shared with Windows or Linux):

  - every write goes through `Dev`, which refuses anything outside the ESP partition;
  - only files in our own directory are touched: `\boot\` (whole-disk install) or
    `\EFI\ospab\` (alongside install), plus the ospab loader file(s) (`\EFI\BOOT\BOOTX64.EFI` only
    when it is our loader);
  - new files are written next to the old ones (`KERNEL.NEW`), read back and compared first; the
    switch is a single directory-entry write that points `KERNEL` at the new clusters, so there is no
    moment without a bootable `KERNEL`; the previous data stays as `KERNEL.OLD`;
  - the boot counter file `UPDATE.ST` (boot/common/update.rs) is written last.

The kernel clears the pending flag with `mark_boot_ok()` once the console is ready.
Documentation: docs/en/packages.md, docs/en/boot.md.
*/
extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::update;

type Res<T> = Result<T, String>;

const ESP_GUID: [u8; 16] = [0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B];
const LINUX_GUID: [u8; 16] = [0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4];
const BIOS_BOOT_GUID: [u8; 16] = [0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6F, 0x6E, 0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49];
const BIOS_PART_START: u64 = 34;
const FAT_DATE: u16 = 0x5C21; // 2026-01-01, like the installer
const EOC: u32 = 0x0FFF_FFFF;
const CHUNK_SECTORS: usize = 64;

fn le16(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }
fn le32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) }
fn le64(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

/// "1.1.0.191": kernel version plus build number (`.0` for a development build).
pub fn running_version() -> String {
    let b = env!("OSPAB_BUILD");
    let n: u32 = b.parse().unwrap_or(0);
    format!("{}.{}", env!("CARGO_PKG_VERSION"), n)
}

// ─── Block access, confined to one partition ────────────────────────────────

struct Dev {
    disk: usize,
    base: u64,
    sectors: u64,
}

impl Dev {
    fn rd_sectors(&self, lba: u64, buf: &mut [u8]) -> Res<()> {
        let n = (buf.len() / 512) as u64;
        if lba + n > self.sectors {
            return Err("read outside the partition".to_string());
        }
        for _ in 0..3 {
            if crate::drivers::read(self.disk, self.base + lba, n as u32, buf) {
                return Ok(());
            }
        }
        Err(format!("disk read error at LBA {}", self.base + lba))
    }

    fn wr_sectors(&self, lba: u64, data: &[u8]) -> Res<()> {
        let n = (data.len() / 512) as u64;
        if lba + n > self.sectors {
            return Err("write outside the partition refused".to_string());
        }
        for _ in 0..3 {
            if crate::drivers::write(self.disk, self.base + lba, n as u32, data) {
                return Ok(());
            }
        }
        Err(format!("disk write error at LBA {}", self.base + lba))
    }

    fn rd(&self, off: u64, buf: &mut [u8]) -> Res<()> {
        let (mut pos, mut done) = (off, 0usize);
        while done < buf.len() {
            let skip = (pos % 512) as usize;
            let n = ((skip + buf.len() - done + 511) / 512).min(CHUNK_SECTORS);
            let mut tmp = vec![0u8; n * 512];
            self.rd_sectors(pos / 512, &mut tmp)?;
            let take = (n * 512 - skip).min(buf.len() - done);
            buf[done..done + take].copy_from_slice(&tmp[skip..skip + take]);
            done += take;
            pos += take as u64;
        }
        Ok(())
    }

    fn wr(&self, off: u64, data: &[u8]) -> Res<()> {
        let (mut pos, mut done) = (off, 0usize);
        while done < data.len() {
            let skip = (pos % 512) as usize;
            let n = ((skip + data.len() - done + 511) / 512).min(CHUNK_SECTORS);
            let take = (n * 512 - skip).min(data.len() - done);
            let mut tmp = vec![0u8; n * 512];
            if skip != 0 || take != n * 512 {
                self.rd_sectors(pos / 512, &mut tmp)?;
            }
            tmp[skip..skip + take].copy_from_slice(&data[done..done + take]);
            self.wr_sectors(pos / 512, &tmp)?;
            done += take;
            pos += take as u64;
        }
        Ok(())
    }

    fn flush(&self) {
        crate::drivers::flush(self.disk);
    }
}

// ─── GPT ─────────────────────────────────────────────────────────────────────

struct Part {
    start: u64,
    sectors: u64,
    typ: [u8; 16],
    name: String,
}

fn read_gpt(disk: usize) -> Option<Vec<Part>> {
    let mut h = [0u8; 512];
    if !crate::drivers::read(disk, 1, 1, &mut h) || &h[0..8] != b"EFI PART" {
        return None;
    }
    let (lba, n, sz) = (le64(&h, 72), le32(&h, 80) as usize, le32(&h, 84) as usize);
    if sz != 128 || n == 0 || n > 128 {
        return None;
    }
    let mut ents = vec![0u8; (n * sz + 511) / 512 * 512];
    if !crate::drivers::read(disk, lba, (ents.len() / 512) as u32, &mut ents) {
        return None;
    }
    let mut v = Vec::new();
    for e in ents.chunks_exact(sz).take(n) {
        if e[0..16].iter().all(|&b| b == 0) {
            continue;
        }
        let (s, l) = (le64(e, 32), le64(e, 40));
        if l < s {
            continue;
        }
        let units: Vec<u16> = (0..36).map(|i| le16(e, 56 + 2 * i)).take_while(|&u| u != 0).collect();
        v.push(Part { start: s, sectors: l - s + 1, typ: e[0..16].try_into().unwrap(), name: String::from_utf16_lossy(&units) });
    }
    Some(v)
}

// ─── FAT32 ───────────────────────────────────────────────────────────────────

struct Ent {
    idx: usize,
    lfn_start: usize,
    name: String,
    sfn: [u8; 11],
    attr: u8,
    cluster: u32,
    size: u32,
}

struct Fat {
    dev: Dev,
    bps: u64,
    cb: u64,
    fat_off: u64,
    fat_bytes: u64,
    nfats: u64,
    data_off: u64,
    root: u32,
    clusters: u32,
    fat: Vec<u8>,
    dirty: BTreeSet<usize>,
    hint: u32,
    fsinfo_off: Option<u64>,
    free_delta: i64,
}

fn sfn_of(name: &str) -> Option<[u8; 11]> {
    let up = name.to_ascii_uppercase();
    let (b, e) = match up.rsplit_once('.') {
        Some((b, e)) => (b, e),
        None => (up.as_str(), ""),
    };
    if b.is_empty() || b.len() > 8 || e.len() > 3 {
        return None;
    }
    let mut out = [b' '; 11];
    for (i, c) in b.bytes().enumerate() {
        out[i] = c;
    }
    for (i, c) in e.bytes().enumerate() {
        out[8 + i] = c;
    }
    let bad = |c: u8| c < 0x21 || c > 0x7E || b"\"*+,/:;<=>?[\\]|.".contains(&c);
    if b.bytes().chain(e.bytes()).any(bad) {
        return None;
    }
    Some(out)
}

impl Fat {
    fn mount(dev: Dev) -> Res<Fat> {
        let mut b = [0u8; 512];
        dev.rd_sectors(0, &mut b)?;
        if b[510] != 0x55 || b[511] != 0xAA {
            return Err("no FAT boot sector".to_string());
        }
        let bps = le16(&b, 11) as u64;
        let spc = b[13] as u64;
        let rsvd = le16(&b, 14) as u64;
        let nfats = b[16] as u64;
        let fatsz = le32(&b, 36) as u64;
        let total = if le16(&b, 19) != 0 { le16(&b, 19) as u64 } else { le32(&b, 32) as u64 };
        if !(512..=4096).contains(&bps) || !bps.is_power_of_two() || spc == 0 || !spc.is_power_of_two() {
            return Err("unsupported FAT geometry".to_string());
        }
        if le16(&b, 17) != 0 || le16(&b, 22) != 0 || fatsz == 0 || nfats == 0 || nfats > 2 || total == 0 {
            return Err("not FAT32".to_string());
        }
        if le16(&b, 40) & 0x80 != 0 {
            return Err("FAT mirroring is off; refusing to write".to_string());
        }
        let root = le32(&b, 44);
        let data_sectors = total.checked_sub(rsvd + nfats * fatsz).ok_or("bad FAT size")?;
        let clusters = (data_sectors / spc) as u32;
        if clusters < 65525 || root < 2 || fatsz * bps > 32 * 1024 * 1024 {
            return Err("not FAT32".to_string());
        }
        let fat_off = rsvd * bps;
        let fat_bytes = fatsz * bps;
        let mut fat = vec![0u8; fat_bytes as usize];
        dev.rd(fat_off, &mut fat)?;
        let fsi = le16(&b, 48) as u64;
        let mut fsinfo_off = None;
        if fsi != 0 && fsi < rsvd {
            let mut s = [0u8; 512];
            dev.rd(fsi * bps, &mut s)?;
            if le32(&s, 0) == 0x4161_5252 && le32(&s, 484) == 0x6141_7272 {
                fsinfo_off = Some(fsi * bps);
            }
        }
        Ok(Fat {
            dev,
            bps,
            cb: bps * spc,
            fat_off,
            fat_bytes,
            nfats,
            data_off: (rsvd + nfats * fatsz) * bps,
            root,
            clusters,
            fat,
            dirty: BTreeSet::new(),
            hint: 2,
            fsinfo_off,
            free_delta: 0,
        })
    }

    fn c_off(&self, c: u32) -> u64 {
        self.data_off + (c as u64 - 2) * self.cb
    }
    fn is_data(&self, c: u32) -> bool {
        c >= 2 && c < self.clusters + 2
    }
    fn fat_get(&self, c: u32) -> u32 {
        le32(&self.fat, c as usize * 4) & 0x0FFF_FFFF
    }
    fn fat_set(&mut self, c: u32, v: u32) {
        let o = c as usize * 4;
        let old = le32(&self.fat, o);
        self.fat[o..o + 4].copy_from_slice(&((old & 0xF000_0000) | (v & 0x0FFF_FFFF)).to_le_bytes());
        self.dirty.insert(o / 512);
    }

    fn chain(&self, first: u32) -> Res<Vec<u32>> {
        let mut v = Vec::new();
        let mut c = first;
        while self.is_data(c) {
            v.push(c);
            if v.len() > self.clusters as usize {
                return Err("cluster chain loop".to_string());
            }
            c = self.fat_get(c);
            if c >= 0x0FFF_FFF8 {
                return Ok(v);
            }
        }
        Err("bad cluster chain".to_string())
    }

    fn alloc(&mut self, n: usize) -> Res<Vec<u32>> {
        let mut out: Vec<u32> = Vec::with_capacity(n);
        let total = self.clusters;
        let mut c = self.hint.max(2);
        let mut scanned = 0u32;
        while out.len() < n && scanned < total {
            if c >= total + 2 {
                c = 2;
            }
            if self.fat_get(c) == 0 {
                out.push(c);
            }
            c += 1;
            scanned += 1;
        }
        if out.len() < n {
            return Err("the ESP is full".to_string());
        }
        for i in 0..n {
            let next = if i + 1 < n { out[i + 1] } else { EOC };
            self.fat_set(out[i], next);
        }
        self.hint = out[n - 1] + 1;
        self.free_delta -= n as i64;
        Ok(out)
    }

    fn free_chain(&mut self, first: u32) -> Res<()> {
        for c in self.chain(first)? {
            self.fat_set(c, 0);
            self.free_delta += 1;
        }
        Ok(())
    }

    fn free_clusters(&self) -> u64 {
        (2..self.clusters + 2).filter(|&c| self.fat_get(c) == 0).count() as u64
    }

    /// Write the changed FAT sectors to every FAT copy, then FSInfo.
    fn flush_fat(&mut self) -> Res<()> {
        let dirty: Vec<usize> = self.dirty.iter().cloned().collect();
        for k in dirty {
            let lo = k * 512;
            let hi = (lo + 512).min(self.fat.len());
            for f in 0..self.nfats {
                self.dev.wr(self.fat_off + f * self.fat_bytes + lo as u64, &self.fat[lo..hi])?;
            }
        }
        self.dirty.clear();
        if let (Some(off), true) = (self.fsinfo_off, self.free_delta != 0) {
            let mut s = [0u8; 512];
            self.dev.rd(off, &mut s)?;
            let free = le32(&s, 488);
            if free != 0xFFFF_FFFF {
                let nf = (free as i64 + self.free_delta).clamp(0, self.clusters as i64) as u32;
                s[488..492].copy_from_slice(&nf.to_le_bytes());
                s[492..496].copy_from_slice(&self.hint.to_le_bytes());
                self.dev.wr(off, &s)?;
            }
            self.free_delta = 0;
        }
        self.dev.flush();
        Ok(())
    }

    // ── directories ──
    fn list(&self, first: u32) -> Res<(Vec<u32>, Vec<Ent>)> {
        let cl = self.chain(first)?;
        let mut data = vec![0u8; cl.len() * self.cb as usize];
        for (i, &c) in cl.iter().enumerate() {
            let o = i * self.cb as usize;
            self.dev.rd(self.c_off(c), &mut data[o..o + self.cb as usize])?;
        }
        let mut out = Vec::new();
        let mut lfn: Vec<u16> = Vec::new();
        let mut lfn_start = usize::MAX;
        for (idx, e) in data.chunks_exact(32).enumerate() {
            if e[0] == 0 {
                break;
            }
            if e[0] == 0xE5 {
                lfn.clear();
                lfn_start = usize::MAX;
                continue;
            }
            let attr = e[11];
            if attr == 0x0F {
                let seq = (e[0] & 0x1F) as usize;
                if e[0] & 0x40 != 0 {
                    lfn.clear();
                    lfn.resize(seq * 13, 0xFFFF);
                    lfn_start = idx;
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
                lfn_start = usize::MAX;
                continue;
            }
            let name = if !lfn.is_empty() {
                let u: Vec<u16> = lfn.iter().cloned().take_while(|&u| u != 0 && u != 0xFFFF).collect();
                String::from_utf16_lossy(&u)
            } else {
                let b: String = e[0..8].iter().map(|&c| c as char).collect::<String>().trim_end().to_string();
                let x: String = e[8..11].iter().map(|&c| c as char).collect::<String>().trim_end().to_string();
                if x.is_empty() { b } else { format!("{}.{}", b, x) }
            };
            out.push(Ent {
                idx,
                lfn_start: if lfn.is_empty() { idx } else { lfn_start },
                name,
                sfn: e[0..11].try_into().unwrap(),
                attr,
                cluster: ((le16(e, 20) as u32) << 16) | le16(e, 26) as u32,
                size: le32(e, 28),
            });
            lfn.clear();
            lfn_start = usize::MAX;
        }
        Ok((cl, out))
    }

    fn find_in(&self, dir: u32, name: &str) -> Res<Option<Ent>> {
        let (_, ents) = self.list(dir)?;
        Ok(ents.into_iter().find(|e| e.name.eq_ignore_ascii_case(name)))
    }

    /// Directory cluster of a path of directory names ("EFI", "ospab").
    fn dir_of(&self, comps: &[&str]) -> Res<Option<u32>> {
        let mut cur = self.root;
        for c in comps {
            match self.find_in(cur, c)? {
                Some(e) if e.attr & 0x10 != 0 && self.is_data(e.cluster) => cur = e.cluster,
                _ => return Ok(None),
            }
        }
        Ok(Some(cur))
    }

    fn file_at(&self, comps: &[&str]) -> Res<Option<(u32, Ent)>> {
        let Some((last, dirs)) = comps.split_last() else { return Ok(None) };
        let Some(d) = self.dir_of(dirs)? else { return Ok(None) };
        Ok(self.find_in(d, last)?.filter(|e| e.attr & 0x10 == 0).map(|e| (d, e)))
    }

    fn read_file(&self, e: &Ent) -> Res<Vec<u8>> {
        let mut out = vec![0u8; e.size as usize];
        if e.size == 0 {
            return Ok(out);
        }
        let cl = self.chain(e.cluster)?;
        if (cl.len() as u64) * self.cb < e.size as u64 {
            return Err("file shorter than its size".to_string());
        }
        let mut done = 0usize;
        let mut i = 0;
        while done < out.len() {
            let mut j = i;
            while j + 1 < cl.len() && cl[j + 1] == cl[j] + 1 && (j + 1 - i) < 8 {
                j += 1;
            }
            let bytes = (((j - i + 1) as u64 * self.cb) as usize).min(out.len() - done);
            self.dev.rd(self.c_off(cl[i]), &mut out[done..done + bytes])?;
            done += bytes;
            i = j + 1;
        }
        Ok(out)
    }

    fn entry_loc(&self, cl: &[u32], idx: usize) -> (u64, usize) {
        let off = idx as u64 * 32;
        (self.c_off(cl[(off / self.cb) as usize]) + off % self.cb, idx)
    }

    fn write_entry(&self, dir: u32, idx: usize, bytes: &[u8; 32]) -> Res<()> {
        let cl = self.chain(dir)?;
        if (idx as u64 * 32) / self.cb >= cl.len() as u64 {
            return Err("directory index out of range".to_string());
        }
        let (off, _) = self.entry_loc(&cl, idx);
        self.dev.wr(off, bytes)
    }

    fn read_entry(&self, dir: u32, idx: usize) -> Res<[u8; 32]> {
        let cl = self.chain(dir)?;
        let (off, _) = self.entry_loc(&cl, idx);
        let mut b = [0u8; 32];
        self.dev.rd(off, &mut b)?;
        Ok(b)
    }

    /// Point an existing entry at other data (one 32-byte write inside one sector).
    fn repoint(&self, dir: u32, idx: usize, cluster: u32, size: u32) -> Res<()> {
        let mut e = self.read_entry(dir, idx)?;
        e[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
        e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
        e[28..32].copy_from_slice(&size.to_le_bytes());
        e[24..26].copy_from_slice(&FAT_DATE.to_le_bytes());
        self.write_entry(dir, idx, &e)
    }

    fn create_entry(&mut self, dir: u32, name: &str, cluster: u32, size: u32) -> Res<usize> {
        let sfn = sfn_of(name).ok_or("bad 8.3 name")?;
        let (cl, ents) = self.list(dir)?;
        if ents.iter().any(|e| e.sfn == sfn) {
            return Err(format!("{} already exists", name));
        }
        // First free slot; the list stops at the end marker, so scan raw.
        let mut raw = vec![0u8; cl.len() * self.cb as usize];
        for (i, &c) in cl.iter().enumerate() {
            let o = i * self.cb as usize;
            self.dev.rd(self.c_off(c), &mut raw[o..o + self.cb as usize])?;
        }
        let slot = raw.chunks_exact(32).position(|e| e[0] == 0 || e[0] == 0xE5);
        let idx = match slot {
            Some(i) => i,
            None => {
                let nc = self.alloc(1)?[0];
                self.dev.wr(self.c_off(nc), &vec![0u8; self.cb as usize])?;
                self.fat_set(*cl.last().unwrap(), nc);
                self.flush_fat()?;
                raw.len() / 32
            }
        };
        let mut e = [0u8; 32];
        e[0..11].copy_from_slice(&sfn);
        e[11] = 0x20;
        e[16..18].copy_from_slice(&FAT_DATE.to_le_bytes());
        e[18..20].copy_from_slice(&FAT_DATE.to_le_bytes());
        e[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
        e[24..26].copy_from_slice(&FAT_DATE.to_le_bytes());
        e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
        e[28..32].copy_from_slice(&size.to_le_bytes());
        self.write_entry(dir, idx, &e)?;
        Ok(idx)
    }

    /// Mark an entry (and its long-name entries) deleted. The clusters are not freed here.
    fn delete_entry(&self, dir: u32, ent: &Ent) -> Res<()> {
        for i in ent.lfn_start..=ent.idx {
            let mut e = self.read_entry(dir, i)?;
            e[0] = 0xE5;
            self.write_entry(dir, i, &e)?;
        }
        Ok(())
    }

    fn refs(&self, dir: u32, cluster: u32) -> Res<usize> {
        Ok(self.list(dir)?.1.iter().filter(|e| e.cluster == cluster && e.name != "." && e.name != "..").count())
    }

    /// Free `cluster`'s chain unless another entry of the directory still uses it.
    fn free_unless_shared(&mut self, dir: u32, cluster: u32) -> Res<()> {
        if self.is_data(cluster) && self.refs(dir, cluster)? == 0 {
            self.free_chain(cluster)?;
        }
        Ok(())
    }

    /// Write `data` into fresh clusters and create the entry `name`. Verified by reading back.
    fn stage(&mut self, dir: u32, name: &str, data: &[u8]) -> Res<Ent> {
        if let Some(left) = self.find_in(dir, name)? {
            // Left over from an interrupted update.
            self.delete_entry(dir, &left)?;
            self.free_unless_shared(dir, left.cluster)?;
            self.flush_fat()?;
        }
        let mut first = 0u32;
        if !data.is_empty() {
            let n = ((data.len() as u64 + self.cb - 1) / self.cb) as usize;
            let cl = self.alloc(n)?;
            first = cl[0];
            let mut i = 0;
            while i < n {
                let mut j = i;
                while j + 1 < n && cl[j + 1] == cl[j] + 1 {
                    j += 1;
                }
                let lo = i * self.cb as usize;
                let hi = ((j + 1) * self.cb as usize).min(data.len());
                self.dev.wr(self.c_off(cl[i]), &data[lo..hi])?;
                i = j + 1;
            }
            self.flush_fat()?;
        }
        let idx = self.create_entry(dir, name, first, data.len() as u32)?;
        let ent = self.find_in(dir, name)?.ok_or("new entry vanished")?;
        if ent.idx != idx || self.read_file(&ent)? != data {
            return Err(format!("{}: readback differs", name));
        }
        Ok(ent)
    }

    /// Switch `target` to the staged data. With `keep_as`, the previous data becomes that file.
    fn commit(&mut self, dir: u32, staged: Ent, target: &str, keep_as: Option<&str>) -> Res<()> {
        match self.find_in(dir, target)? {
            None => {
                // First installation of this file: rename the staged entry.
                let sfn = sfn_of(target).ok_or("bad 8.3 name")?;
                let mut e = self.read_entry(dir, staged.idx)?;
                e[0..11].copy_from_slice(&sfn);
                self.write_entry(dir, staged.idx, &e)?;
            }
            Some(t) => {
                let mut free_head = 0u32; // data that nothing will reference after the switch
                if let Some(old) = keep_as {
                    match self.find_in(dir, old)? {
                        Some(o) => {
                            free_head = o.cluster;
                            self.repoint(dir, o.idx, t.cluster, t.size)?;
                        }
                        None => {
                            self.create_entry(dir, old, t.cluster, t.size)?;
                        }
                    }
                } else {
                    free_head = t.cluster;
                }
                self.repoint(dir, t.idx, staged.cluster, staged.size)?; // the switch
                self.delete_entry(dir, &staged)?;
                if self.is_data(free_head) {
                    self.free_unless_shared(dir, free_head)?;
                }
            }
        }
        self.flush_fat()
    }

    /// Overwrite an existing file of exactly the same size inside its first cluster.
    fn overwrite_same_size(&self, e: &Ent, data: &[u8]) -> Res<()> {
        if e.size as usize != data.len() || data.len() as u64 > self.cb || !self.is_data(e.cluster) {
            return Err("in-place write needs a file of the same size".to_string());
        }
        self.dev.wr(self.c_off(e.cluster), data)?;
        self.dev.flush();
        let mut back = vec![0u8; data.len()];
        self.dev.rd(self.c_off(e.cluster), &mut back)?;
        if back != data { Err("readback differs".to_string()) } else { Ok(()) }
    }
}

// ─── Finding our ESP ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
pub enum Layout {
    /// Whole-disk install: `\boot\KERNEL`, `\boot\ospab.cfg`, `\EFI\BOOT\BOOTX64.EFI`.
    Erase,
    /// Alongside other systems: everything in `\EFI\ospab\`.
    Alongside,
}

struct Found {
    fat: Fat,
    disk: usize,
    part_no: usize,
    layout: Layout,
}

impl Layout {
    fn dir(self) -> &'static [&'static str] {
        match self {
            Layout::Erase => &["boot"],
            Layout::Alongside => &["EFI", "ospab"],
        }
    }
    fn dir_text(self) -> &'static str {
        match self {
            Layout::Erase => "/boot",
            Layout::Alongside => "/EFI/ospab",
        }
    }
}

fn is_elf(d: &[u8]) -> bool {
    d.len() > 64 && &d[0..4] == b"\x7fELF" && d[4] == 2 && le16(d, 18) == 0x3E
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn detect_layout(fat: &Fat) -> Res<Option<Layout>> {
    for l in [Layout::Erase, Layout::Alongside] {
        let d = l.dir();
        let mut k = d.to_vec();
        k.push("KERNEL");
        let mut c = d.to_vec();
        c.push("ospab.cfg");
        if let (Some((_, ke)), Some(_)) = (fat.file_at(&k)?, fat.file_at(&c)?) {
            if ke.size >= 64 && fat.is_data(ke.cluster) {
                let mut head = [0u8; 64];
                fat.dev.rd(fat.c_off(ke.cluster), &mut head)?;
                if &head[0..4] == b"\x7fELF" {
                    return Ok(Some(l));
                }
            }
        }
    }
    Ok(None)
}

fn find_esp() -> Res<Found> {
    let mode = crate::arch::x86_64::boot::cmdline_get("mode");
    if mode == "live" || mode == "installer" {
        return Err("this is the live system (mode=".to_string() + mode + "); system updates only work on an installed system");
    }
    let mut root_disks: Vec<usize> = Vec::new();
    let mut cands: Vec<Found> = Vec::new();
    for d in 0..crate::drivers::disk_count() {
        let Some(parts) = read_gpt(d) else { continue };
        if parts.iter().any(|p| p.typ == LINUX_GUID && p.name == "AETERNA") {
            root_disks.push(d);
        }
        for (i, p) in parts.iter().enumerate() {
            if p.typ != ESP_GUID {
                continue;
            }
            let dev = Dev { disk: d, base: p.start, sectors: p.sectors };
            let Ok(fat) = Fat::mount(dev) else { continue };
            if let Ok(Some(layout)) = detect_layout(&fat) {
                cands.push(Found { fat, disk: d, part_no: i + 1, layout });
            }
        }
    }
    if cands.is_empty() {
        return Err("no ospab installation found on an EFI System Partition (is this system installed?)".to_string());
    }
    if cands.len() > 1 {
        cands.retain(|c| root_disks.contains(&c.disk));
    }
    if cands.len() != 1 {
        return Err("cannot tell which EFI System Partition this system booted from (several ospab installs); refusing".to_string());
    }
    Ok(cands.pop().unwrap())
}

fn state_comps(l: Layout) -> Vec<&'static str> {
    let mut v = l.dir().to_vec();
    v.push(update::STATE_NAME);
    v
}

/// The update state stored on the ESP (None: no state file, or no ESP).
pub fn read_state() -> Option<update::State> {
    let f = find_esp().ok()?;
    let (_, e) = f.fat.file_at(&state_comps(f.layout)).ok()??;
    update::parse(&f.fat.read_file(&e).ok()?)
}

/// Called by the kernel when the console is ready. If this boot was a trial of an updated kernel
/// (`update_try=1` on the command line), clears the pending flag. Returns a message to log.
pub fn mark_boot_ok() -> Option<String> {
    if crate::arch::x86_64::boot::cmdline_get("update_try") != "1" {
        return None;
    }
    let f = match find_esp() {
        Ok(f) => f,
        Err(e) => return Some(format!("update: boot not confirmed: {}", e)),
    };
    let r = (|| -> Res<Option<String>> {
        let Some((_, e)) = f.fat.file_at(&state_comps(f.layout))? else { return Ok(None) };
        let Some(mut st) = update::parse(&f.fat.read_file(&e)?) else { return Ok(None) };
        if !st.pending {
            return Ok(None);
        }
        st.pending = false;
        st.failed = false;
        st.tries = 0;
        let b = update::encode(&st).ok_or("state does not fit")?;
        f.fat.overwrite_same_size(&e, &b)?;
        Ok(Some(format!("update {} confirmed, the previous kernel stays as {}", st.version, st.old)))
    })();
    match r {
        Ok(m) => m,
        Err(e) => Some(format!("update: cannot confirm the boot: {}", e)),
    }
}

// ─── Installing a system package ─────────────────────────────────────────────

pub struct SystemImage<'a> {
    pub version: &'a str,
    pub kernel: &'a [u8],
    pub loader: Option<&'a [u8]>,
    /// bios.img: stage 1 at 0, stage 2 at 0x800.
    pub bios: Option<&'a [u8]>,
}

struct BiosPlan {
    disk: usize,
    sectors: u64,
}

pub struct Plan<'a> {
    img: SystemImage<'a>,
    f: Found,
    rotate: bool,
    prev_version: String,
    loaders: Vec<Vec<&'static str>>,
    bios: Option<BiosPlan>,
    pub lines: Vec<String>,
    pub up_to_date: bool,
}

fn fmt_kib(n: usize) -> String {
    format!("{} KiB", (n + 1023) / 1024)
}

/// Check everything and describe what `apply` will do. Writes nothing.
pub fn prepare<'a>(img: SystemImage<'a>) -> Res<Plan<'a>> {
    if !is_elf(img.kernel) {
        return Err("the package kernel is not an x86-64 ELF file".to_string());
    }
    if let Some(l) = img.loader {
        if l.len() < 1024 || &l[0..2] != b"MZ" || !contains(l, b"ospab-boot") {
            return Err("the package loader is not an ospab-boot EFI application".to_string());
        }
    }
    if let Some(b) = img.bios {
        if b.len() <= 0x800 + 512 || b[510] != 0x55 || b[511] != 0xAA {
            return Err("the package BIOS image is malformed".to_string());
        }
    }
    let f = find_esp()?;
    let dir = f.fat.dir_of(f.layout.dir())?.ok_or("our directory vanished")?;
    let mut lines = Vec::new();
    lines.push(format!(
        "EFI System Partition: disk {} partition {} ({}), files in {}",
        f.disk, f.part_no, if f.layout == Layout::Erase { "whole-disk install" } else { "alongside install" }, f.layout.dir_text()
    ));

    // Previous kernel: rotate only when the current one is confirmed good.
    let st = read_state_from(&f);
    let rotate = !matches!(&st, Some(s) if s.pending || s.failed);
    let prev_version = match (&st, rotate) {
        (Some(s), false) => s.previous.clone(),
        _ => running_version(),
    };
    let kent = f.fat.find_in(dir, "KERNEL")?.ok_or("KERNEL vanished")?;
    let cur_kernel = f.fat.read_file(&kent)?;
    let kernel_same = cur_kernel == img.kernel;

    // Loader files that are ours.
    let mut loaders: Vec<Vec<&'static str>> = Vec::new();
    let mut loader_same = true;
    if let Some(l) = img.loader {
        let cands: Vec<Vec<&'static str>> = match f.layout {
            Layout::Erase => vec![vec!["EFI", "BOOT", "BOOTX64.EFI"], vec!["EFI", "OSPAB", "OSPABLDR.EFI"]],
            Layout::Alongside => vec![vec!["EFI", "ospab", "OSPABLDR.EFI"]],
        };
        for c in cands {
            if let Some((_, e)) = f.fat.file_at(&c)? {
                let cur = f.fat.read_file(&e)?;
                if &cur[..2.min(cur.len())] != b"MZ" || !contains(&cur, b"ospab-boot") {
                    lines.push(format!("skip /{}: not an ospab loader, left alone", c.join("/")));
                    continue;
                }
                if cur != l {
                    loader_same = false;
                }
                loaders.push(c);
            }
        }
    }

    // Space.
    let cb = f.fat.cb as usize;
    let need = |n: usize| (n + cb - 1) / cb;
    let mut clusters = need(img.kernel.len()) + 1;
    if let Some(l) = img.loader {
        clusters += loaders.len() * need(l.len());
    }
    clusters += need(8192) + 4;
    if f.fat.free_clusters() < clusters as u64 + 8 {
        return Err("not enough free space on the ESP".to_string());
    }

    // BIOS loader: only on a whole-disk install whose MBR and BIOS boot partition look like ours.
    let mut bios = None;
    if let (Some(b), Layout::Erase) = (img.bios, f.layout) {
        let mut mbr = [0u8; 512];
        let ok = crate::drivers::read(f.disk, 0, 1, &mut mbr) && mbr[510] == 0x55 && mbr[511] == 0xAA
            && mbr[450] == 0xEE && le64(&mbr, 0x40) == BIOS_PART_START;
        let part_ok = read_gpt(f.disk).map_or(false, |ps| {
            let n = ((b.len() - 0x800 + 511) / 512) as u64;
            ps.iter().any(|p| p.typ == BIOS_BOOT_GUID && p.start == BIOS_PART_START && p.sectors >= n)
        });
        if ok && part_ok {
            bios = Some(BiosPlan { disk: f.disk, sectors: ((b.len() - 0x800 + 511) / 512) as u64 });
        } else {
            lines.push("BIOS loader: not updated (no ospab BIOS boot code and BIOS boot partition on this disk)".to_string());
        }
    }

    let up_to_date = kernel_same && (img.loader.is_none() || loader_same) && st.as_ref().map_or(true, |s| !s.pending && !s.failed);
    let kp = format!("{}/KERNEL", f.layout.dir_text());
    lines.push(format!("write {}.NEW ({}), verify, then switch: {} -> {}.OLD, new kernel -> {}",
        kp, fmt_kib(img.kernel.len()), kp, kp, kp));
    if !rotate {
        lines.push("the running update is not confirmed yet: KERNEL.OLD (last known good) is kept as it is".to_string());
    }
    if let Some(l) = img.loader {
        for c in &loaders {
            lines.push(format!("replace /{} with the new loader ({}), the old one is kept as .OLD", c.join("/"), fmt_kib(l.len())));
        }
    }
    lines.push(format!("{}/ospab.cfg: make sure the entry \"ospab.os (previous)\" boots KERNEL.OLD", f.layout.dir_text()));
    lines.push(format!("{}/{}: boot counter, {} tries; the kernel confirms when its console is ready",
        f.layout.dir_text(), update::STATE_NAME, update::MAX_TRIES));
    if let Some(b) = &bios {
        lines.push(format!("BIOS loader: stage 2 -> LBA {}..{} of disk {}, stage 1 boot code in the MBR (partition table kept)",
            BIOS_PART_START, BIOS_PART_START + b.sectors - 1, b.disk));
    }
    lines.push("nothing else on the ESP or the disk is changed".to_string());
    Ok(Plan { img, f, rotate, prev_version, loaders, bios, lines, up_to_date })
}

fn read_state_from(f: &Found) -> Option<update::State> {
    let (_, e) = f.fat.file_at(&state_comps(f.layout)).ok()??;
    update::parse(&f.fat.read_file(&e).ok()?)
}

/// The ospab.cfg text with an `ospab.os (previous)` entry that boots `old` (added before the
/// memory test entry, or at the end). `None` when it already has one.
fn cfg_with_previous(text: &str, old: &str) -> Res<Option<String>> {
    let parsed = crate::config::parse(text);
    if parsed.cfg.entries.iter().any(|e| e.kernel.eq_ignore_ascii_case(old)) {
        return Ok(None);
    }
    let mut id = "previous".to_string();
    let mut n = 2;
    while parsed.cfg.entries.iter().any(|e| e.id == id) {
        id = format!("previous{}", n);
        n += 1;
    }
    let block = format!("[entry {}]\ntitle = ospab.os (previous)\ntype = ospab\nkernel = {}\n\n", id, old);
    let before = parsed.cfg.entries.iter().find(|e| e.typ == crate::config::EntryType::Memtest).map(|e| e.line);
    let mut out = String::new();
    let mut inserted = false;
    for (i, l) in text.lines().enumerate() {
        if Some(i + 1) == before {
            out.push_str(&block);
            inserted = true;
        }
        out.push_str(l);
        out.push('\n');
    }
    if !inserted {
        if !out.ends_with("\n\n") {
            out.push('\n');
        }
        out.push_str(&block);
    }
    // The result must still parse without new errors and contain the entry.
    let check = crate::config::parse(&out);
    if check.errors.len() > parsed.errors.len() || !check.cfg.entries.iter().any(|e| e.kernel.eq_ignore_ascii_case(old)) {
        return Err("could not add the previous-kernel entry to ospab.cfg safely".to_string());
    }
    Ok(Some(out))
}

impl<'a> Plan<'a> {
    /// Write everything. Returns progress lines.
    pub fn apply(mut self) -> Res<Vec<String>> {
        let mut log = Vec::new();
        let layout = self.f.layout;
        let dir = self.f.fat.dir_of(layout.dir())?.ok_or("our directory vanished")?;
        let kernel_path = format!("{}/KERNEL", layout.dir_text());
        let old_path = format!("{}/KERNEL.OLD", layout.dir_text());

        // 1. Stage every new file (nothing visible changes yet).
        let kstaged = self.f.fat.stage(dir, "KERNEL.NEW", self.img.kernel)?;
        log.push(format!("{}.NEW written and verified ({} bytes)", kernel_path, self.img.kernel.len()));

        let mut lstaged = Vec::new();
        if let Some(l) = self.img.loader {
            for c in self.loaders.clone() {
                let ld = self.f.fat.dir_of(&c[..c.len() - 1])?.ok_or("loader directory vanished")?;
                let newname = format!("{}.NEW", c[c.len() - 1].rsplit_once('.').map(|x| x.0).unwrap_or("LDR"));
                let s = self.f.fat.stage(ld, &newname, l)?;
                log.push(format!("/{} staged as {} and verified", c.join("/"), newname));
                lstaged.push((ld, s, c));
            }
        }

        let cfg_comps: Vec<&str> = { let mut v = layout.dir().to_vec(); v.push("ospab.cfg"); v };
        let (cfg_dir, cfg_ent) = self.f.fat.file_at(&cfg_comps)?.ok_or("ospab.cfg vanished")?;
        let cfg_text = String::from_utf8_lossy(&self.f.fat.read_file(&cfg_ent)?).into_owned();
        let new_cfg = cfg_with_previous(&cfg_text, &old_path)?;
        let cfg_staged = match &new_cfg {
            Some(t) => Some(self.f.fat.stage(cfg_dir, "OSPAB.NEW", t.as_bytes())?),
            None => None,
        };

        // 2. Switch: loaders, kernel, configuration. Each switch is one directory-entry write.
        for (ld, s, c) in lstaged {
            let name = c[c.len() - 1];
            let oldn = format!("{}.OLD", name.rsplit_once('.').map(|x| x.0).unwrap_or("LDR"));
            self.f.fat.commit(ld, s, name, Some(&oldn))?;
            log.push(format!("/{} replaced", c.join("/")));
        }
        self.f.fat.commit(dir, kstaged, "KERNEL", if self.rotate { Some("KERNEL.OLD") } else { None })?;
        if self.rotate {
            log.push(format!("{} -> {}; new kernel is {}", kernel_path, old_path, kernel_path));
        } else {
            log.push(format!("new kernel is {} ({} kept)", kernel_path, old_path));
        }
        if let Some(s) = cfg_staged {
            self.f.fat.commit(cfg_dir, s, "ospab.cfg", None)?;
            log.push(format!("{}/ospab.cfg: entry \"ospab.os (previous)\" added", layout.dir_text()));
        }

        // 3. Boot counter, last.
        let st = update::State {
            pending: true,
            tries: update::MAX_TRIES,
            failed: false,
            kernel: kernel_path.clone(),
            old: old_path.clone(),
            version: self.img.version.to_string(),
            previous: self.prev_version.clone(),
        };
        let bytes = update::encode(&st).ok_or("state does not fit")?;
        match self.f.fat.find_in(dir, update::STATE_NAME)? {
            Some(e) if e.size as usize == bytes.len() => self.f.fat.overwrite_same_size(&e, &bytes)?,
            other => {
                if let Some(e) = other {
                    self.f.fat.delete_entry(dir, &e)?;
                    self.f.fat.free_unless_shared(dir, e.cluster)?;
                }
                self.f.fat.stage(dir, "UPDATE.NEW", &bytes)?;
                let s = self.f.fat.find_in(dir, "UPDATE.NEW")?.ok_or("state file vanished")?;
                self.f.fat.commit(dir, s, update::STATE_NAME, None)?;
            }
        }
        self.f.fat.flush_fat()?;
        log.push(format!("{}/{} written: {} tries", layout.dir_text(), update::STATE_NAME, update::MAX_TRIES));

        // 4. Read everything back through a fresh mount.
        let dev = Dev { disk: self.f.disk, base: self.f.fat.dev.base, sectors: self.f.fat.dev.sectors };
        let again = Fat::mount(dev)?;
        let d2 = again.dir_of(layout.dir())?.ok_or("directory missing after the update")?;
        let k = again.find_in(d2, "KERNEL")?.ok_or("KERNEL missing after the update")?;
        if again.read_file(&k)? != self.img.kernel {
            return Err("KERNEL differs after the update".to_string());
        }
        log.push("final check: KERNEL matches the package".to_string());

        // 5. BIOS loader (failure here does not undo the UEFI side).
        if let (Some(bp), Some(img)) = (&self.bios, self.img.bios) {
            match write_bios(bp, img) {
                Ok(()) => log.push(format!("BIOS loader written: {} sectors at LBA {}", bp.sectors, BIOS_PART_START)),
                Err(e) => log.push(format!("WARNING: BIOS loader not updated: {}", e)),
            }
        }
        Ok(log)
    }
}

/// Stage 2 into the BIOS boot partition (LBA 34..), then stage 1 into the MBR boot code
/// (bytes 0..446; the partition table is kept). Both read back.
fn write_bios(bp: &BiosPlan, img: &[u8]) -> Res<()> {
    let stage2 = &img[0x800..];
    for i in 0..bp.sectors {
        let mut sec = [0u8; 512];
        let from = i as usize * 512;
        let n = (stage2.len() - from).min(512);
        sec[..n].copy_from_slice(&stage2[from..from + n]);
        if !crate::drivers::write(bp.disk, BIOS_PART_START + i, 1, &sec) {
            return Err(format!("write error at LBA {}", BIOS_PART_START + i));
        }
    }
    crate::drivers::flush(bp.disk);
    for i in 0..bp.sectors {
        let mut sec = [0u8; 512];
        let from = i as usize * 512;
        let n = (stage2.len() - from).min(512);
        if !crate::drivers::read(bp.disk, BIOS_PART_START + i, 1, &mut sec) || sec[..n] != stage2[from..from + n] {
            return Err("stage 2 readback differs".to_string());
        }
    }
    let mut mbr = [0u8; 512];
    if !crate::drivers::read(bp.disk, 0, 1, &mut mbr) {
        return Err("cannot read the MBR".to_string());
    }
    mbr[..446].copy_from_slice(&img[..446]);
    mbr[0x40..0x48].copy_from_slice(&BIOS_PART_START.to_le_bytes());
    if !crate::drivers::write(bp.disk, 0, 1, &mbr) {
        return Err("cannot write the MBR".to_string());
    }
    crate::drivers::flush(bp.disk);
    let mut back = [0u8; 512];
    if !crate::drivers::read(bp.disk, 0, 1, &mut back) || back != mbr {
        return Err("MBR readback differs".to_string());
    }
    Ok(())
}
