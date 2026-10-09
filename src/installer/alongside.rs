/*
 * Installer — "Install alongside other systems" mode.
 *
 * Adds ospab.os to a disk that already holds Windows / Linux (GPT + UEFI)
 * without touching them:
 *
 *   - parses the existing GPT (both copies, CRC-checked) and lists the partitions;
 *   - creates ONE new GPT entry, "AETERNA", in the largest free gap
 *     (primary entry sector + primary header + backup entry sector + backup header);
 *   - reuses the existing EFI System Partition (FAT32): adds \EFI\ospab\ with
 *     OSPABLDR.EFI, ospab.cfg and KERNEL; every other ESP file stays as it is;
 *   - never writes UEFI NVRAM (the final screen explains how to boot it).
 *
 * Safety:
 *   - the whole change is computed in memory first (`Plan`) and shown as a dry-run
 *     summary; nothing is written before the user types "install";
 *   - every disk write goes through `Writer`, which refuses any LBA outside the
 *     new partition, the ESP and the four GPT sectors that change;
 *   - everything is read back and re-parsed afterwards (GPT CRCs, unchanged
 *     partition entries, FAT chains and file contents).
 */

use super::*;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

const ALIGN: u64 = 2048; // 1 MiB
/// The persistence area (vfs/disk_sync.rs) needs 8 MiB + the identity sectors.
const MIN_NEW_SECTORS: u64 = 64 * 2048; // 64 MiB
const FAT_EOC: u32 = 0x0FFF_FFFF;
const NEW_FAT_DATE: u16 = 0x5C21; // 2026-01-01
const BATCH: usize = 32; // sectors per disk write

const NAME_DIR: &[u8; 11] = b"OSPAB      ";
const NAME_LDR: &[u8; 11] = b"OSPABLDREFI";
const NAME_CFG: &[u8; 11] = b"OSPAB   CFG";
const NAME_KRN: &[u8; 11] = b"KERNEL     ";
const NAME_EFI: &[u8; 11] = b"EFI        ";

// ── GUIDs ────────────────────────────────────────────────────────────────────
fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[0..4].copy_from_slice(&d1.to_le_bytes());
    g[4..6].copy_from_slice(&d2.to_le_bytes());
    g[6..8].copy_from_slice(&d3.to_le_bytes());
    g[8..16].copy_from_slice(&d4);
    g
}

fn type_name(g: &[u8; 16]) -> &'static str {
    let apple = [0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC];
    let table: [([u8; 16], &'static str); 14] = [
        (ESP_GUID, "EFI System"),
        (guid(0xEBD0A0A2, 0xB9E5, 0x4433, [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7]), "Microsoft basic data"),
        (guid(0xE3C9E316, 0x0B5C, 0x4DB8, [0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE]), "Microsoft reserved"),
        (guid(0xDE94BBA4, 0x06D1, 0x4D40, [0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC]), "Windows recovery"),
        (LINUX_GUID, "Linux filesystem"),
        (guid(0x0657FD6D, 0xA4AB, 0x43C4, [0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F]), "Linux swap"),
        (guid(0xE6D6D379, 0xF507, 0x44C2, [0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28]), "Linux LVM"),
        (guid(0x933AC7E1, 0x2EB4, 0x4F13, [0xB8, 0x44, 0x0E, 0x14, 0xE2, 0xAE, 0xF9, 0x15]), "Linux /home"),
        (guid(0x4F68BCE3, 0xE8CD, 0x4DB1, [0x96, 0xE7, 0xFB, 0xCA, 0xF9, 0x84, 0xB7, 0x09]), "Linux root (x86-64)"),
        (guid(0x21686148, 0x6449, 0x6E6F, [0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49]), "BIOS boot"),
        (guid(0x48465300, 0x0000, 0x11AA, apple), "Apple HFS+"),
        (guid(0x7C3457EF, 0x0000, 0x11AA, apple), "Apple APFS"),
        (guid(0x5808C8AA, 0x7E8F, 0x42E0, [0x85, 0xD2, 0xE1, 0xE9, 0x04, 0x34, 0xCF, 0xB3]), "Windows LDM metadata"),
        (guid(0xAF9B60A0, 0x1431, 0x4F62, [0xBC, 0x68, 0x33, 0x11, 0x71, 0x4A, 0x69, 0xAD]), "Windows LDM data"),
    ];
    for (g2, n) in table.iter() {
        if g2 == g { return n; }
    }
    "Unknown type"
}

// ── Sector overlay: in-memory view of the changes to existing metadata ───────
struct Ov {
    disk: usize,
    map: BTreeMap<u64, ([u8; 512], &'static str)>,
}

impl Ov {
    fn new(disk: usize) -> Ov { Ov { disk, map: BTreeMap::new() } }

    /// Current content of a sector (overlay first, then the disk).
    fn read(&self, lba: u64) -> Result<[u8; 512], String> {
        if let Some((s, _)) = self.map.get(&lba) { return Ok(*s); }
        let mut b = [0u8; 512];
        if disk_read(self.disk, lba, 1, &mut b) { Ok(b) } else { Err(format!("cannot read LBA {}", lba)) }
    }

    /// Mutable copy of an existing sector (loaded from the disk on first use).
    fn edit(&mut self, lba: u64, label: &'static str) -> Result<&mut [u8; 512], String> {
        if !self.map.contains_key(&lba) {
            let mut b = [0u8; 512];
            if !disk_read(self.disk, lba, 1, &mut b) { return Err(format!("cannot read LBA {}", lba)); }
            self.map.insert(lba, (b, label));
        }
        Ok(&mut self.map.get_mut(&lba).unwrap().0)
    }

    /// A sector that is fully replaced (zero-filled), not read from the disk.
    fn fresh(&mut self, lba: u64, label: &'static str) -> &mut [u8; 512] {
        self.map.insert(lba, ([0u8; 512], label));
        &mut self.map.get_mut(&lba).unwrap().0
    }
}

// ── GPT ──────────────────────────────────────────────────────────────────────
#[derive(Clone)]
struct Part {
    slot: usize,
    type_guid: [u8; 16],
    start: u64,
    end: u64,
    name: String,
}
impl Part {
    fn sectors(&self) -> u64 { self.end - self.start + 1 }
    fn is_esp(&self) -> bool { self.type_guid == ESP_GUID }
}

struct Gpt {
    first_usable: u64,
    last_usable: u64,
    n_ent: usize,
    ent_sz: usize,
    ent_lba: u64,
    bak_ent_lba: u64,
    bak_hdr_lba: u64,
    hdr: [u8; 512],
    bak_hdr: [u8; 512],
    entries: Vec<u8>,
    parts: Vec<Part>,
}

fn rd32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) }
fn rd64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

fn read_sectors(disk: usize, lba: u64, n: u64) -> Option<Vec<u8>> {
    let mut v = alloc::vec![0u8; n as usize * 512];
    let mut done = 0u64;
    while done < n {
        let c = (n - done).min(64);
        let o = done as usize * 512;
        if !disk_read(disk, lba + done, c as u32, &mut v[o..o + c as usize * 512]) { return None; }
        done += c;
    }
    Some(v)
}

/// Check a GPT header sector: signature, size, CRC. Returns the header size.
fn check_header(h: &[u8; 512]) -> Result<usize, String> {
    if &h[0..8] != b"EFI PART" { return Err(String::from("no GPT signature")); }
    let hs = rd32(h, 12) as usize;
    if hs < 92 || hs > 512 { return Err(String::from("bad GPT header size")); }
    let mut c = *h;
    c[16..20].fill(0);
    if crc32(&c[..hs]) != rd32(h, 16) { return Err(String::from("GPT header CRC32 mismatch")); }
    Ok(hs)
}

fn parse_gpt(d: &VDisk) -> Result<Gpt, String> {
    let mut mbr = [0u8; 512];
    let mut hdr = [0u8; 512];
    if !disk_read(d.index, 0, 1, &mut mbr) || !disk_read(d.index, 1, 1, &mut hdr) {
        return Err(String::from("Cannot read the start of the disk."));
    }
    if &hdr[0..8] != b"EFI PART" {
        let mbr_parts = mbr[510] == 0x55 && mbr[511] == 0xAA && (0..4).any(|i| mbr[446 + i * 16 + 4] != 0);
        return Err(if mbr_parts {
            String::from("This disk uses a legacy MBR partition table (no GPT).\nInstalling alongside needs a GPT disk booted in UEFI mode; use\n\"Erase\" mode on an empty disk instead. The disk was not touched.")
        } else {
            String::from("This disk has no partition table, so there is nothing to install\nalongside. Use \"Erase entire disk\" mode instead.")
        });
    }
    let hs = check_header(&hdr).map_err(|e| format!("Primary GPT is damaged: {}.\nRepair it from Windows/Linux first (e.g. gdisk). Nothing was written.", e))?;
    let _ = hs;
    let last = d.sectors - 1;
    if rd64(&hdr, 24) != 1 { return Err(String::from("Primary GPT header has an unexpected location.")); }
    if rd64(&hdr, 32) != last {
        return Err(String::from("The backup GPT is not at the end of the disk (disk was resized?).\nFix it first (Linux: sgdisk -e, or Windows Disk Management)."));
    }
    let first_usable = rd64(&hdr, 40);
    let last_usable = rd64(&hdr, 48);
    let ent_lba = rd64(&hdr, 72);
    let n_ent = rd32(&hdr, 80) as usize;
    let ent_sz = rd32(&hdr, 84) as usize;
    if ent_sz != 128 && ent_sz != 256 && ent_sz != 512 { return Err(format!("Unsupported GPT entry size {}.", ent_sz)); }
    if n_ent == 0 || n_ent > 1024 { return Err(format!("Unsupported GPT entry count {}.", n_ent)); }
    if first_usable > last_usable || last_usable >= d.sectors { return Err(String::from("GPT usable range is invalid.")); }
    let ent_secs = ((n_ent * ent_sz + 511) / 512) as u64;
    if ent_lba < 2 || ent_lba + ent_secs > first_usable { return Err(String::from("GPT entry array location is unusual; refusing.")); }
    let entries = read_sectors(d.index, ent_lba, ent_secs).ok_or_else(|| String::from("Cannot read the GPT entries."))?;
    if crc32(&entries[..n_ent * ent_sz]) != rd32(&hdr, 88) {
        return Err(String::from("Primary GPT entries CRC32 mismatch (damaged table). Nothing was written."));
    }

    // Backup copy: must be intact and identical in content.
    let mut bak = [0u8; 512];
    if !disk_read(d.index, last, 1, &mut bak) { return Err(String::from("Cannot read the backup GPT header.")); }
    check_header(&bak).map_err(|e| format!("Backup GPT is damaged: {}.\nRepair it first (gdisk / sgdisk). Nothing was written.", e))?;
    if rd64(&bak, 24) != last || rd64(&bak, 32) != 1 { return Err(String::from("Backup GPT header has an unexpected location.")); }
    let bak_ent_lba = rd64(&bak, 72);
    if rd32(&bak, 80) as usize != n_ent || rd32(&bak, 84) as usize != ent_sz || rd32(&bak, 88) != rd32(&hdr, 88) {
        return Err(String::from("Primary and backup GPT disagree (did a tool crash?).\nRun gdisk/sgdisk to repair; nothing was written."));
    }
    if bak_ent_lba <= last_usable || bak_ent_lba + ent_secs > last {
        return Err(String::from("Backup GPT entry array location is unusual; refusing."));
    }

    let mut parts = Vec::new();
    for i in 0..n_ent {
        let e = &entries[i * ent_sz..(i + 1) * ent_sz];
        if e[0..16].iter().all(|&b| b == 0) { continue; }
        let (start, end) = (rd64(e, 32), rd64(e, 40));
        if start > end || start < first_usable || end > last_usable {
            return Err(format!("Partition {} has an invalid range; refusing.", i + 1));
        }
        let mut name = String::new();
        for k in 0..((ent_sz - 56) / 2).min(36) {
            let c = u16::from_le_bytes([e[56 + k * 2], e[57 + k * 2]]);
            if c == 0 { break; }
            name.push(char::from_u32(c as u32).filter(|ch| !ch.is_control()).unwrap_or('?'));
        }
        let mut tg = [0u8; 16];
        tg.copy_from_slice(&e[0..16]);
        parts.push(Part { slot: i, type_guid: tg, start, end, name });
    }
    Ok(Gpt { first_usable, last_usable, n_ent, ent_sz, ent_lba, bak_ent_lba, bak_hdr_lba: last, hdr, bak_hdr: bak, entries, parts })
}

/// Largest aligned free gap as (first sector, sector count).
fn largest_gap(g: &Gpt) -> Option<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = g.parts.iter().map(|p| (p.start, p.end)).collect();
    v.sort();
    let mut gaps: Vec<(u64, u64)> = Vec::new(); // (start, end inclusive)
    let mut cur = g.first_usable;
    for (s, e) in v {
        if s > cur { gaps.push((cur, s - 1)); }
        if e + 1 > cur { cur = e + 1; }
    }
    if cur <= g.last_usable { gaps.push((cur, g.last_usable)); }
    let mut best: Option<(u64, u64)> = None;
    for (s, e) in gaps {
        let a = (s + ALIGN - 1) / ALIGN * ALIGN;
        let b = (e + 1) / ALIGN * ALIGN; // exclusive
        if b > a && best.map_or(true, |(_, n)| b - a > n) { best = Some((a, b - a)); }
    }
    best
}

fn size_choices(gap: u64) -> Vec<u64> {
    let mut v: Vec<u64> = Vec::new();
    for mb in [256u64, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536] {
        let s = mb * 2048;
        if s >= MIN_NEW_SECTORS && s < gap { v.push(s); }
    }
    v.push(gap);
    v
}

fn fmt_sectors(s: u64) -> String { fmt_size(s / 2048) }

fn rand_guid(seed: &[u8; 16]) -> [u8; 16] {
    let t = unsafe { core::arch::x86_64::_rdtsc() };
    make_uuid(t ^ rd64(seed, 0).rotate_left(13), rd64(seed, 8) ^ t.rotate_left(29))
}

// ── FAT32 (read + planned modification through the overlay) ──────────────────
struct Fat {
    part_start: u64,
    spc: u32,
    rsvd: u32,
    nfats: u32,
    fatsz: u32,
    root: u32,
    data_start: u64,
    max_cluster: u32,
    fsinfo_lba: Option<u64>,
}

struct DirHit { cluster: u32, is_dir: bool, size: u32 }

fn parse_fat(disk: usize, p: &Part) -> Result<Fat, String> {
    let mut v = [0u8; 512];
    if !disk_read(disk, p.start, 1, &mut v) { return Err(String::from("cannot read the ESP boot sector")); }
    if v[510] != 0x55 || v[511] != 0xAA { return Err(String::from("ESP has no FAT boot sector")); }
    let bps = u16::from_le_bytes([v[11], v[12]]);
    let spc = v[13] as u32;
    let rsvd = u16::from_le_bytes([v[14], v[15]]) as u32;
    let nfats = v[16] as u32;
    let root_ents = u16::from_le_bytes([v[17], v[18]]);
    let tot16 = u16::from_le_bytes([v[19], v[20]]) as u32;
    let fatsz16 = u16::from_le_bytes([v[22], v[23]]);
    let tot32 = rd32(&v, 32);
    let fatsz = rd32(&v, 36);
    let root = rd32(&v, 44);
    let fsinfo = u16::from_le_bytes([v[48], v[49]]) as u64;
    if bps != 512 { return Err(format!("ESP uses {}-byte sectors (only 512 supported)", bps)); }
    if spc == 0 || !spc.is_power_of_two() || spc > 128 { return Err(String::from("ESP has an invalid cluster size")); }
    if root_ents != 0 || fatsz16 != 0 || fatsz == 0 || rsvd == 0 || nfats == 0 || nfats > 4 {
        return Err(String::from("ESP is not FAT32 (only FAT32 is supported)"));
    }
    let total = if tot32 != 0 { tot32 } else { tot16 } as u64;
    if total == 0 || total > p.sectors() { return Err(String::from("ESP boot sector size exceeds the partition")); }
    let data_rel = rsvd as u64 + nfats as u64 * fatsz as u64;
    if data_rel >= total { return Err(String::from("ESP geometry is invalid")); }
    let clusters = (total - data_rel) / spc as u64;
    if clusters < 65525 { return Err(String::from("ESP is not FAT32 (cluster count too low)")); }
    if root < 2 || root as u64 > clusters + 1 { return Err(String::from("ESP root directory cluster is invalid")); }
    let fsinfo_lba = if fsinfo >= 1 && fsinfo < rsvd as u64 { Some(p.start + fsinfo) } else { None };
    Ok(Fat {
        part_start: p.start, spc, rsvd, nfats, fatsz, root,
        data_start: p.start + data_rel, max_cluster: (clusters + 1) as u32, fsinfo_lba,
    })
}

impl Fat {
    fn clus_lba(&self, c: u32) -> u64 { self.data_start + (c as u64 - 2) * self.spc as u64 }
    fn fat_pos(&self, copy: u32, c: u32) -> (u64, usize) {
        let off = c as u64 * 4;
        (self.part_start + self.rsvd as u64 + copy as u64 * self.fatsz as u64 + off / 512, (off % 512) as usize)
    }

    fn get(&self, ov: &Ov, c: u32) -> Result<u32, String> {
        let (lba, o) = self.fat_pos(0, c);
        Ok(rd32(&ov.read(lba)?, o) & 0x0FFF_FFFF)
    }

    /// Set a FAT entry in every FAT copy (upper 4 bits preserved).
    fn set(&self, ov: &mut Ov, c: u32, val: u32) -> Result<(), String> {
        for copy in 0..self.nfats {
            let (lba, o) = self.fat_pos(copy, c);
            let s = ov.edit(lba, "FAT")?;
            let old = rd32(s, o);
            w32(s, o, (old & 0xF000_0000) | (val & 0x0FFF_FFFF));
        }
        Ok(())
    }

    fn chain(&self, ov: &Ov, first: u32) -> Result<Vec<u32>, String> {
        let mut v = Vec::new();
        let mut c = first;
        while c >= 2 && c <= self.max_cluster {
            v.push(c);
            if v.len() > self.max_cluster as usize { return Err(String::from("FAT chain loop")); }
            c = self.get(ov, c)?;
            if c >= 0x0FFF_FFF8 { return Ok(v); }
        }
        if v.is_empty() { Ok(v) } else { Err(String::from("broken FAT chain")) }
    }

    /// Take `n` free clusters (lowest first), marked as end-of-chain for now.
    fn alloc(&self, ov: &mut Ov, n: usize) -> Result<Vec<u32>, String> {
        let mut out = Vec::with_capacity(n);
        if n == 0 { return Ok(out); }
        let mut c = 2u32;
        while c <= self.max_cluster {
            let (lba, o0) = self.fat_pos(0, c);
            let sec = ov.read(lba)?;
            let mut o = o0;
            while o < 512 && c <= self.max_cluster {
                if rd32(&sec, o) & 0x0FFF_FFFF == 0 {
                    out.push(c);
                    self.set(ov, c, FAT_EOC)?;
                    if out.len() == n { return Ok(out); }
                }
                o += 4;
                c += 1;
            }
        }
        Err(format!("the ESP has too little free space (about {} KiB more needed)", (n - out.len()) as u64 * self.spc as u64 / 2))
    }

    fn link(&self, ov: &mut Ov, clusters: &[u32]) -> Result<(), String> {
        for i in 0..clusters.len() {
            let next = if i + 1 < clusters.len() { clusters[i + 1] } else { FAT_EOC };
            self.set(ov, clusters[i], next)?;
        }
        Ok(())
    }

    fn dir_find(&self, ov: &Ov, dir: u32, name: &[u8; 11]) -> Result<Option<DirHit>, String> {
        for c in self.chain(ov, dir)? {
            for s in 0..self.spc as u64 {
                let sec = ov.read(self.clus_lba(c) + s)?;
                for e in 0..16 {
                    let ent = &sec[e * 32..e * 32 + 32];
                    if ent[0] == 0 { return Ok(None); }
                    if ent[0] == 0xE5 || ent[11] & 0x0F == 0x0F || ent[11] & 0x08 != 0 { continue; }
                    if &ent[0..11] == name {
                        let cl = ((u16::from_le_bytes([ent[20], ent[21]]) as u32) << 16)
                            | u16::from_le_bytes([ent[26], ent[27]]) as u32;
                        return Ok(Some(DirHit { cluster: cl, is_dir: ent[11] & 0x10 != 0, size: rd32(ent, 28) }));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Put a 32-byte entry into the first free slot of a directory.
    fn dir_add(&self, ov: &mut Ov, dir: u32, entry: &[u8; 32]) -> Result<(), String> {
        for c in self.chain(ov, dir)? {
            for s in 0..self.spc as u64 {
                let lba = self.clus_lba(c) + s;
                let sec = ov.read(lba)?;
                for e in 0..16 {
                    if sec[e * 32] == 0 || sec[e * 32] == 0xE5 {
                        let m = ov.edit(lba, "dir-link")?;
                        m[e * 32..e * 32 + 32].copy_from_slice(entry);
                        return Ok(());
                    }
                }
            }
        }
        Err(String::from("the ESP directory is full"))
    }

    /// New directory in `parent` (`parent_root` = parent is the volume root).
    fn mkdir(&self, ov: &mut Ov, parent: u32, parent_root: bool, name: &[u8; 11], nt: u8) -> Result<u32, String> {
        let c = self.alloc(ov, 1)?[0];
        let base = self.clus_lba(c);
        for s in 0..self.spc as u64 { ov.fresh(base + s, "dir-new"); }
        {
            let sec = ov.edit(base, "dir-new")?;
            sec[0..32].copy_from_slice(&mk_entry(b".          ", 0x10, 0, c, 0));
            sec[32..64].copy_from_slice(&mk_entry(b"..         ", 0x10, 0, if parent_root { 0 } else { parent }, 0));
        }
        self.dir_add(ov, parent, &mk_entry(name, 0x10, nt, c, 0))?;
        Ok(c)
    }

    /// Look a path of 8.3 names up (read-only through `ov`).
    fn lookup(&self, ov: &Ov, path: &[&[u8; 11]]) -> Result<Option<DirHit>, String> {
        let mut cur = self.root;
        for (i, n) in path.iter().enumerate() {
            match self.dir_find(ov, cur, n)? {
                None => return Ok(None),
                Some(h) => {
                    if i + 1 == path.len() { return Ok(Some(h)); }
                    if !h.is_dir { return Ok(None); }
                    cur = h.cluster;
                }
            }
        }
        Ok(None)
    }

    /// Compare a file on disk (walking its FAT chain) with `data`.
    fn compare_file(&self, ov: &Ov, hit: &DirHit, data: &[u8]) -> bool {
        if hit.size as usize != data.len() { return false; }
        let Ok(chain) = self.chain(ov, hit.cluster) else { return false };
        let need = (data.len() + self.spc as usize * 512 - 1) / (self.spc as usize * 512);
        if chain.len() != need.max(1) && !(data.is_empty() && chain.is_empty()) { return false; }
        let mut off = 0usize;
        let mut i = 0usize;
        while i < chain.len() && off < data.len() {
            let mut j = i + 1;
            while j < chain.len() && chain[j] == chain[j - 1] + 1 && (j - i) * (self.spc as usize) < BATCH { j += 1; }
            let secs = (j - i) * self.spc as usize;
            let mut buf = alloc::vec![0u8; secs * 512];
            if !disk_read(ov.disk, self.clus_lba(chain[i]), secs as u32, &mut buf) { return false; }
            let n = (data.len() - off).min(secs * 512);
            if buf[..n] != data[off..off + n] { return false; }
            off += secs * 512;
            i = j;
        }
        true
    }
}

fn mk_entry(name: &[u8; 11], attr: u8, nt: u8, cluster: u32, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0..11].copy_from_slice(name);
    e[11] = attr;
    e[12] = nt;
    w16(&mut e, 16, NEW_FAT_DATE); // creation date
    w16(&mut e, 18, NEW_FAT_DATE); // last access
    w16(&mut e, 20, (cluster >> 16) as u16);
    w16(&mut e, 24, NEW_FAT_DATE); // write date
    w16(&mut e, 26, (cluster & 0xFFFF) as u16);
    w32(&mut e, 28, size);
    e
}

// ── The plan ─────────────────────────────────────────────────────────────────
struct FileJob {
    shown: &'static str,
    name: &'static [u8; 11],
    data: &'static [u8],
    clusters: Vec<u32>,
}

struct Plan {
    esp: Part,
    esp_no: usize,
    new_slot: usize,
    new_start: u64,
    new_end: u64,
    fat: Fat,
    ov: Ov,                       // FAT / FSInfo / directory sectors
    files: Vec<FileJob>,
    efi_existed: bool,
    ospab_dir: u32,
    gpt_writes: Vec<(u64, [u8; 512], &'static str)>, // in write order
    new_entries: Vec<u8>,
    identity: [u8; 512],
    allowed: Vec<(u64, u64)>,     // [start, end) LBA ranges writes may touch
    total_sectors: u64,
}

fn build_plan(d: &VDisk, g: &Gpt, esp: &Part, gap: (u64, u64), size: u64, cfg: &Config, img: &Images) -> Result<Plan, String> {
    let new_start = gap.0;
    let new_end = gap.0 + size - 1;
    if size < MIN_NEW_SECTORS || size > gap.1 { return Err(String::from("The selected size does not fit the free space.")); }
    for p in &g.parts {
        if p.start <= new_end && new_start <= p.end { return Err(String::from("Internal error: new partition overlaps an existing one.")); }
    }
    // free GPT slot
    let new_slot = (0..g.n_ent)
        .find(|&i| g.entries[i * g.ent_sz..i * g.ent_sz + 16].iter().all(|&b| b == 0))
        .ok_or_else(|| String::from("The GPT has no free partition entry."))?;

    let fat = parse_fat(d.index, esp)?;
    let mut ov = Ov::new(d.index);

    // \EFI (create only if the ESP lacks it), \EFI\ospab must not exist yet
    let (efi_cluster, efi_existed) = match fat.dir_find(&ov, fat.root, NAME_EFI)? {
        Some(h) if h.is_dir => (h.cluster, true),
        Some(_) => return Err(String::from("\\EFI on the ESP is a file, not a directory; refusing.")),
        None => (fat.mkdir(&mut ov, fat.root, true, NAME_EFI, 0)?, false),
    };
    if efi_existed && fat.dir_find(&ov, efi_cluster, NAME_DIR)?.is_some() {
        return Err(String::from("\\EFI\\ospab already exists on the ESP (earlier install?).\nDelete that folder from Windows/Linux first; nothing was written."));
    }
    let ospab_dir = fat.mkdir(&mut ov, efi_cluster, false, NAME_DIR, 0x08)?;

    // files
    let cfg_text = build_ospab_cfg(true).as_bytes();
    let spec: [(&'static str, &'static [u8; 11], &'static [u8], u8); 3] = [
        ("OSPABLDR.EFI", NAME_LDR, img.efi, 0),
        ("ospab.cfg", NAME_CFG, cfg_text, 0x18),
        ("KERNEL", NAME_KRN, img.kernel, 0),
    ];
    let cb = fat.spc as usize * 512;
    let mut files = Vec::new();
    let mut used_clusters = 1u32; // the ospab directory
    for (shown, name, data, nt) in spec {
        if data.is_empty() { return Err(format!("{} is missing from the installer media.", shown)); }
        let n = (data.len() + cb - 1) / cb;
        let clusters = fat.alloc(&mut ov, n)?;
        fat.link(&mut ov, &clusters)?;
        fat.dir_add(&mut ov, ospab_dir, &mk_entry(name, 0x20, nt, clusters[0], data.len() as u32))?;
        used_clusters += n as u32;
        files.push(FileJob { shown, name, data, clusters });
    }
    if !efi_existed { used_clusters += 1; }
    // FSInfo: free count / next free hint
    if let Some(l) = fat.fsinfo_lba {
        let s = ov.read(l)?;
        if rd32(&s, 0) == 0x4161_5252 && rd32(&s, 484) == 0x6141_7272 {
            let m = ov.edit(l, "FSInfo")?;
            let free = rd32(m, 488);
            if free != 0xFFFF_FFFF { w32(m, 488, free.saturating_sub(used_clusters)); }
            let last = files.iter().filter_map(|f| f.clusters.last().copied()).max().unwrap_or(2);
            w32(m, 492, last + 1);
        }
    }

    // GPT: new entry
    let ent_secs_idx = (new_slot * g.ent_sz) / 512;
    let mut ne = g.entries.clone();
    {
        let e = &mut ne[new_slot * g.ent_sz..(new_slot + 1) * g.ent_sz];
        e[0..16].copy_from_slice(&LINUX_GUID);
        let seed: [u8; 16] = { let mut s = [0u8; 16]; s.copy_from_slice(&g.hdr[56..72]); s };
        e[16..32].copy_from_slice(&rand_guid(&seed));
        w64(e, 32, new_start);
        w64(e, 40, new_end);
        w64(e, 48, 0);
        for (i, c) in "AETERNA".chars().enumerate() { w16(e, 56 + i * 2, c as u16); }
    }
    let ecrc = crc32(&ne[..g.n_ent * g.ent_sz]);
    let sec_bytes = |i: usize| -> [u8; 512] { let mut b = [0u8; 512]; b.copy_from_slice(&ne[i * 512..i * 512 + 512]); b };
    let fix_hdr = |h: &[u8; 512]| -> [u8; 512] {
        let mut x = *h;
        let hs = rd32(&x, 12) as usize;
        w32(&mut x, 88, ecrc);
        w32(&mut x, 16, 0);
        let c = crc32(&x[..hs]);
        w32(&mut x, 16, c);
        x
    };
    let mut gpt_writes: Vec<(u64, [u8; 512], &'static str)> = Vec::new();
    gpt_writes.push((g.bak_ent_lba + ent_secs_idx as u64, sec_bytes(ent_secs_idx), "GPT backup entry"));
    gpt_writes.push((g.bak_hdr_lba, fix_hdr(&g.bak_hdr), "GPT backup header"));
    gpt_writes.push((g.ent_lba + ent_secs_idx as u64, sec_bytes(ent_secs_idx), "GPT primary entry"));
    gpt_writes.push((1, fix_hdr(&g.hdr), "GPT primary header"));

    // AETERNA identity record (same layout as the full-disk installer)
    let mut id = [0u8; 512];
    id[0..8].copy_from_slice(b"AETERNA ");
    let ver = crate::version::VERSION_STR.as_bytes();
    id[8..8 + ver.len().min(16)].copy_from_slice(&ver[..ver.len().min(16)]);
    let arch = crate::version::ARCH.as_bytes();
    id[24..24 + arch.len().min(8)].copy_from_slice(&arch[..arch.len().min(8)]);
    let date = crate::version::BUILD_DATE.as_bytes();
    id[32..32 + date.len().min(16)].copy_from_slice(&date[..date.len().min(16)]);
    let host = &cfg.host[..cfg.host_len];
    id[48..48 + host.len().min(32)].copy_from_slice(&host[..host.len().min(32)]);
    let loc = LOCALES[cfg.locale].as_bytes();
    id[80..80 + loc.len().min(16)].copy_from_slice(&loc[..loc.len().min(16)]);
    w64(&mut id, 96, esp.start);
    w64(&mut id, 104, new_start);
    w64(&mut id, 112, size / 2048);
    id[510] = 0xAE;
    id[511] = 0x05;

    // Everything the installer may write, and nothing else.
    let mut allowed = alloc::vec![(esp.start, esp.end + 1), (new_start, new_end + 1)];
    for (l, _, _) in &gpt_writes { allowed.push((*l, *l + 1)); }

    let mut total = ov.map.len() as u64 + gpt_writes.len() as u64 + 2;
    for f in &files { total += f.clusters.len() as u64 * fat.spc as u64; }
    Ok(Plan {
        esp: esp.clone(), esp_no: esp.slot + 1, new_slot, new_start, new_end, fat, ov, files, efi_existed,
        ospab_dir, gpt_writes, new_entries: ne, identity: id, allowed, total_sectors: total,
    })
}

/// "a..b, c, d..e" for a sorted list of LBAs, at most `max` ranges.
fn ranges(lbas: &[u64], max: usize) -> String {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &l in lbas {
        match out.last_mut() {
            Some(r) if r.1 + 1 == l => r.1 = l,
            _ => out.push((l, l)),
        }
    }
    let mut s = String::new();
    for (i, (a, b)) in out.iter().enumerate() {
        if i == max { s.push_str(&format!(" +{} more", out.len() - max)); break; }
        if i > 0 { s.push_str(", "); }
        if a == b { s.push_str(&format!("{}", a)); } else { s.push_str(&format!("{}..{}", a, b)); }
    }
    s
}

fn label_lbas(p: &Plan, label: &str) -> Vec<u64> {
    p.ov.map.iter().filter(|(_, (_, l))| *l == label).map(|(k, _)| *k).collect()
}

/// The dry-run: (heading, text) rows describing exactly what will be written.
fn summary(d: &VDisk, g: &Gpt, p: &Plan) -> Vec<(&'static str, String)> {
    let mut v: Vec<(&'static str, String)> = Vec::new();
    let w = (width() as usize).saturating_sub(17);
    let tr = |s: String| truncate(&s, w);
    let si = (p.new_slot * g.ent_sz / 512) as u64;
    v.push(("GPT sectors", tr(format!("LBA 1, {} (entry {}); backup LBA {}, {}",
        g.ent_lba + si, p.new_slot + 1, g.bak_hdr_lba, g.bak_ent_lba + si))));
    v.push(("New partition", tr(format!("#{} AETERNA  LBA {}..{}  ({})",
        p.new_slot + 1, p.new_start, p.new_end, fmt_sectors(p.new_end - p.new_start + 1)))));
    v.push(("  its sectors", tr(format!("LBA {} (identity), {} (empty store)", p.new_start, p.new_start + 8))));
    v.push(("ESP", tr(format!("#{} LBA {}..{}  FAT32, {} B clusters", p.esp_no, p.esp.start, p.esp.end, p.fat.spc * 512))));
    v.push(("  FAT sectors", tr(ranges(&label_lbas(p, "FAT"), 4))));
    let mut dl = label_lbas(p, "dir-new");
    dl.extend(label_lbas(p, "dir-link"));
    dl.sort();
    v.push(("  Dir sectors", tr(ranges(&dl, 4))));
    let fs = label_lbas(p, "FSInfo");
    if !fs.is_empty() { v.push(("  FSInfo", tr(ranges(&fs, 2)))); }
    v.push(("New folder", String::from(if p.efi_existed { "\\EFI\\ospab\\  (inside the existing \\EFI)" } else { "\\EFI\\  and  \\EFI\\ospab\\" })));
    for f in &p.files {
        let mut l: Vec<u64> = Vec::new();
        for &c in &f.clusters { for s in 0..p.fat.spc as u64 { l.push(p.fat.clus_lba(c) + s); } }
        v.push(("New file", tr(format!("{}  {}  LBA {}", f.shown, fmt_bytes(f.data.len() as u64), ranges(&l, 2)))));
    }
    let others: Vec<String> = g.parts.iter().map(|x| format!("#{}", x.slot + 1)).collect();
    v.push(("Untouched", tr(format!("partitions {}; ESP files outside \\EFI\\ospab", others.join(" ")))));
    v.push(("Total", format!("{} sectors ({}) will be written", p.total_sectors, fmt_bytes(p.total_sectors * 512))));
    let _ = d;
    v
}

fn log_plan(p: &Plan, rows: &[(&'static str, String)]) {
    slog("[ALONGSIDE] === dry-run summary ===\r\n");
    for (k, t) in rows { slog("[ALONGSIDE] "); slog(k); slog(": "); slog(t); slog("\r\n"); }
    slog("[ALONGSIDE] metadata sectors:\r\n");
    for (lba, (_, l)) in p.ov.map.iter() { slog("  "); slog(l); slog(" LBA "); slog_dec(*lba); slog("\r\n"); }
    for (lba, _, l) in &p.gpt_writes { slog("  "); slog(l); slog(" LBA "); slog_dec(*lba); slog("\r\n"); }
    for f in &p.files {
        slog("  file "); slog(f.shown); slog(" clusters ");
        slog_dec(f.clusters[0] as u64); slog(".. count "); slog_dec(f.clusters.len() as u64); slog("\r\n");
    }
}

// ── Guarded writer ───────────────────────────────────────────────────────────
struct Writer<'a> {
    disk: usize,
    allowed: &'a [(u64, u64)],
    total: u64,
    done: u64,
    last_pm: u64,
    errors: u64,
}

impl<'a> Writer<'a> {
    fn write(&mut self, lba: u64, data: &[u8]) -> bool {
        let n = (data.len() / 512) as u64;
        if n == 0 || data.len() % 512 != 0 { return false; }
        if !self.allowed.iter().any(|&(s, e)| lba >= s && lba + n <= e) {
            slog("[ALONGSIDE] SAFETY: refused write at LBA "); slog_dec(lba); slog(" count "); slog_dec(n); slog("\r\n");
            self.errors += 1;
            return false;
        }
        let ok = disk_write(self.disk, lba, n as u32, data);
        if !ok { self.errors += 1; }
        self.done += n;
        let pm = (self.done * 1000 / self.total.max(1)).min(999);
        if pm != self.last_pm { self.last_pm = pm; draw_overall(pm); }
        ok
    }
}

// ── Pages ────────────────────────────────────────────────────────────────────
fn show_lines(row: u64, s: &str, fg: u32, bg: u32) -> u64 {
    let mut r = row;
    for line in s.lines() {
        Pen::at(3, r).on(bg).put(&truncate(line, (width() as usize).saturating_sub(5)), fg);
        r += 1;
    }
    r
}

fn error_box(row: u64, title: &str, msg: &str) {
    let h = msg.lines().count() as u64 + 2;
    draw_box(row, h, FG_ERR, ERR_BG, title);
    show_lines(row + 1, msg, FG, ERR_BG);
}

/// Returns Nav::Next when the whole alongside install ran (successfully or not).
pub fn run(d: &VDisk, cfg: &Config, img: &Images) -> Nav {
    set_alongside(true);
    let r = run_inner(d, cfg, img);
    set_alongside(false);
    r
}

fn run_inner(d: &VDisk, cfg: &Config, img: &Images) -> Nav {
    slog("[ALONGSIDE] scanning GPT of /dev/"); slog(d.name()); slog("\r\n");
    let gpt = parse_gpt(d);
    let mut sel_esp = 0usize;
    let mut sel_size: Option<usize> = None;
    loop {
        let plan = match page_scan(d, &gpt, cfg, img, &mut sel_esp, &mut sel_size) {
            Ok(p) => p,
            Err(n) => return n,
        };
        let g = gpt.as_ref().ok().unwrap();
        match page_confirm(d, g, &plan) {
            Nav::Back => continue,
            Nav::Quit => return Nav::Quit,
            Nav::Next => {}
        }
        execute(d, g, plan, cfg, img);
        return Nav::Next;
    }
}

fn page_scan(d: &VDisk, gpt: &Result<Gpt, String>, cfg: &Config, img: &Images,
             sel_esp: &mut usize, sel_size: &mut Option<usize>) -> Result<Plan, Nav> {
    slog("[ALONGSIDE] page: scan\r\n");
    chrome(2, "Existing systems on this disk", FG_TITLE,
           &format!("/dev/{}  \u{00B7}  {}  \u{00B7}  nothing is written on this page", d.name(), fmt_size(d.size_mb)),
           &[("\u{2191}\u{2193}", "Choose ESP"), ("\u{2190}\u{2192}", "Size"), ("Enter", "Continue"), ("Esc", "Back")]);

    let g = match gpt {
        Ok(g) => g,
        Err(msg) => {
            slog("[ALONGSIDE] refused: "); slog(msg); slog("\r\n");
            error_box(R_BODY, "Cannot install alongside here", msg);
            drain_keys();
            footer(&[("Esc", "Back")], "");
            loop {
                match key() {
                    ESC | '\n' => return Err(Nav::Back),
                    CTRL_C | 'q' | 'Q' => return Err(Nav::Quit),
                    _ => {}
                }
            }
        }
    };

    // Partition table
    Pen::at(2, R_BODY).put("#", FG_DIM).pad(6).put("TYPE", FG_DIM).pad(30).put("NAME", FG_DIM).pad(46).put("SIZE", FG_DIM).pad(58).put("FIRST LBA", FG_DIM);
    hrule(R_BODY + 1);
    let max_rows = (rows().saturating_sub(R_BODY + 16)).clamp(3, 12) as usize;
    let mut sorted: Vec<&Part> = g.parts.iter().collect();
    sorted.sort_by_key(|p| p.start);
    for (i, p) in sorted.iter().enumerate() {
        if i == max_rows {
            t(2, R_BODY + 2 + i as u64, &format!("\u{2026} and {} more partitions", sorted.len() - max_rows), FG_DIM);
            break;
        }
        let r = R_BODY + 2 + i as u64;
        let tfg = if p.is_esp() { ACCENT } else { FG };
        Pen::at(2, r).put(&format!("{}", p.slot + 1), FG_DIM).pad(6)
            .put(&truncate(type_name(&p.type_guid), 22), tfg).pad(30)
            .put(&truncate(if p.name.is_empty() { "-" } else { p.name.as_str() }, 14), FG).pad(46)
            .put(&fmt_sectors(p.sectors()), FG).pad(58)
            .put(&format!("{}", p.start), FG_DIM);
    }
    let shown = sorted.len().min(max_rows) + (if sorted.len() > max_rows { 1 } else { 0 });
    let mut row = R_BODY + 2 + shown.max(1) as u64 + 1;
    if sorted.is_empty() { t(2, R_BODY + 2, "(no partitions)", FG_DIM); }

    // Free space and ESP candidates
    let gap = largest_gap(g);
    let esps: Vec<&Part> = sorted.iter().copied().filter(|p| p.is_esp()).collect();
    let mut problem: Option<String> = None;
    match gap {
        None => problem = Some(String::from("There is no free space on this disk.\nShrink a partition from Windows (Disk Management) or Linux (gparted)\nto leave at least 64 MiB unallocated. Nothing was changed.")),
        Some((s, n)) if n < MIN_NEW_SECTORS => problem = Some(format!(
            "The largest free gap is only {} (LBA {}..{}); at least 64 MiB is needed.\nShrink a partition from Windows or Linux first. Nothing was changed.",
            fmt_sectors(n), s, s + n - 1)),
        _ => {}
    }
    if problem.is_none() && esps.is_empty() {
        problem = Some(String::from("No EFI System Partition was found on this disk, so there is no\nplace for the boot files. Alongside mode never creates one.\nNothing was changed."));
    }
    if let Some(m) = &problem {
        slog("[ALONGSIDE] refused: "); slog(m); slog("\r\n");
        match gap {
            Some((s, n)) => t(2, row, &format!("Largest free gap: {} at LBA {}..{}", fmt_sectors(n), s, s + n - 1), FG_WARN),
            None => t(2, row, "Largest free gap: none", FG_WARN),
        }
        error_box(row + 2, "Cannot install alongside here", m);
        footer(&[("Esc", "Back")], "");
        drain_keys();
        loop {
            match key() {
                ESC | '\n' => return Err(Nav::Back),
                CTRL_C | 'q' | 'Q' => return Err(Nav::Quit),
                _ => {}
            }
        }
    }
    let gap = gap.unwrap();
    t(2, row, &format!("Largest free gap: {} at LBA {}..{}", fmt_sectors(gap.1), gap.0, gap.0 + gap.1 - 1), FG_OK);
    row += 2;

    let sizes = size_choices(gap.1);
    let mut si = sel_size.unwrap_or(sizes.len() - 1).min(sizes.len() - 1);
    *sel_esp = (*sel_esp).min(esps.len() - 1);
    let fat_state: Vec<String> = esps.iter().map(|p| match parse_fat(d.index, p) {
        Ok(_) => String::from("FAT32"),
        Err(e) => format!("unusable: {}", e),
    }).collect();
    let mut cur = 0usize; // 0 = ESP, 1 = size, 2 = continue
    let mut msg: Option<String> = None;
    loop {
        for i in 0..3usize {
            let r = row + i as u64 + if i == 2 { 1 } else { 0 };
            let selb = i == cur;
            let bg = if selb { SEL_BG } else { BG };
            if i == 2 {
                clear_panel_row(r);
                Pen::at(2, r).on(if selb { ACCENT } else { KEY_BG }).put("  Review the plan \u{2192}  ", if selb { BG } else { FG });
                continue;
            }
            let mut p = Pen::at(0, r).on(bg);
            p.put(if selb { "\u{25B6} " } else { "  " }, ACCENT);
            if i == 0 {
                let e = esps[*sel_esp];
                p.put("Boot files go to ESP", if selb { FG_TITLE } else { FG }).pad(26);
                p.put(&format!("#{} ({}, {})", e.slot + 1, fmt_sectors(e.sectors()), fat_state[*sel_esp]), FG_TITLE);
                if esps.len() > 1 { p.put(&format!("   [{} of {}]", *sel_esp + 1, esps.len()), FG_DIM); }
            } else {
                p.put("New AETERNA partition", if selb { FG_TITLE } else { FG }).pad(26);
                p.put(&fmt_sectors(sizes[si]), FG_TITLE);
                if si == sizes.len() - 1 { p.put("  (all free space)", FG_DIM); }
            }
            p.pad(width());
        }
        clear_panel_row(row + 5);
        if let Some(m) = &msg { show_lines(row + 5, m, FG_ERR, BG); }
        else { t(2, row + 5, "Windows/Linux partitions are never moved, resized or written.", FG_DIM); }

        let k = key();
        msg = None;
        match k {
            keyboard::KEY_UP => { cur = if cur == 0 { 2 } else { cur - 1 }; }
            keyboard::KEY_DOWN | '\t' => { cur = (cur + 1) % 3; }
            keyboard::KEY_LEFT | keyboard::KEY_RIGHT => {
                let fwd = k == keyboard::KEY_RIGHT;
                if cur == 0 {
                    let n = esps.len();
                    *sel_esp = if fwd { (*sel_esp + 1) % n } else { (*sel_esp + n - 1) % n };
                } else if cur == 1 {
                    let n = sizes.len();
                    si = if fwd { (si + 1) % n } else { (si + n - 1) % n };
                }
            }
            '\n' => {
                *sel_size = Some(si);
                match build_plan(d, g, esps[*sel_esp], gap, sizes[si], cfg, img) {
                    Ok(p) => return Ok(p),
                    Err(e) => { slog("[ALONGSIDE] plan failed: "); slog(&e); slog("\r\n"); msg = Some(e); }
                }
            }
            ESC => return Err(Nav::Back),
            CTRL_C | 'q' | 'Q' => return Err(Nav::Quit),
            _ => {}
        }
    }
}

fn page_confirm(d: &VDisk, g: &Gpt, p: &Plan) -> Nav {
    slog("[ALONGSIDE] page: confirm\r\n");
    chrome(3, "Review the dry-run", FG_TITLE, "This is exactly what will be written. Nothing has been written yet.",
           &[("Enter", "Install"), ("Esc", "Back")]);
    let rows_v = summary(d, g, p);
    log_plan(p, &rows_v);
    let mut r = R_BODY;
    for (k, v) in &rows_v {
        let fg = if *k == "Untouched" { FG_OK } else { FG };
        Pen::at(2, r).put(k, FG_DIM).pad(15).put(v, fg);
        r += 1;
    }
    r += 1;
    Pen::at(2, r).put("Boot menu / UEFI NVRAM entries are not changed. Type ", FG).put("install", FG_TITLE).put(" and press Enter:", FG);
    r += 1;
    let pr = r;
    drain_keys();
    let mut buf = [0u8; 12];
    let mut len = 0usize;
    let mut wrong = false;
    loop {
        let mut pen = Pen::at(2, pr).on(FIELD_BG);
        pen.put(" ", FG);
        for i in 0..len { cell(pen.col, pr, buf[i] as char, FG_TITLE, FIELD_BG); pen.col += 1; }
        pen.put("_", ACCENT).pad(24);
        clear_panel_row(pr + 1);
        if wrong { t(2, pr + 1, "Type the word install to continue, or press Esc to go back.", FG_ERR); }
        match key() {
            '\n' => {
                if buf[..len].eq_ignore_ascii_case(b"install") {
                    slog("[ALONGSIDE] confirmed\r\n");
                    return Nav::Next;
                }
                wrong = true;
            }
            ESC => return Nav::Back,
            CTRL_C => return Nav::Quit,
            BKSP => { if len > 0 { len -= 1; } }
            c if c.is_ascii_alphabetic() && len < 10 => { buf[len] = c as u8; len += 1; wrong = false; }
            _ => {}
        }
    }
}

// ── Execution ────────────────────────────────────────────────────────────────
struct Outcome { checks: Vec<Check>, ok: bool }

fn execute(d: &VDisk, g: &Gpt, plan: Plan, cfg: &Config, img: &Images) {
    let _ = img;
    chrome(4, "Installing alongside", FG_TITLE,
           &format!("Writing to /dev/{} \u{2014} do not power off or remove the disk.", d.name()), &[]);
    footer(&[], "Installing\u{2026} please wait");
    for i in 0..labels().len() { step_draw(i, St::Pending, ""); }
    t(2, R_OVR, "Overall progress", FG_DIM);
    WRITE_ERRS.store(0, Ordering::Relaxed);
    P_TOTAL.store(0, Ordering::Relaxed);
    S_TOTAL.store(0, Ordering::Relaxed);
    draw_overall(0);

    let mut w = Writer { disk: d.index, allowed: &plan.allowed, total: plan.total_sectors, done: 0, last_pm: u64::MAX, errors: 0 };
    macro_rules! die {
        ($i:expr, $msg:expr) => {{ install_failed($i, $msg); return; }}
    }

    // 0 — re-validate: the disk must still look exactly as it did when planned
    step_begin(0, 0);
    match parse_gpt(d) {
        Ok(g2) if g2.entries == g.entries && g2.hdr == g.hdr && g2.bak_hdr == g.bak_hdr => {}
        _ => die!(0, "the partition table changed since the review; nothing was written"),
    }
    step_end(0, St::Ok, "GPT unchanged since review");

    // 1 — file data into free ESP clusters (not yet referenced by anything)
    step_begin(1, 0);
    for f in &plan.files {
        if !write_file(&mut w, &plan.fat, f) { die!(1, "write error while copying files (ESP left consistent)"); }
    }
    disk_flush(d.index);
    step_end(1, St::Ok, &format!("{} files", plan.files.len()));

    // 2 — FAT + FSInfo, then the new directory, then the link in the old directory
    step_begin(2, 0);
    let mut order: Vec<(u8, u64)> = plan.ov.map.iter().map(|(l, (_, lab))| {
        let rank = match *lab { "FAT" => 0, "FSInfo" => 1, "dir-new" => 2, _ => 3 };
        (rank, *l)
    }).collect();
    order.sort();
    let mut fat_done = false;
    let mut i = 0usize;
    while i < order.len() {
        let (rank, lba) = order[i];
        if rank >= 2 && !fat_done {
            disk_flush(d.index);
            step_end(2, St::Ok, "FAT updated");
            step_begin(3, 0);
            fat_done = true;
        }
        let mut j = i + 1;
        while j < order.len() && order[j].0 == rank && order[j].1 == order[j - 1].1 + 1 && (j - i) < BATCH { j += 1; }
        let mut buf = Vec::with_capacity((j - i) * 512);
        for k in i..j { buf.extend_from_slice(&plan.ov.map[&order[k].1].0); }
        if !w.write(lba, &buf) { die!(if fat_done { 3 } else { 2 }, "write error while updating the ESP metadata"); }
        i = j;
    }
    if !fat_done { step_end(2, St::Ok, "FAT updated"); step_begin(3, 0); }
    disk_flush(d.index);
    step_end(3, St::Ok, "\\EFI\\ospab linked");

    // 4 — the new partition's own sectors (inside free space we are about to claim)
    step_begin(4, 0);
    if !w.write(plan.new_start, &plan.identity) { die!(4, "cannot write the identity record"); }
    if !w.write(plan.new_start + 8, &[0u8; 512]) { die!(4, "cannot clear the persistence header"); }
    disk_flush(d.index);
    step_end(4, St::Ok, "identity + empty store");

    // 5 — GPT last: backup entry, backup header, primary entry, primary header
    step_begin(5, 0);
    for (lba, data, label) in &plan.gpt_writes {
        slog("[ALONGSIDE] writing "); slog(label); slog(" at LBA "); slog_dec(*lba); slog("\r\n");
        if !w.write(*lba, data) { die!(5, "cannot update the GPT (partition table may be unchanged)"); }
    }
    disk_flush(d.index);
    step_end(5, St::Ok, "primary + backup");
    P_TOTAL.store(0, Ordering::Relaxed);
    draw_overall(1000);

    // 6 — read back
    step_begin(6, 0);
    let out = verify(d, g, &plan);
    let failed = out.checks.iter().filter(|c| !c.ok).count();
    if failed == 0 { step_end(6, St::Ok, &format!("{} checks passed", out.checks.len())); }
    else { step_end(6, St::Fail, &format!("{} of {} checks failed", failed, out.checks.len())); }
    slog(if out.ok { "[ALONGSIDE] install complete, all checks OK\r\n" } else { "[ALONGSIDE] install complete WITH ERRORS\r\n" });

    draw_checks(R_CHECKS, &out.checks);
    Pen::at(2, R_CHECKS + 8).put("Press Enter to continue.", FG);
    footer(&[("Enter", "Continue")], "");
    drain_keys();
    loop { if key() == '\n' { break; } }
    page_done(d, &plan, cfg, &out);
}

fn write_file(w: &mut Writer, fat: &Fat, f: &FileJob) -> bool {
    let spc = fat.spc as usize;
    let cl = &f.clusters;
    let (mut i, mut off) = (0usize, 0usize);
    while i < cl.len() {
        let mut j = i + 1;
        while j < cl.len() && cl[j] == cl[j - 1] + 1 && (j - i) * spc < BATCH { j += 1; }
        let secs = (j - i) * spc;
        let mut buf = alloc::vec![0u8; secs * 512];
        let take = f.data.len().saturating_sub(off).min(secs * 512);
        buf[..take].copy_from_slice(&f.data[off..off + take]);
        if !w.write(fat.clus_lba(cl[i]), &buf) { return false; }
        off += secs * 512;
        i = j;
    }
    true
}

fn verify(d: &VDisk, g: &Gpt, p: &Plan) -> Outcome {
    slog("[ALONGSIDE] === verification ===\r\n");
    let mut checks: Vec<Check> = Vec::new();
    let mut push = |label: &'static str, ok: bool| {
        slog("[VERIFY] "); slog(label); slog(if ok { ": ok\r\n" } else { ": FAILED\r\n" });
        checks.push(Check { label, ok });
    };

    // GPT: re-parse (both headers + entries CRC), new entry present, others byte-identical
    let g2 = parse_gpt(d);
    push("GPT valid (primary + backup CRC)", g2.is_ok());
    let (same, entry_ok) = match &g2 {
        Ok(n) => {
            let ssz = g.ent_sz;
            let mut same = n.entries.len() == g.entries.len();
            if same {
                for i in 0..g.n_ent {
                    if i == p.new_slot { continue; }
                    if n.entries[i * ssz..(i + 1) * ssz] != g.entries[i * ssz..(i + 1) * ssz] { same = false; break; }
                }
            }
            let e = n.parts.iter().any(|x| x.slot == p.new_slot && x.start == p.new_start && x.end == p.new_end && x.name == "AETERNA");
            (same && n.parts.len() == g.parts.len() + 1, e)
        }
        Err(_) => (false, false),
    };
    push("Existing partition entries unchanged", same);
    push("AETERNA partition entry", entry_ok);

    // ESP metadata sectors identical to the plan
    let mut meta_ok = true;
    for (lba, (data, _)) in p.ov.map.iter() {
        let mut b = [0u8; 512];
        if !disk_read(d.index, *lba, 1, &mut b) || &b != data { meta_ok = false; slog("[VERIFY] mismatch at LBA "); slog_dec(*lba); slog("\r\n"); }
    }
    push("ESP metadata read back", meta_ok);

    // Files via an independent walk of the on-disk FAT
    let rd = Ov::new(d.index);
    for f in &p.files {
        let hit = p.fat.lookup(&rd, &[NAME_EFI, NAME_DIR, f.name]).ok().flatten();
        let ok = hit.map_or(false, |h| !h.is_dir && p.fat.compare_file(&rd, &h, f.data));
        push(match f.shown { "OSPABLDR.EFI" => "\\EFI\\ospab\\OSPABLDR.EFI", "ospab.cfg" => "\\EFI\\ospab\\ospab.cfg", _ => "\\EFI\\ospab\\KERNEL" }, ok);
    }
    let sig_ok = {
        let mut b = [0u8; 512];
        disk_read(d.index, p.esp.start, 1, &mut b) && b[510] == 0x55 && b[511] == 0xAA
    };
    push("ESP boot sector intact", sig_ok);

    // Identity + persistence discoverable
    let mut idb = [0u8; 512];
    let id_ok = disk_read(d.index, p.new_start, 1, &mut idb) && idb == p.identity;
    push("AETERNA identity record", id_ok);
    let base_ok = ospab_os::fs::disk_sync::base_lba(d.index) == Some(p.new_start + 8);
    push("Persistence area found by kernel", base_ok);

    let ok = checks.iter().all(|c| c.ok);
    Outcome { checks, ok }
}

// ── Done ─────────────────────────────────────────────────────────────────────
fn page_done(d: &VDisk, p: &Plan, cfg: &Config, out: &Outcome) {
    slog("[ALONGSIDE] page: done\r\n");
    let (title, tfg) = if out.ok { ("Installed next to your other systems", FG_OK) }
                       else { ("Finished with problems", FG_WARN) };
    chrome(5, title, tfg, "Your existing partitions were not modified.",
           &[("Enter", "How to boot it"), ("Esc", "Back to shell")]);
    let (border, fill) = if out.ok { (FG_OK, OK_BG) } else { (FG_WARN, WARN_BG) };
    draw_box(R_BODY, 5, border, fill, "");
    Pen::at(3, R_BODY + 1).on(fill).put(if out.ok { "\u{2713}  " } else { "!  " }, border).put("ospab.os files: ", FG_TITLE)
        .put(&format!("ESP #{}  \\EFI\\ospab\\", p.esp_no), FG);
    Pen::at(6, R_BODY + 2).on(fill).put(&format!("AETERNA partition #{}  {}  LBA {}..{}",
        p.new_slot + 1, fmt_sectors(p.new_end - p.new_start + 1), p.new_start, p.new_end), FG_DIM);
    Pen::at(6, R_BODY + 3).on(fill).put(&format!("{}  \u{00B7}  {}", cfg.hostname(), LOCALES[cfg.locale]), FG_DIM);
    t(2, R_BODY + 6, "Verification", FG_TITLE);
    draw_checks(R_BODY + 7, &out.checks);
    let nr = R_BODY + 7 + ((out.checks.len() + 1) / 2) as u64 + 1;
    t(2, nr, "The firmware boot list was NOT changed. Press Enter to see how to start ospab.os.", FG);

    drain_keys();
    loop {
        match key() {
            '\n' => break,
            ESC | 'q' | 'Q' | CTRL_C => return,
            _ => {}
        }
    }

    // Boot instructions
    let dev = if d.is_nvme() { String::from("/dev/nvme0n1") } else { format!("/dev/{}", d.name()) };
    chrome(5, "How to boot ospab.os", FG_TITLE, "Installing never writes UEFI NVRAM; pick one of these once.",
           &[("Enter", "Reboot now"), ("Esc", "Back to shell")]);
    let efi_cmd1 = format!("efibootmgr -c -d {} -p {} -L ospab.os \\", dev, p.esp_no);
    let efi_cmd2 = String::from("  -l '\\EFI\\ospab\\OSPABLDR.EFI'");
    let mut r = R_BODY;
    t(2, r, "1  Firmware boot menu (F12 / F11 / Esc at power-on)", FG_TITLE);
    t(5, r + 1, "choose \"boot from file\" / \"add boot option\" and select", FG_DIM);
    t(5, r + 2, "\\EFI\\ospab\\OSPABLDR.EFI", ACCENT);
    r += 4;
    t(2, r, "2  GRUB (Linux): add to /etc/grub.d/40_custom, then update-grub", FG_TITLE);
    let grub = [
        "menuentry \"ospab.os\" {",
        "  insmod part_gpt",
        "  insmod fat",
        "  search --file --set=root /EFI/ospab/OSPABLDR.EFI",
        "  chainloader /EFI/ospab/OSPABLDR.EFI",
        "}",
    ];
    for (i, l) in grub.iter().enumerate() { t(5, r + 1 + i as u64, l, ACCENT); }
    r += 8;
    t(2, r, "3  From Linux, register a firmware entry:", FG_TITLE);
    t(5, r + 1, &efi_cmd1, ACCENT);
    t(5, r + 2, &efi_cmd2, ACCENT);
    t(5, r + 3, &format!("(check the device and ESP number #{} with lsblk first)", p.esp_no), FG_DIM);

    slog("[ALONGSIDE] how to boot:\r\n");
    slog("  1) firmware boot menu -> boot from file -> \\EFI\\ospab\\OSPABLDR.EFI\r\n");
    slog("  2) GRUB: menuentry \"ospab.os\" { insmod part_gpt; insmod fat; search --file --set=root /EFI/ospab/OSPABLDR.EFI; chainloader /EFI/ospab/OSPABLDR.EFI }\r\n");
    slog("  3) efibootmgr -c -d "); slog(&dev); slog(" -p "); slog_dec(p.esp_no as u64);
    slog(" -L ospab.os -l '\\EFI\\ospab\\OSPABLDR.EFI'\r\n");

    drain_keys();
    loop {
        match key() {
            '\n' | 'r' | 'R' => {
                fill_cells(0, rows() - 1, cols(), 1, BAR_BG);
                abs_text(2, rows() - 1, "Syncing disks and rebooting\u{2026}", FG_TITLE, BAR_BG);
                disk_flush(d.index);
                if ospab_os::fs::disk_sync::is_dirty() { ospab_os::fs::disk_sync::sync_filesystem(); }
                slog("[INSTALLER] rebooting\r\n");
                ospab_os::acpi::reboot();
                return;
            }
            ESC | 'q' | 'Q' | CTRL_C => return,
            _ => {}
        }
    }
}
