/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Where the persistent layer lives on disk, the reader of the old snapshot format, and the
entry points the shell, the installer and the power paths use (`is_dirty`, `sync_filesystem`,
`deferred_tick`). The persistent layer itself is AeternaFS v2 (vfs/aeternafs.rs); the whole-RAM
snapshot of earlier versions is only read, once, to migrate it (vfs/persist.rs).

Layout of the AETERNA root partition (or of a raw disk, from LBA 2048):

  base ..................... base + 16384   old snapshot area (8 MiB), read only, then cleared
  v2_start ................. end            AeternaFS v2 volume (4096-byte blocks)

where base = partition start + 8 sectors (sector 0 holds the installer's identity record) and
v2_start = base + 16384, rounded up to a multiple of 8 sectors.

Old snapshot format ("Flat Image Persistence"):
  SUPER_MAGIC u64 LE, sector_count u32, b"AETERNA_FS", VERSION u32 = 1, COUNT u32,
  then COUNT entries: path_len u16, path, type u8 (0 file, 1 dir), [data_len u32, data].
*/

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryInto;

use super::ramfs::RamNode;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Magic of the old snapshot at its first byte (8 bytes): "AETERNA\0"
pub const SUPER_MAGIC: u64 = 0x41455445524E41;

/// Magic signature that follows the old superblock
const MAGIC: &[u8; 10] = b"AETERNA_FS";

/// Old format version
const VERSION: u32 = 1;

const TAG_FILE: u8 = 0;
const TAG_DIR:  u8 = 1;

/// Starting LBA on a disk without GPT.
const LBA_BASE: u64 = 2048;

/// Size reserved for the old snapshot (8 MiB). The v2 volume starts after it.
pub const MAX_FS_BYTES: usize = 8 * 1024 * 1024;

/// Sectors of the old snapshot area.
pub const LEGACY_SECTORS: u64 = (MAX_FS_BYTES / 512) as u64;

/// Smallest v2 volume worth creating (sectors): 1 MiB.
const MIN_V2_SECTORS: u64 = 2048;

/// Bytes of the volume in use, for `df` before the first mount (kept for old callers).
pub fn last_snapshot_bytes() -> usize {
    super::aeternafs::root_volume_info().map_or(0, |i| ((i.total_blocks - i.free_blocks) * 4096) as usize)
}

/// Choose the primary persistence disk: prefer AHCI, else first disk.
pub fn select_disk() -> Option<(usize, crate::drivers::DiskKind, usize)> {
    let total = crate::drivers::disk_count();
    for i in 0..total {
        if let Some(info) = crate::drivers::disk_info(i) {
            if info.kind == crate::drivers::DiskKind::Ahci {
                let ahci_idx = crate::drivers::disk_info_count_before(i, crate::drivers::DiskKind::Ahci);
                return Some((i, info.kind, ahci_idx));
            }
        }
    }
    if let Some(info) = crate::drivers::disk_info(0) {
        let kind_idx = crate::drivers::disk_info_count_before(0, info.kind);
        return Some((0, info.kind, kind_idx));
    }
    None
}

/// Expose the chosen disk index for boot-time inspection
pub fn primary_disk_index() -> Option<usize> {
    select_disk().map(|(g, _, _)| g)
}

/// GPT type GUID the installer gives the AETERNA root partition
/// (0FC63DAF-8483-4772-8E79-3D69D8477DE4, mixed-endian on disk).
const ROOT_TYPE_GUID: [u8; 16] = [0xAF,0x3D,0xC6,0x0F,0x83,0x84,0x72,0x47,0x8E,0x79,0x3D,0x69,0xD8,0x47,0x7D,0xE4];

/// Sectors skipped at the start of the AETERNA root partition
/// (sector 0 holds the installer's identity record).
pub const ROOT_SKIP: u64 = 8;

/// (first LBA of the old snapshot area, end LBA exclusive of the usable area, has GPT)
fn locate(global_idx: usize) -> Option<(u64, u64, bool)> {
    let mut hdr = [0u8; 512];
    if !crate::drivers::read(global_idx, 1, 1, &mut hdr) { return None; }
    if &hdr[0..8] != b"EFI PART" {
        let end = crate::drivers::disk_info(global_idx)?.sectors;
        return Some((LBA_BASE, end, false));
    }
    let ent_lba = u64::from_le_bytes(hdr[72..80].try_into().ok()?);
    let n_ent   = u32::from_le_bytes(hdr[80..84].try_into().ok()?).min(128) as u64;
    let ent_sz  = u32::from_le_bytes(hdr[84..88].try_into().ok()?) as u64;
    if ent_sz != 128 { return None; }
    let mut sec = [0u8; 512];
    for i in 0..n_ent {
        if i % 4 == 0 && !crate::drivers::read(global_idx, ent_lba + i / 4, 1, &mut sec) { return None; }
        let o = (i % 4) as usize * 128;
        let e = &sec[o..o + 128];
        if e[0..16] != ROOT_TYPE_GUID { continue; }
        // Partition name (UTF-16LE) must start with "AETERNA"
        let named = b"AETERNA".iter().enumerate().all(|(k, &c)| e[56 + k * 2] == c && e[57 + k * 2] == 0);
        if !named { continue; }
        let start = u64::from_le_bytes(e[32..40].try_into().ok()?);
        let end   = u64::from_le_bytes(e[40..48].try_into().ok()?);
        if end > start + ROOT_SKIP + LEGACY_SECTORS { return Some((start + ROOT_SKIP, end + 1, true)); }
        return None;
    }
    None
}

/// First LBA of the old snapshot area on disk `global_idx`.
///
/// * No GPT (blank or raw disk): LBA 2048.
/// * GPT with an "AETERNA" root partition (written by `install`): inside that partition,
///   so nothing lands on the ESP's FAT32 boot sector, which also sits at LBA 2048.
/// * Any other GPT disk: None, persistence is disabled rather than overwriting someone
///   else's partition.
pub fn base_lba(global_idx: usize) -> Option<u64> {
    locate(global_idx).map(|l| l.0)
}

/// Where the persistent AeternaFS v2 volume of a disk lives.
#[derive(Clone, Copy, Debug)]
pub struct Area {
    /// Old snapshot area (read once for migration).
    pub legacy_lba: u64,
    /// First sector of the v2 volume (multiple of 8).
    pub v2_lba: u64,
    /// Sectors of the v2 volume (multiple of 8).
    pub v2_sectors: u64,
    /// The area is inside a GPT partition named AETERNA (not a raw disk).
    pub gpt: bool,
}

pub fn area(global_idx: usize) -> Option<Area> {
    let (base, end, gpt) = locate(global_idx)?;
    let v2_lba = (base + LEGACY_SECTORS + 7) & !7;
    if end <= v2_lba { return None; }
    let v2_sectors = (end - v2_lba) & !7;
    if v2_sectors < MIN_V2_SECTORS { return None; }
    Some(Area { legacy_lba: base, v2_lba, v2_sectors, gpt })
}

// ─── Old snapshot: deserialization ──────────────────────────────────────────

/// Deserialize an old snapshot blob into a tree.
/// Returns None if the magic or version is invalid.
pub fn deserialize_ramfs(buf: &[u8]) -> Option<BTreeMap<String, RamNode>> {
    // Header: SUPER_MAGIC(8) + sector_count(4) + MAGIC(10) + VERSION(4) + COUNT(4)
    let hdr_min = 8 + 4 + MAGIC.len() + 4 + 4;
    if buf.len() < hdr_min { return None; }

    if u64::from_le_bytes(buf[0..8].try_into().ok()?) != SUPER_MAGIC { return None; }
    let mut cursor = 8 + 4;
    if &buf[cursor..cursor + MAGIC.len()] != MAGIC { return None; }
    cursor += MAGIC.len();

    let version = u32::from_le_bytes(buf[cursor..cursor + 4].try_into().ok()?);
    cursor += 4;
    if version != VERSION { return None; }

    let count = u32::from_le_bytes(buf[cursor..cursor + 4].try_into().ok()?);
    cursor += 4;

    let mut tree: BTreeMap<String, RamNode> = BTreeMap::new();

    for _ in 0..count {
        if cursor + 2 > buf.len() { break; }
        let path_len = u16::from_le_bytes(buf[cursor..cursor + 2].try_into().ok()?) as usize;
        cursor += 2;
        if cursor + path_len > buf.len() { break; }
        let path = match core::str::from_utf8(&buf[cursor..cursor + path_len]) {
            Ok(s) => String::from(s),
            Err(_) => break,
        };
        cursor += path_len;
        if cursor >= buf.len() { break; }
        let tag = buf[cursor];
        cursor += 1;
        match tag {
            TAG_DIR => {
                tree.insert(path, RamNode::Dir);
            }
            TAG_FILE => {
                if cursor + 4 > buf.len() { break; }
                let data_len = u32::from_le_bytes(buf[cursor..cursor + 4].try_into().ok()?) as usize;
                cursor += 4;
                if cursor + data_len > buf.len() { break; }
                let data = buf[cursor..cursor + data_len].to_vec();
                cursor += data_len;
                tree.insert(path, RamNode::File(data));
            }
            _ => break, // unknown tag: corrupt data
        }
    }

    Some(tree)
}

// ─── Old snapshot: disk I/O ──────────────────────────────────────────────────

/// Read the old snapshot blob from disk (None if there is none).
/// Reads the first sector for the magic and the sector count, then the rest in batches.
pub fn read_from_disk() -> Option<Vec<u8>> {
    let (global_idx, _kind, _per_kind_idx) = select_disk()?;
    let base = base_lba(global_idx)?;

    let mut hdr = [0u8; 512];
    if !crate::drivers::read(global_idx, base, 1, &mut hdr) {
        crate::arch::x86_64::serial::write_str("[FS] read header sector failed\r\n");
        return None;
    }
    if u64::from_le_bytes(hdr[0..8].try_into().ok()?) != SUPER_MAGIC {
        return None;
    }
    let sector_count = u32::from_le_bytes(hdr[8..12].try_into().ok()?);
    if sector_count == 0 || sector_count as usize > MAX_FS_BYTES / 512 {
        crate::arch::x86_64::serial::write_str("[FS] invalid sector_count in the old snapshot\r\n");
        return None;
    }

    let total = sector_count as usize * 512;
    let mut buf: Vec<u8> = alloc::vec![0u8; total];
    const BATCH: u32 = 128;
    let mut done = 0u32;
    while done < sector_count {
        let batch = (sector_count - done).min(BATCH);
        let off = done as usize * 512;
        let end = off + batch as usize * 512;
        if !crate::drivers::read(global_idx, base + done as u64, batch, &mut buf[off..end]) {
            crate::arch::x86_64::serial::write_str("[FS] old snapshot: batch read failed\r\n");
            return None;
        }
        done += batch;
    }
    Some(buf)
}

// ─── Entry points of the persistent layer ───────────────────────────────────

/// Called by the RamFS on every change of the boot-time layer. The persistent layer tracks
/// its own changes, so there is nothing to record here any more.
#[inline]
pub fn mark_dirty_at_tick() {}

/// Kernel parameter `persist=ro` (and the installer): never write the persistent volume.
static READ_ONLY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn set_read_only(on: bool) {
    READ_ONLY.store(on, core::sync::atomic::Ordering::Relaxed);
}

pub fn is_read_only() -> bool {
    READ_ONLY.load(core::sync::atomic::Ordering::Relaxed)
}

/// Are there changes that are not committed to disk yet?
#[inline]
pub fn is_dirty() -> bool {
    super::aeternafs::any_dirty()
}

/// Commit the persistent volume now (`sync`). Returns true when nothing is left uncommitted.
pub fn sync_filesystem() -> bool {
    super::aeternafs::sync_all()
}

/// Time-based commit. Called from the shell idle loop and from the commit thread.
pub fn deferred_tick() {
    super::aeternafs::tick();
}
