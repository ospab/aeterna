/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
mkimage — build a GPT disk image with one FAT32 EFI System Partition and, with --bios, a BIOS boot
partition (LBA 34..2047) plus stage 1 in the MBR, so the image boots on BIOS and UEFI.

No dependencies and no cargo project on purpose: build it with plain rustc on the
host (Windows or Linux), so it does not inherit the kernel's .cargo/config.toml:

    rustc -O --edition 2021 tools/mkimage.rs -o target/mkimage(.exe)
    mkimage out.img [--size-mib N] [--bios bios.img] DEST=SRC [DEST=SRC ...]

bios.img comes from scripts/bios-image.sh (stage 1 at offset 0, stage 2 at 0x800).

DEST is a path inside the ESP ("EFI/BOOT/BOOTX64.EFI"); every component must be a
valid 8.3 name. All-lowercase names keep their case (NT case bits), so firmware
and Windows show "boot/ospab.cfg" as written.
*/
use std::collections::BTreeMap;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

const SECTOR: usize = 512;
const PART_START: u64 = 2048; // 1 MiB alignment
const GPT_ENTRIES: usize = 128;
const GPT_ENTRY_SIZE: usize = 128;
const GPT_ENTRY_SECTORS: u64 = (GPT_ENTRIES * GPT_ENTRY_SIZE / SECTOR) as u64;
const RESERVED_SECTORS: u32 = 32;
const ESP_TYPE: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
const BIOS_BOOT_TYPE: &str = "21686148-6449-6E6F-744E-656564454649";
/// BIOS boot partition: the gap between the GPT and the ESP (LBA 34..2047, 503 KiB).
const BIOS_PART_START: u64 = 2 + GPT_ENTRY_SECTORS;
const BIOS_PART_END: u64 = PART_START - 1;

enum Node {
    Dir(BTreeMap<String, Node>),
    File(Vec<u8>),
}

fn die(msg: &str) -> ! {
    eprintln!("mkimage: {}", msg);
    exit(1)
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn put16(b: &mut [u8], o: usize, v: u16) { b[o..o + 2].copy_from_slice(&v.to_le_bytes()); }
fn put32(b: &mut [u8], o: usize, v: u32) { b[o..o + 4].copy_from_slice(&v.to_le_bytes()); }
fn put64(b: &mut [u8], o: usize, v: u64) { b[o..o + 8].copy_from_slice(&v.to_le_bytes()); }

/// GUID text → on-disk mixed-endian bytes.
fn guid_bytes(s: &str) -> [u8; 16] {
    let hex: Vec<u8> = s
        .chars()
        .filter(|c| *c != '-')
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|p| u8::from_str_radix(&p.iter().collect::<String>(), 16).unwrap())
        .collect();
    let mut g = [0u8; 16];
    g[0..4].copy_from_slice(&[hex[3], hex[2], hex[1], hex[0]]);
    g[4..6].copy_from_slice(&[hex[5], hex[4]]);
    g[6..8].copy_from_slice(&[hex[7], hex[6]]);
    g[8..16].copy_from_slice(&hex[8..16]);
    g
}

/// Version-4-style GUID from a simple xorshift seeded by the clock and a salt.
fn random_guid(salt: u64) -> [u8; 16] {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1);
    let mut x = t ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut g = [0u8; 16];
    for b in g.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    g[7] = (g[7] & 0x0F) | 0x40;
    g[8] = (g[8] & 0x3F) | 0x80;
    g
}

/// 8.3 short name (11 bytes, space padded) + NT case flags.
fn short_name(name: &str) -> ([u8; 11], u8) {
    let (base, ext) = match name.rfind('.') {
        Some(i) => (&name[..i], &name[i + 1..]),
        None => (name, ""),
    };
    let ok = |s: &str, max: usize| {
        s.len() <= max && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"_-~!#$%&'()@^`{}".contains(&c))
    };
    if base.is_empty() || !ok(base, 8) || !ok(ext, 3) {
        die(&format!("'{}' is not a valid 8.3 name", name));
    }
    let mut flags = 0u8;
    for (part, bit) in [(base, 0x08u8), (ext, 0x10u8)] {
        let has_lower = part.bytes().any(|c| c.is_ascii_lowercase());
        let has_upper = part.bytes().any(|c| c.is_ascii_uppercase());
        if has_lower && has_upper {
            die(&format!("'{}' mixes upper and lower case (no long names)", name));
        }
        if has_lower {
            flags |= bit;
        }
    }
    let mut out = [b' '; 11];
    for (i, c) in base.bytes().enumerate() {
        out[i] = c.to_ascii_uppercase();
    }
    for (i, c) in ext.bytes().enumerate() {
        out[8 + i] = c.to_ascii_uppercase();
    }
    (out, flags)
}

// ─── FAT32 ──────────────────────────────────────────────────────────────────

struct Fat {
    spc: u32, // sectors per cluster
    clusters: u32,
    next_free: u32,
    fat: Vec<u32>,
}

impl Fat {
    fn cluster_bytes(&self) -> usize { self.spc as usize * SECTOR }

    /// Reserve `n` contiguous clusters and chain them; returns the first (0 if n = 0).
    fn alloc(&mut self, n: usize) -> u32 {
        if n == 0 {
            return 0;
        }
        let first = self.next_free;
        if (first as u64 + n as u64) > self.clusters as u64 + 2 {
            die("image too small for the files (use --size-mib)");
        }
        for i in 0..n as u32 {
            self.fat[(first + i) as usize] = if i + 1 == n as u32 { 0x0FFF_FFFF } else { first + i + 1 };
        }
        self.next_free += n as u32;
        first
    }
}

/// Layout pass: clusters for every directory and file. Returns the first cluster
/// per node in visiting order.
fn assign(node: &Node, is_root: bool, fat: &mut Fat, out: &mut Vec<u32>) {
    match node {
        Node::File(data) => {
            let cb = fat.cluster_bytes();
            out.push(fat.alloc((data.len() + cb - 1) / cb));
        }
        Node::Dir(children) => {
            let entries = children.len() + if is_root { 0 } else { 2 };
            let cb = fat.cluster_bytes();
            out.push(fat.alloc(((entries * 32 + cb - 1) / cb).max(1)));
            for child in children.values() {
                assign(child, false, fat, out);
            }
        }
    }
}

fn dir_entry(name: &[u8; 11], case: u8, attr: u8, cluster: u32, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0..11].copy_from_slice(name);
    e[11] = attr;
    e[12] = case;
    let date: u16 = ((2026 - 1980) << 9) | (1 << 5) | 1;
    put16(&mut e, 16, date); // created
    put16(&mut e, 18, date); // accessed
    put16(&mut e, 20, (cluster >> 16) as u16);
    put16(&mut e, 24, date); // modified
    put16(&mut e, 26, cluster as u16);
    put32(&mut e, 28, size);
    e
}

/// Write pass: same visiting order as `assign`.
fn write_node(node: &Node, parent: u32, clusters: &[u32], idx: &mut usize, data_area: &mut [u8], fat: &Fat, is_root: bool) {
    let my = clusters[*idx];
    *idx += 1;
    let off = |c: u32| (c as usize - 2) * fat.cluster_bytes();
    match node {
        Node::File(bytes) => {
            if my != 0 {
                data_area[off(my)..off(my) + bytes.len()].copy_from_slice(bytes);
            }
        }
        Node::Dir(children) => {
            let mut entries: Vec<[u8; 32]> = Vec::new();
            if !is_root {
                entries.push(dir_entry(b".          ", 0, 0x10, my, 0));
                entries.push(dir_entry(b"..         ", 0, 0x10, parent, 0));
            }
            // Children's first clusters follow in visiting order; walk them.
            let mut child_idx = *idx;
            for (name, child) in children {
                let (sn, case) = short_name(name);
                let c = clusters[child_idx];
                match child {
                    Node::File(b) => entries.push(dir_entry(&sn, case, 0x20, c, b.len() as u32)),
                    Node::Dir(_) => entries.push(dir_entry(&sn, case, 0x10, c, 0)),
                }
                child_idx += count(child);
            }
            let base = off(my);
            for (i, e) in entries.iter().enumerate() {
                data_area[base + i * 32..base + i * 32 + 32].copy_from_slice(e);
            }
            let parent_for_children = if is_root { 0 } else { my };
            for child in children.values() {
                write_node(child, parent_for_children, clusters, idx, data_area, fat, false);
            }
        }
    }
}

fn count(node: &Node) -> usize {
    match node {
        Node::File(_) => 1,
        Node::Dir(c) => 1 + c.values().map(count).sum::<usize>(),
    }
}

fn total_size(node: &Node) -> usize {
    match node {
        Node::File(d) => d.len() + 4096,
        Node::Dir(c) => 4096 + c.values().map(total_size).sum::<usize>(),
    }
}

/// Format `part` (the partition bytes) as FAT32 holding `root`.
fn build_fat32(part: &mut [u8], root: &Node, serial: u32) {
    let total = (part.len() / SECTOR) as u32;
    // 512-byte clusters keep small images valid FAT32 (>= 65525 clusters);
    // bigger volumes use 4 KiB clusters.
    let spc: u32 = if total >= 1_048_576 { 8 } else { 1 };
    let mut fat_sectors = 1u32;
    loop {
        let data = total - RESERVED_SECTORS - 2 * fat_sectors;
        let clusters = data / spc;
        let need = ((clusters as u64 + 2) * 4 + SECTOR as u64 - 1) / SECTOR as u64;
        if need as u32 <= fat_sectors {
            break;
        }
        fat_sectors = need as u32;
    }
    let clusters = (total - RESERVED_SECTORS - 2 * fat_sectors) / spc;
    if clusters < 65525 {
        die("partition too small for FAT32 (need about 33 MiB or more)");
    }
    let mut fat = Fat { spc, clusters, next_free: 2, fat: vec![0; clusters as usize + 2] };
    fat.fat[0] = 0x0FFF_FFF8;
    fat.fat[1] = 0x0FFF_FFFF;

    let mut firsts = Vec::new();
    assign(root, true, &mut fat, &mut firsts);
    assert_eq!(firsts[0], 2, "root directory must start at cluster 2");

    // Boot sector.
    let bs = &mut part[0..SECTOR];
    bs[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    bs[3..11].copy_from_slice(b"MSWIN4.1");
    put16(bs, 11, SECTOR as u16);
    bs[13] = spc as u8;
    put16(bs, 14, RESERVED_SECTORS as u16);
    bs[16] = 2; // FATs
    bs[21] = 0xF8; // fixed media
    put16(bs, 24, 63);
    put16(bs, 26, 255);
    put32(bs, 28, PART_START as u32); // hidden sectors
    put32(bs, 32, total);
    put32(bs, 36, fat_sectors);
    put32(bs, 44, 2); // root cluster
    put16(bs, 48, 1); // FSInfo
    put16(bs, 50, 6); // backup boot sector
    bs[64] = 0x80;
    bs[66] = 0x29;
    put32(bs, 67, serial);
    bs[71..82].copy_from_slice(b"OSPAB ESP  ");
    bs[82..90].copy_from_slice(b"FAT32   ");
    bs[510] = 0x55;
    bs[511] = 0xAA;
    let boot = bs.to_vec();
    part[6 * SECTOR..7 * SECTOR].copy_from_slice(&boot);

    // FSInfo (+ backup).
    let free = clusters + 2 - fat.next_free;
    let mut fsinfo = vec![0u8; SECTOR];
    put32(&mut fsinfo, 0, 0x4161_5252);
    put32(&mut fsinfo, 484, 0x6141_7272);
    put32(&mut fsinfo, 488, free);
    put32(&mut fsinfo, 492, fat.next_free);
    put32(&mut fsinfo, 508, 0xAA55_0000);
    part[SECTOR..2 * SECTOR].copy_from_slice(&fsinfo);
    part[7 * SECTOR..8 * SECTOR].copy_from_slice(&fsinfo);

    // FATs.
    for copy in 0..2 {
        let base = (RESERVED_SECTORS + copy * fat_sectors) as usize * SECTOR;
        for (i, v) in fat.fat.iter().enumerate() {
            put32(part, base + i * 4, *v);
        }
    }

    // Data.
    let data_start = (RESERVED_SECTORS + 2 * fat_sectors) as usize * SECTOR;
    let mut idx = 0;
    write_node(root, 0, &firsts, &mut idx, &mut part[data_start..], &fat, true);
}

// ─── GPT ────────────────────────────────────────────────────────────────────

fn write_gpt(img: &mut [u8], part_end: u64, bios_part: bool) {
    let sectors = (img.len() / SECTOR) as u64;

    // Protective MBR.
    let mbr = &mut img[0..SECTOR];
    mbr[446 + 1..446 + 4].copy_from_slice(&[0x00, 0x02, 0x00]);
    mbr[446 + 4] = 0xEE;
    mbr[446 + 5..446 + 8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    put32(mbr, 446 + 8, 1);
    put32(mbr, 446 + 12, (sectors - 1).min(0xFFFF_FFFF) as u32);
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    // Partition entries.
    let mut entries = vec![0u8; GPT_ENTRIES * GPT_ENTRY_SIZE];
    entries[0..16].copy_from_slice(&guid_bytes(ESP_TYPE));
    entries[16..32].copy_from_slice(&random_guid(1));
    put64(&mut entries, 32, PART_START);
    put64(&mut entries, 40, part_end);
    for (i, c) in "EFI System Partition".encode_utf16().enumerate() {
        put16(&mut entries, 56 + i * 2, c);
    }
    if bios_part {
        entries[128..144].copy_from_slice(&guid_bytes(BIOS_BOOT_TYPE));
        entries[144..160].copy_from_slice(&random_guid(4));
        put64(&mut entries, 128 + 32, BIOS_PART_START);
        put64(&mut entries, 128 + 40, BIOS_PART_END);
        for (i, c) in "BIOS boot".encode_utf16().enumerate() {
            put16(&mut entries, 128 + 56 + i * 2, c);
        }
    }
    let entries_crc = crc32(&entries);
    let disk_guid = random_guid(2);

    let backup_entries_lba = sectors - 1 - GPT_ENTRY_SECTORS;
    for (my_lba, alt_lba, entries_lba) in [(1, sectors - 1, 2), (sectors - 1, 1, backup_entries_lba)] {
        let mut h = vec![0u8; SECTOR];
        h[0..8].copy_from_slice(b"EFI PART");
        put32(&mut h, 8, 0x0001_0000);
        put32(&mut h, 12, 92);
        put64(&mut h, 24, my_lba);
        put64(&mut h, 32, alt_lba);
        put64(&mut h, 40, 2 + GPT_ENTRY_SECTORS); // first usable
        put64(&mut h, 48, backup_entries_lba - 1); // last usable
        h[56..72].copy_from_slice(&disk_guid);
        put64(&mut h, 72, entries_lba);
        put32(&mut h, 80, GPT_ENTRIES as u32);
        put32(&mut h, 84, GPT_ENTRY_SIZE as u32);
        put32(&mut h, 88, entries_crc);
        let crc = crc32(&h[0..92]);
        put32(&mut h, 16, crc);
        let at = my_lba as usize * SECTOR;
        img[at..at + SECTOR].copy_from_slice(&h);
        let e = entries_lba as usize * SECTOR;
        img[e..e + entries.len()].copy_from_slice(&entries);
    }
}

// ─── main ───────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0].starts_with('-') {
        die("usage: mkimage OUT.img [--size-mib N] [--bios BIOS.IMG] DEST=SRC ...");
    }
    let out = &args[0];
    let mut size_mib: Option<u64> = None;
    let mut bios: Option<Vec<u8>> = None;
    let mut root = Node::Dir(BTreeMap::new());
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--size-mib" {
            size_mib = Some(args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or_else(|| die("bad --size-mib")));
            i += 2;
            continue;
        }
        if args[i] == "--bios" {
            let p = args.get(i + 1).unwrap_or_else(|| die("--bios needs a file"));
            bios = Some(std::fs::read(p).unwrap_or_else(|e| die(&format!("{}: {}", p, e))));
            i += 2;
            continue;
        }
        let (dest, src) = args[i].split_once('=').unwrap_or_else(|| die(&format!("expected DEST=SRC: {}", args[i])));
        let data = std::fs::read(src).unwrap_or_else(|e| die(&format!("{}: {}", src, e)));
        let parts: Vec<&str> = dest.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
        let mut node = &mut root;
        for (n, part) in parts.iter().enumerate() {
            short_name(part); // validate early
            let Node::Dir(children) = node else { die(&format!("{}: parent is a file", dest)) };
            if n + 1 == parts.len() {
                children.insert(part.to_string(), Node::File(data));
                break;
            }
            node = children.entry(part.to_string()).or_insert_with(|| Node::Dir(BTreeMap::new()));
        }
        i += 1;
    }

    // Default: content + slack, at least 64 MiB (FAT32 needs ~33 MiB).
    let need_mib = (total_size(&root) as u64 * 5 / 4) / (1 << 20) + 16;
    let size_mib = size_mib.unwrap_or(need_mib.max(64));
    let sectors = size_mib * 2048;
    let part_end = sectors - 1 - GPT_ENTRY_SECTORS - 1; // inclusive
    let mut img = vec![0u8; sectors as usize * SECTOR];

    let serial = random_guid(3);
    let serial = u32::from_le_bytes([serial[0], serial[1], serial[2], serial[3]]);
    let p0 = PART_START as usize * SECTOR;
    let p1 = (part_end as usize + 1) * SECTOR;
    build_fat32(&mut img[p0..p1], &root, serial);
    if let Some(b) = &bios {
        // stage1 into the MBR (the partition table area is written by write_gpt), stage2 into the
        // BIOS boot partition; stage1 learns where stage2 is at offset 0x40.
        if b.len() < 0x800 + 512 || b[510] != 0x55 || b[511] != 0xAA {
            die("--bios: not a bios.img (scripts/bios-image.sh)");
        }
        let stage2 = &b[0x800..];
        if stage2.len() as u64 > (BIOS_PART_END - BIOS_PART_START + 1) * SECTOR as u64 {
            die("--bios: stage2 does not fit into the BIOS boot partition");
        }
        img[0..446].copy_from_slice(&b[0..446]);
        put64(&mut img, 0x40, BIOS_PART_START);
        let at = BIOS_PART_START as usize * SECTOR;
        img[at..at + stage2.len()].copy_from_slice(stage2);
    }
    write_gpt(&mut img, part_end, bios.is_some());

    std::fs::write(out, &img).unwrap_or_else(|e| die(&format!("{}: {}", out, e)));
    println!("mkimage: {} ({} MiB, GPT + FAT32 ESP{})", out, size_mib, if bios.is_some() { " + BIOS boot partition" } else { "" });
}
