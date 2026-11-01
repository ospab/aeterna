/*
 * disk_tools — GPT-aware fdisk, NVMe lsblk extension, and mkfs.aeterna
 *
 * BSL 1.1 — Copyright (c) 2026 ospab
 *
 * run_fdisk(args)   — list all disks (AHCI + NVMe) with GPT partition tables
 * run_lsblk(args)   — list all block devices including NVMe
 * run_mkfs(args)    — format a partition with AeternaFS
 *
 * All output goes through plum::io (stdout/stderr can be piped or redirected).
 */

#![allow(dead_code)]

extern crate alloc;


const FG: u32     = 0x00FFFFFF;
const FG_OK: u32  = 0x0000FF00;
const FG_ERR: u32 = 0x00FF4444;
const FG_DIM: u32 = 0x00AAAAAA;
const FG_HL: u32  = 0x00FFCC00;
const FG_DIR: u32 = 0x005555FF;
const BG: u32     = 0x00000000;

fn puts(s: &str)  { crate::userspace::plum::io::out_c(s, FG); }
fn ok(s: &str)    { crate::userspace::plum::io::out_c(s, FG_OK); }
fn err(s: &str)   { crate::userspace::plum::io::err(s); }
fn dim(s: &str)   { crate::userspace::plum::io::out_c(s, FG_DIM); }
fn hl(s: &str)    { crate::userspace::plum::io::out_c(s, FG_HL); }

fn put_u64(mut n: u64) {
    if n == 0 { puts("0"); return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    for j in (0..i).rev() { { let mut cb = [0u8; 4]; crate::userspace::plum::io::out_c((buf[j] as char).encode_utf8(&mut cb), FG); }; }
}

fn put_u64_col(mut n: u64, col: u32) {
    if n == 0 { { let mut cb = [0u8; 4]; crate::userspace::plum::io::out_c(('0').encode_utf8(&mut cb), col); }; return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    for j in (0..i).rev() { { let mut cb = [0u8; 4]; crate::userspace::plum::io::out_c((buf[j] as char).encode_utf8(&mut cb), col); }; }
}

fn put_size_mib(mib: u64) {
    if mib >= 1024 {
        let gib = mib / 1024;
        let frac = (mib % 1024) * 10 / 1024;
        put_u64(gib); puts("."); put_u64(frac); puts(" GiB");
    } else {
        put_u64(mib); puts(" MiB");
    }
}

// ─── fdisk ────────────────────────────────────────────────────────────────

/// `fdisk [-l]` — list all disks and GPT partition tables.
pub fn run_fdisk(args: &str) {
    if !args.is_empty() && args != "-l" {
        err("fdisk: unknown option\n");
        dim("Usage: fdisk -l\n");
        return;
    }

    let mut found_any = false;

    // ── All disks (ATA, AHCI, NVMe, virtio-blk) ──────────────────────────
    let n = crate::drivers::disk_count();
    for i in 0..n {
        if let Some(d) = crate::drivers::disk_info(i) {
            found_any = true;
            let dev_name = crate::drivers::dev_name_for_index(i);
            let is_nvme = d.kind == crate::drivers::DiskKind::Nvme;
            let psep = if is_nvme { "p" } else { "" };
            // GPT of an NVMe disk is read in the namespace's native LBA size
            let ss: u64 = if is_nvme { crate::drivers::nvme::sector_size() as u64 } else { 512 };
            hl("Disk /dev/");
            hl(dev_name);
            puts(": ");
            put_size_mib(d.size_mb as u64);
            puts(", ");
            put_u64(d.size_mb as u64 * 1024 * 1024);
            puts(" bytes, ");
            put_u64(d.sectors * 512 / ss);
            puts(" sectors\n");
            puts("Disk model: ");
            puts(crate::drivers::model_str(d));
            puts("\n");
            dim("Units: sectors of ");
            put_u64(ss);
            puts(" bytes\n");

            // Read the GPT
            let pc = if is_nvme {
                let mut nd = crate::drivers::block::NvmeDisk::new();
                crate::drivers::gpt::parse(&mut nd).unwrap_or(0)
            } else {
                let mut ad = crate::drivers::block::AhciDisk { disk_idx: i };
                crate::drivers::gpt::parse(&mut ad).unwrap_or(0)
            };
            if pc == 0 {
                dim("Partition table type: none\n\n");
            } else {
                dim("Partition table type: GPT\n");
                puts("Device\t\t\tStart\t\tEnd\t\tSize\tType\n");
                dim("─────────────────────────────────────────────────────────\n");
                for j in 0..pc {
                    if let Some(part) = crate::drivers::gpt::get_partition(j) {
                        puts("/dev/");
                        puts(dev_name);
                        puts(psep);
                        put_u64((j + 1) as u64);
                        puts("\t");
                        put_u64(part.start_lba);
                        puts("\t\t");
                        put_u64(part.end_lba);
                        puts("\t\t");
                        let size_sec = part.end_lba.saturating_sub(part.start_lba) + 1;
                        let size_mib = size_sec * ss / (1024 * 1024);
                        put_size_mib(size_mib);
                        puts("\t");
                        puts(guid_type_label(&part.type_guid));
                        if !part.name.is_empty() {
                            puts(" ("); puts(&part.name); puts(")");
                        }
                        puts("\n");
                    }
                }
                puts("\n");
            }
        }
    }

    if !found_any {
        dim("No block devices found.\n");
        dim("Attach a disk: QEMU -drive file=disk.img,format=raw,if=none,id=d0\n");
        dim("               -device ahci,id=ahci0 -device ide-hd,drive=d0,bus=ahci0.0\n");
    }
}

// ─── lsblk ───────────────────────────────────────────────────────────────

/// Extended `lsblk` with NVMe support.
pub fn run_lsblk(_args: &str) {
    if crate::drivers::disk_count() == 0 {
        puts("lsblk: no block devices found\n");
        return;
    }
    puts("NAME           TYPE    SIZE       RO  MODEL\n");
    dim("──────────────────────────────────────────────────────────\n");

    // All disks
    let n = crate::drivers::disk_count();
    for i in 0..n {
        if let Some(d) = crate::drivers::disk_info(i) {
            let base_name = crate::drivers::dev_name_for_index(i);
            let kind_s = match d.kind {
                crate::drivers::DiskKind::Ahci   => "SATA  ",
                crate::drivers::DiskKind::Ata    => "IDE   ",
                crate::drivers::DiskKind::Nvme   => "NVMe  ",
                crate::drivers::DiskKind::Virtio => "virtio",
            };
            puts(base_name);
            puts("             ");
            puts(kind_s);
            puts("  ");
            put_size_mib(d.size_mb as u64);
            puts("   0   ");
            puts(crate::drivers::model_str(d));
            puts("\n");

            // NVMe partitions come from the GPT parsed at boot / by fdisk
            if d.kind == crate::drivers::DiskKind::Nvme {
                let ss = crate::drivers::nvme::sector_size() as u64;
                for pi in 0..crate::drivers::gpt::partition_count() {
                    if let Some(part) = crate::drivers::gpt::get_partition(pi) {
                        puts("  nvme0n1p");
                        put_u64((pi + 1) as u64);
                        puts("      part    ");
                        let psize = (part.end_lba.saturating_sub(part.start_lba) + 1) * ss;
                        put_size_mib(psize / (1024 * 1024));
                        puts("   0   ");
                        if !part.name.is_empty() { puts(&part.name); }
                        puts("\n");
                    }
                }
            }
        }
    }
}

// ─── mkfs ─────────────────────────────────────────────────────────────────

/// `mkfs.aeterna <device> [label]`
/// Formats the given block device (partition) with AeternaFS.
///
/// Examples:
///   mkfs /dev/nvme0n1p1
///   mkfs /dev/nvme0n1p1 MYPART
///
pub fn run_mkfs(args: &str) {
    let mut tokens = args.splitn(3, ' ');
    let device = match tokens.next() {
        Some(d) if !d.is_empty() => d.trim(),
        _ => {
            err("mkfs: missing device\n");
            dim("Usage: mkfs <device> [label]\n");
            dim("       mkfs /dev/nvme0n1p1\n");
            dim("       mkfs /dev/nvme0n1p1 MYPART\n");
            return;
        }
    };
    let label = tokens.next().unwrap_or("AETERNA").trim();
    let label = if label.is_empty() { "AETERNA" } else { label };

    puts("mkfs.aeterna: formatting ");
    puts(device);
    puts(" with label '");
    puts(label);
    puts("'\n");

    let (disk, start, sectors) = match resolve_partition(device, "mkfs") {
        Some(t) => t,
        None => return,
    };
    // Never format the volume that holds `/`.
    if let Some(v) = crate::fs::aeternafs::root_volume() {
        if let Some(a) = crate::fs::disk_sync::area(v.disk_index()) {
            if v.disk_index() == disk && start < a.v2_lba + a.v2_sectors && start + sectors > a.legacy_lba {
                err("mkfs: this partition holds the running system's files\n");
                return;
            }
        }
    }
    match crate::fs::aeternafs::mkfs(disk, start, sectors, label) {
        Ok(()) => {
            ok("[AeternaFS v2] Format successful\n");
            puts("  Label:     "); puts(label); puts("\n");
            puts("  Device:    "); puts(device); puts("\n");
            puts("  Start LBA: "); put_u64(start); puts("\n");
            puts("  Sectors:   "); put_u64(sectors); puts("\n");
            dim("Mount it with `mount <device> <mountpoint>`.\n");
        }
        Err(e) => {
            err("mkfs: format failed: ");
            err(&alloc::format!("{}\n", e));
        }
    }
}

/// `/dev/nvme0n1pN`, `/dev/sdaN`, `/dev/vdaN`, `/dev/hdaN` -> (disk index, first sector,
/// sectors) in 512-byte units, from the GPT of that disk.
fn resolve_partition(device: &str, who: &str) -> Option<(usize, u64, u64)> {
    if device.starts_with("/dev/nvme0n1p") {
        let part_num = match parse_usize(&device["/dev/nvme0n1p".len()..]) {
            Some(n) if n >= 1 => n,
            _ => { err(who); err(": invalid partition number\n"); return None; }
        };
        let disk = (0..crate::drivers::disk_count()).find(|&i| {
            crate::drivers::disk_info(i).map_or(false, |d| d.kind == crate::drivers::DiskKind::Nvme)
        });
        let disk = match disk { Some(d) => d, None => { err(who); err(": no NVMe disk\n"); return None; } };
        let part = match crate::drivers::gpt::get_partition(part_num - 1) {
            Some(p) => p,
            None => {
                err(who); err(": partition not found in GPT\n");
                dim("Tip: run `fdisk -l` to list available partitions\n");
                return None;
            }
        };
        // GPT LBAs of an NVMe namespace are in its own sector size; the drivers use 512.
        let mul = (crate::drivers::nvme::sector_size() / 512) as u64;
        let first = part.start_lba * mul;
        let count = (part.end_lba.saturating_sub(part.start_lba) + 1) * mul;
        return Some((disk, first, count));
    }
    if let Some(name) = device.strip_prefix("/dev/") {
        let (disk_name, part_str) = split_dev_name(name);
        let disk = match ahci_name_to_idx(disk_name) {
            Some(i) => i,
            None => { err(who); err(": unknown device (supported: /dev/nvme0n1pN, /dev/sdaN, /dev/vdaN, /dev/hdaN)\n"); return None; }
        };
        let part_num = match parse_usize(part_str) {
            Some(n) if n >= 1 => n,
            _ => { err(who); err(": invalid partition number\n"); return None; }
        };
        let mut dev = crate::drivers::block::AhciDisk { disk_idx: disk };
        if crate::drivers::gpt::parse(&mut dev).unwrap_or(0) == 0 {
            err(who); err(": no GPT found on the disk\n");
            return None;
        }
        let part = match crate::drivers::gpt::get_partition(part_num - 1) {
            Some(p) => p,
            None => { err(who); err(": partition index out of range\n"); return None; }
        };
        return Some((disk, part.start_lba, part.end_lba.saturating_sub(part.start_lba) + 1));
    }
    err(who);
    err(": unrecognized device path\n");
    dim("Supported: /dev/nvme0n1pN  /dev/sdaN  /dev/vdaN  /dev/hdaN\n");
    None
}

// ─── mount helper (called after mkfs or at boot) ──────────────────────────

/// `mount <device> <mountpoint>`
pub fn run_mount(args: &str) {
    let mut toks = args.split_whitespace();
    let device = match toks.next() {
        Some(d) => d,
        None => { show_volumes(); return; }
    };
    let mountpoint = match toks.next() {
        Some(m) if m.starts_with('/') => m,
        _ => { err("mount: usage: mount [<device> <mountpoint>]\n"); return; }
    };
    let (disk, start, sectors) = match resolve_partition(device, "mount") {
        Some(t) => t,
        None => return,
    };
    // The running system's own volume is already mounted below `/`.
    if let Some(v) = crate::fs::aeternafs::root_volume() {
        if let Some(a) = crate::fs::disk_sync::area(v.disk_index()) {
            if v.disk_index() == disk && start < a.v2_lba + a.v2_sectors && start + sectors > a.legacy_lba {
                err("mount: this partition holds the running system's files (already in use for /)\n");
                return;
            }
        }
    }
    if !crate::fs::aeternafs::has_v2_magic(disk, start) {
        err("mount: no AeternaFS v2 volume there; format it with `mkfs` first\n");
        return;
    }
    match crate::fs::aeternafs::mount_raw(disk, start, sectors) {
        Ok(vol) => {
            let fs = crate::fs::aeternafs::AeFs::register(vol, "aeternafs", disk, false);
            if crate::fs::mount(mountpoint, fs) {
                ok("Mounted successfully\n");
            } else {
                err("mount: the mount point is taken or the table is full\n");
            }
        }
        Err(e) => {
            err("mount: ");
            err(&alloc::format!("{}\n", e));
        }
    }
}

/// `mount` without arguments: the volumes AeternaFS has mounted.
fn show_volumes() {
    puts("Mounted filesystems:\n");
    puts("  cowfs         on /       (read-only system files + writable layer)\n");
    puts("  procfs        on /proc\n");
    let mut any = false;
    for v in crate::fs::aeternafs::volumes_info() {
        any = true;
        puts("  ");
        puts(&alloc::format!("aeternafs v2  disk {}  {}  gen {}  {} MiB free of {} MiB  {} snapshot(s){}\n",
            v.disk, if v.label.is_empty() { "-" } else { &v.label }, v.generation,
            v.free_blocks * 4 / 1024, v.total_blocks * 4 / 1024, v.snapshots,
            if v.is_root { "  (writable layer of /)" } else { "" }));
    }
    if !any {
        dim("  no persistent volume: changes to / stay in RAM\n");
    }
}

// ─── fsck / snap ──────────────────────────────────────────────────────────

fn volume_or_err(who: &str) -> Option<&'static crate::fs::aeternafs::AeFs> {
    match crate::fs::aeternafs::root_volume() {
        Some(v) => Some(v),
        None => {
            err(who);
            err(": no persistent AeternaFS volume (live system or no AETERNA partition)\n");
            None
        }
    }
}

/// `fsck [--deep]`: commit pending changes, then check the persistent volume.
pub fn run_fsck(args: &str) {
    let deep = args.split_whitespace().any(|a| a == "--deep" || a == "-d");
    let v = match volume_or_err("fsck") { Some(v) => v, None => return };
    puts(if deep { "Checking the volume, reading every data page...\n" } else { "Checking the volume...\n" });
    match v.fsck(deep) {
        Ok(r) => {
            puts(&alloc::format!(
                "  trees {}  nodes {}  inodes {} ({} dirs, {} files, {} symlinks)\n  data blocks {}  free blocks {}  snapshots {}\n",
                r.trees, r.nodes, r.inodes, r.dirs, r.files, r.symlinks, r.data_blocks, r.free_blocks, r.snapshots));
            if r.is_ok() {
                ok("Clean: no errors found.\n");
            } else {
                err(&alloc::format!("{} error(s):\n", r.errors.len()));
                for e in r.errors.iter().take(20) {
                    err(&alloc::format!("  {}\n", e));
                }
            }
        }
        Err(e) => err(&alloc::format!("fsck: {}\n", e)),
    }
}

/// `snap create|list|delete [name]` on the persistent volume.
pub fn run_snap(args: &str) {
    let mut t = args.split_whitespace();
    let sub = t.next().unwrap_or("list");
    let name = t.next();
    let v = match volume_or_err("snap") { Some(v) => v, None => return };
    match (sub, name) {
        ("list", _) | ("ls", _) => match v.snapshot_list() {
            Ok(l) if l.is_empty() => dim("no snapshots\n"),
            Ok(l) => {
                puts("  ID  GENERATION  NAME\n");
                for s in l {
                    puts(&alloc::format!("  {:<3} {:<11} {}\n", s.id, s.gen, s.name));
                }
            }
            Err(e) => err(&alloc::format!("snap: {}\n", e)),
        },
        ("create", Some(n)) => match v.snapshot_create(n) {
            Ok(()) => ok("Snapshot created.\n"),
            Err(e) => err(&alloc::format!("snap: {}\n", e)),
        },
        ("delete", Some(n)) | ("rm", Some(n)) => match v.snapshot_delete(n) {
            Ok(()) => ok("Snapshot deleted.\n"),
            Err(e) => err(&alloc::format!("snap: {}\n", e)),
        },
        _ => err("usage: snap create <name> | snap list | snap delete <name>\n"),
    }
}

// ─── helpers ──────────────────────────────────────────────────────────────

fn parse_usize(s: &str) -> Option<usize> {
    let s = s.trim();
    if s.is_empty() { return None; }
    let mut n: usize = 0;
    for b in s.bytes() {
        if b < b'0' || b > b'9' { return None; }
        n = n.wrapping_mul(10).wrapping_add((b - b'0') as usize);
    }
    Some(n)
}

/// Split "sda1" → ("sda", "1")
fn split_dev_name(s: &str) -> (&str, &str) {
    let i = s.bytes().rposition(|b| b < b'0' || b > b'9').map(|i| i + 1).unwrap_or(s.len());
    (&s[..i.saturating_sub(0)], &s[i..])
}

fn ahci_name_to_idx(name: &str) -> Option<usize> {
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit());
    let letter = base.chars().last()?;
    let idx = (letter as u8).wrapping_sub(b'a') as usize;
    let want = if base.starts_with("vd") { crate::drivers::DiskKind::Virtio }
               else if base.starts_with("hd") { crate::drivers::DiskKind::Ata }
               else { crate::drivers::DiskKind::Ahci };
    let n = crate::drivers::disk_count();
    let mut ahci_found = 0usize;
    for i in 0..n {
        if let Some(d) = crate::drivers::disk_info(i) {
            if d.kind == want {
                if ahci_found == idx { return Some(i); }
                ahci_found += 1;
            }
        }
    }
    None
}

fn guid_type_label(guid: &[u8; 16]) -> &'static str {
    const ESP:   [u8; 16] = [0x28,0x73,0x2A,0xC1,0x1F,0xF8,0xD2,0x11,0xBA,0x4B,0x00,0xA0,0xC9,0x3E,0xC9,0x3B];
    const LINUX: [u8; 16] = [0xAF,0x3D,0xC6,0x0F,0x83,0x84,0x72,0x47,0x8E,0x79,0x3D,0x69,0xD8,0x47,0x7D,0xE4];
    const MSDAT: [u8; 16] = [0xA2,0xA0,0xD0,0xEB,0xE5,0xB9,0x33,0x44,0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7];
    if guid == &ESP   { return "EFI System"; }
    if guid == &LINUX { return "Linux filesystem"; }
    if guid == &MSDAT { return "Microsoft basic data"; }
    // AeternaFS custom GUID: use a simple check on bytes 0-3
    if guid[0] == 0x53 && guid[1] == 0x46 && guid[2] == 0x54 && guid[3] == 0x45 {
        return "AeternaFS";
    }
    "Unknown"
}
