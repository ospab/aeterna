// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// oosfs: work with AeternaFS v2 images and partitions from the host.

use aeternafs::dev::host::FileDevice;
use aeternafs::dev::{BlockDevice, BLOCK_SIZE};
use aeternafs::{Fs, OSPAB_EPOCH_UNIX_SECS, S_IFDIR, S_IFLNK, S_IFMT};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::exit;

const USAGE: &str = "oosfs - AeternaFS v2 host tool

usage: oosfs <command> [options] <image> [args]

  mkfs  <image> --size 2G [--label L]       create an image (or format a region)
  ls    <image> [path] [-l]                 list a directory
  cat   <image> <path>                      write a file to stdout
  get   <image> <path> <outfile>            copy a file out
  put   <image> <src> <dest> [-r]           copy a file (or a directory with -r) in
  rm    <image> <path> [-r]                 remove a file or directory
  mkdir <image> <path> [-p]                 create a directory
  mv    <image> <from> <to>                 rename
  stat  <image> <path>                      show inode data
  info  <image>                             show volume data
  shell <image>                             interactive filesystem shell
  snap create|list|delete|rollback <image> [name]
  fsck  <image> [--deep]                    check trees, checksums, free space

region options (any command):
  --offset <bytes>    the filesystem starts at this byte offset in the file
  --part <N>          use partition N (1-based, GPT or MBR) of a disk image; inside the AETERNA
                      partition of an installed system the volume is found automatically
  --size <bytes>      region size for mkfs (K, M, G, T suffixes)

images: raw files, and VMware disks (.vmdk: split or single-file sparse, or flat; read and
write). A VMDK in use by a running VM is refused (--force skips the check).

  -v, --verbose       show the region and the first blocks read
";

fn die(msg: &str) -> ! {
    eprintln!("oosfs: {}", msg);
    exit(1);
}

fn parse_size(s: &str) -> u64 {
    let (n, mul) = match s.chars().last() {
        Some('K') | Some('k') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M') | Some('m') => (&s[..s.len() - 1], 1 << 20),
        Some('G') | Some('g') => (&s[..s.len() - 1], 1 << 30),
        Some('T') | Some('t') => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    n.parse::<u64>()
        .unwrap_or_else(|_| die(&format!("bad size '{}'", s)))
        * mul
}

#[derive(Default)]
struct Opts {
    offset: Option<u64>,
    part: Option<usize>,
    size: Option<u64>,
    label: String,
    recursive: bool,
    long: bool,
    deep: bool,
    parents: bool,
    verbose: bool,
    force: bool,
    pos: Vec<String>,
}

fn parse_args() -> Opts {
    let mut o = Opts {
        label: "ospab".into(),
        ..Default::default()
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = |name: &str| {
            it.next()
                .unwrap_or_else(|| die(&format!("{} needs a value", name)))
        };
        match a.as_str() {
            "--offset" => o.offset = Some(parse_size(&val("--offset"))),
            "--part" => o.part = Some(val("--part").parse().unwrap_or_else(|_| die("bad --part"))),
            "--size" => o.size = Some(parse_size(&val("--size"))),
            "--label" => o.label = val("--label"),
            "-r" | "-R" => o.recursive = true,
            "-l" => o.long = true,
            "-p" => o.parents = true,
            "--deep" => o.deep = true,
            "-v" | "--verbose" => o.verbose = true,
            "--force" => o.force = true,
            "-h" | "--help" => {
                print!("{}", USAGE);
                exit(0);
            }
            _ => o.pos.push(a),
        }
    }
    o
}

/// (offset, length) of GPT or MBR partition `n` (1-based), 512-byte sectors.
trait ByteReader {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> bool;
}

impl ByteReader for File {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> bool {
        self.seek(SeekFrom::Start(off)).is_ok() && self.read_exact(buf).is_ok()
    }
}

fn disk_part<R: ByteReader>(f: &mut R, n: usize) -> (u64, u64) {
    let mut mbr = [0u8; 512];
    if !f.read_at(0, &mut mbr) {
        die("cannot read partition table");
    }
    let mut hdr = [0u8; 512];
    if mbr[510..512] == [0x55, 0xAA] {
        let protective = (0..4).any(|i| mbr[446 + i * 16 + 4] == 0xEE);
        if !protective {
            if n == 0 || n > 4 {
                die("MBR partition number out of range (1-4)");
            }
            let entry = 446 + (n - 1) * 16;
            let ptype = mbr[entry + 4];
            let first = u32::from_le_bytes(mbr[entry + 8..entry + 12].try_into().unwrap()) as u64;
            let sectors =
                u32::from_le_bytes(mbr[entry + 12..entry + 16].try_into().unwrap()) as u64;
            if ptype == 0 || sectors == 0 {
                die(&format!("partition {} is empty", n));
            }
            return (first * 512, sectors * 512);
        }
    }
    if !f.read_at(512, &mut hdr) {
        die("cannot read partition table");
    }
    if &hdr[0..8] == b"EFI PART" {
        let lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
        let count = u32::from_le_bytes(hdr[80..84].try_into().unwrap()) as usize;
        let esz = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as usize;
        if n == 0 || n > count || esz < 128 || esz > 4096 {
            die("partition number out of range");
        }
        let mut e = vec![0u8; esz];
        if !f.read_at(lba * 512 + ((n - 1) * esz) as u64, &mut e) {
            die("cannot read GPT partition entry");
        }
        if e[..16].iter().all(|&b| b == 0) {
            die(&format!("partition {} is empty", n));
        }
        let first = u64::from_le_bytes(e[32..40].try_into().unwrap());
        let last = u64::from_le_bytes(e[40..48].try_into().unwrap());
        return (first * 512, (last - first + 1) * 512);
    }

    die("no GPT or MBR partition table")
}

fn locate_aeterna_v2<R: ByteReader>(f: &mut R, partition: (u64, u64)) -> (u64, u64) {
    let (off, len) = partition;
    let mut block = [0u8; BLOCK_SIZE];
    if f.read_at(off, &mut block) && &block[4..12] == b"AETERNA2" {
        return partition;
    }

    // Installed AETERNA partitions keep the legacy installer snapshot first:
    // 8 sectors of identity/spare data followed by an 8 MiB snapshot.
    const V2_DELTA: u64 = (8 + 16_384) * 512;
    if len <= V2_DELTA || !f.read_at(off + V2_DELTA, &mut block) || &block[4..12] != b"AETERNA2" {
        return partition;
    }
    (off + V2_DELTA, len - V2_DELTA)
}

// ─── VMDK ──────────────────────────────────────────────────────────────────
//
// VMware disks: a text descriptor that lists extents, or a single "monolithic sparse" file that
// carries the descriptor inside. Extents are SPARSE (hosted sparse extent: grain directory ->
// grain tables -> grains, allocated on first write) or FLAT (plain preallocated data).
// Compressed stream-optimized extents (OVA exports) are refused.
//
// Sparse extent header (little endian, packed): 0 magic "KDMV", 4 version, 8 flags,
// 12 capacity, 20 grainSize, 28 descriptorOffset, 36 descriptorSize, 44 numGTEsPerGT,
// 48 rgdOffset, 56 gdOffset, 64 overHead; sizes and offsets in 512-byte sectors.
// Flag bit 1: the redundant grain directory at rgdOffset is kept in step; bit 16: compressed.

const SECTOR: u64 = 512;

fn read_u32_at(file: &mut File, off: u64) -> Option<u32> {
    let mut b = [0; 4];
    file.seek(SeekFrom::Start(off)).ok()?;
    file.read_exact(&mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

fn write_u32_at(file: &mut File, off: u64, v: u32) -> bool {
    file.seek(SeekFrom::Start(off)).is_ok() && file.write_all(&v.to_le_bytes()).is_ok()
}

struct Sparse {
    grain: u64,          // sectors per grain
    gtes: u64,           // entries per grain table
    gd: Vec<u32>,        // grain table sector for each directory entry
    rgd: Vec<u32>,       // redundant copies (empty if the extent has none)
    gt_cache: std::collections::HashMap<u64, Vec<u32>>,
}

enum ExtentKind {
    Sparse(Sparse),
    Flat { start: u64 }, // data starts at this sector of the file
}

struct Extent {
    file: File,
    path: std::path::PathBuf,
    disk_start: u64,     // first disk sector covered
    sectors: u64,
    writable: bool,
    kind: ExtentKind,
}

struct VmdkDevice {
    extents: Vec<Extent>,
    offset: u64, // sectors: start of the filesystem region on the virtual disk
    blocks: u64,
}

fn open_extent_file(path: &Path) -> (File, bool) {
    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => (f, true),
        Err(_) => (
            File::open(path).unwrap_or_else(|e| die(&format!("open VMDK extent {}: {}", path.display(), e))),
            false,
        ),
    }
}

fn read_sparse_header(file: &mut File, path: &Path) -> [u8; 512] {
    let mut h = [0u8; 512];
    if !(file.seek(SeekFrom::Start(0)).is_ok() && file.read_exact(&mut h).is_ok()) || &h[0..4] != b"KDMV" {
        die(&format!("{}: not a sparse VMDK extent", path.display()));
    }
    h
}

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

fn load_sparse(file: &mut File, path: &Path, h: &[u8; 512], sectors: u64) -> Sparse {
    let flags = u32::from_le_bytes(h[8..12].try_into().unwrap());
    if flags & (1 << 16) != 0 {
        die(&format!("{}: compressed (stream-optimized) VMDK is not supported; convert it with \
qemu-img or vmware-vdiskmanager first", path.display()));
    }
    let grain = le64(&h[20..]);
    let gtes = u32::from_le_bytes(h[44..48].try_into().unwrap()) as u64;
    let rgd_off = le64(&h[48..]);
    let gd_off = le64(&h[56..]);
    if grain == 0 || gtes == 0 || gd_off == 0 || gd_off == u64::MAX {
        die(&format!("{}: unsupported sparse VMDK geometry", path.display()));
    }
    let count = (sectors + grain * gtes - 1) / (grain * gtes);
    let read_dir = |file: &mut File, at: u64| -> Vec<u32> {
        (0..count)
            .map(|i| read_u32_at(file, at * SECTOR + i * 4).unwrap_or_else(|| die("cannot read the VMDK grain directory")))
            .collect()
    };
    let gd = read_dir(file, gd_off);
    let rgd = if flags & 2 != 0 && rgd_off != 0 { read_dir(file, rgd_off) } else { Vec::new() };
    Sparse { grain, gtes, gd, rgd, gt_cache: std::collections::HashMap::new() }
}

impl VmdkDevice {
    /// `path` is a text descriptor or a monolithic sparse file.
    fn open(path: &Path) -> Self {
        let mut head = [0u8; 4];
        File::open(path).and_then(|mut f| f.read_exact(&mut head)).ok();
        let mut extents = Vec::new();
        if &head == b"KDMV" {
            // Monolithic sparse: one file, the descriptor is embedded and lists only itself.
            let (mut file, writable) = open_extent_file(path);
            let h = read_sparse_header(&mut file, path);
            let sectors = le64(&h[12..]);
            let sp = load_sparse(&mut file, path, &h, sectors);
            extents.push(Extent { file, path: path.to_path_buf(), disk_start: 0, sectors, writable, kind: ExtentKind::Sparse(sp) });
        } else {
            let text = std::fs::read_to_string(path)
                .unwrap_or_else(|e| die(&format!("read VMDK descriptor {}: {}", path.display(), e)));
            let base = path.parent().unwrap_or_else(|| Path::new("."));
            let mut disk_start = 0u64;
            for line in text.lines() {
                let line = line.trim();
                let Some(q) = line.find('"') else { continue };
                let fields: Vec<_> = line[..q].split_whitespace().collect();
                if fields.len() != 3 || !matches!(fields[0], "RW" | "RDONLY") {
                    continue;
                }
                let sectors = fields[1].parse::<u64>().unwrap_or_else(|_| die("bad VMDK extent size"));
                let rest = &line[q + 1..];
                let Some(q2) = rest.find('"') else { die("bad VMDK extent line") };
                let ext_path = base.join(&rest[..q2]);
                let (mut file, mut writable) = open_extent_file(&ext_path);
                writable &= fields[0] == "RW";
                let kind = match fields[2] {
                    "SPARSE" => {
                        let h = read_sparse_header(&mut file, &ext_path);
                        ExtentKind::Sparse(load_sparse(&mut file, &ext_path, &h, sectors))
                    }
                    "FLAT" | "VMFS" => ExtentKind::Flat {
                        start: rest[q2 + 1..].split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0),
                    },
                    other => die(&format!("unsupported VMDK extent type {}", other)),
                };
                extents.push(Extent { file, path: ext_path, disk_start, sectors, writable, kind });
                disk_start += sectors;
            }
            if extents.is_empty() {
                die(&format!("{}: no extents in the VMDK descriptor", path.display()));
            }
        }
        let total: u64 = extents.iter().map(|e| e.sectors).sum();
        Self { extents, offset: 0, blocks: total / 8 }
    }

    /// The grain table entry for `grain`, loading the table into the cache.
    fn gte(file: &mut File, sp: &mut Sparse, grain: u64) -> Option<u32> {
        let (gdi, gti) = (grain / sp.gtes, (grain % sp.gtes) as usize);
        let gt_sector = *sp.gd.get(gdi as usize)?;
        if gt_sector == 0 {
            return Some(0);
        }
        if !sp.gt_cache.contains_key(&gdi) {
            let mut raw = vec![0u8; sp.gtes as usize * 4];
            file.seek(SeekFrom::Start(gt_sector as u64 * SECTOR)).ok()?;
            file.read_exact(&mut raw).ok()?;
            sp.gt_cache.insert(gdi, raw.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect());
        }
        Some(sp.gt_cache[&gdi][gti])
    }

    /// Allocate a zeroed grain at the end of the extent file and record it in both tables.
    fn alloc_grain(file: &mut File, sp: &mut Sparse, grain: u64) -> Option<u32> {
        let (gdi, gti) = (grain / sp.gtes, grain % sp.gtes);
        let gt_sector = *sp.gd.get(gdi as usize)?;
        if gt_sector == 0 {
            // VMware and qemu-img preallocate every grain table; anything else is not supported.
            return None;
        }
        let end = file.seek(SeekFrom::End(0)).ok()?;
        let at = (end + SECTOR - 1) / SECTOR;
        file.seek(SeekFrom::Start(at * SECTOR)).ok()?;
        file.write_all(&vec![0u8; (sp.grain * SECTOR) as usize]).ok()?;
        let at32 = u32::try_from(at).ok()?;
        if !write_u32_at(file, gt_sector as u64 * SECTOR + gti * 4, at32) {
            return None;
        }
        if let Some(&r) = sp.rgd.get(gdi as usize) {
            if r != 0 && !write_u32_at(file, r as u64 * SECTOR + gti * 4, at32) {
                return None;
            }
        }
        if let Some(t) = sp.gt_cache.get_mut(&gdi) {
            t[gti as usize] = at32;
        }
        Some(at32)
    }

    /// Read or write `buf` at byte `pos` of the virtual disk (whole sectors not required).
    fn io(&mut self, mut pos: u64, mut read: Option<&mut [u8]>, mut write: Option<&[u8]>) -> bool {
        let mut done = 0usize;
        let len = read.as_ref().map(|b| b.len()).or(write.map(|b| b.len())).unwrap_or(0);
        while done < len {
            let sector = pos / SECTOR;
            let Some(e) = self.extents.iter_mut().find(|e| sector >= e.disk_start && sector < e.disk_start + e.sectors) else {
                return false;
            };
            let rel = pos - e.disk_start * SECTOR; // byte offset inside the extent
            if write.is_some() && !e.writable {
                eprintln!("oosfs: {} is read-only", e.path.display());
                return false;
            }
            // How much fits before the end of this extent (and of this grain for sparse).
            let (file_off, chunk) = match &mut e.kind {
                ExtentKind::Flat { start } => {
                    let left = e.sectors * SECTOR - rel;
                    (Some(*start * SECTOR + rel), left.min((len - done) as u64))
                }
                ExtentKind::Sparse(sp) => {
                    let gbytes = sp.grain * SECTOR;
                    let grain = rel / gbytes;
                    let within = rel % gbytes;
                    let chunk = (gbytes - within).min((len - done) as u64);
                    let mut g = match Self::gte(&mut e.file, sp, grain) {
                        Some(g) => g,
                        None => return false,
                    };
                    if g == 0 && write.is_some() {
                        g = match Self::alloc_grain(&mut e.file, sp, grain) {
                            Some(g) => g,
                            None => {
                                eprintln!("oosfs: {}: cannot allocate a grain", e.path.display());
                                return false;
                            }
                        };
                    }
                    ((g != 0).then(|| g as u64 * SECTOR + within), chunk)
                }
            };
            let c = chunk as usize;
            match (&mut read, &mut write, file_off) {
                (Some(buf), _, None) => buf[done..done + c].fill(0),
                (Some(buf), _, Some(off)) => {
                    if !(e.file.seek(SeekFrom::Start(off)).is_ok() && e.file.read_exact(&mut buf[done..done + c]).is_ok()) {
                        return false;
                    }
                }
                (None, Some(data), Some(off)) => {
                    if !(e.file.seek(SeekFrom::Start(off)).is_ok() && e.file.write_all(&data[done..done + c]).is_ok()) {
                        return false;
                    }
                }
                _ => return false,
            }
            done += c;
            pos += chunk;
        }
        true
    }
}

impl ByteReader for VmdkDevice {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> bool {
        if off.checked_add(buf.len() as u64).map_or(true, |v| v > self.blocks * BLOCK_SIZE as u64 + self.offset * SECTOR) {
            return false;
        }
        self.io(self.offset * SECTOR + off, Some(buf), None)
    }
}

impl BlockDevice for VmdkDevice {
    fn block_count(&self) -> u64 {
        self.blocks
    }
    fn read_blocks(&mut self, start: u64, buf: &mut [u8]) -> Result<(), aeternafs::dev::IoError> {
        let n = ((buf.len() + BLOCK_SIZE - 1) / BLOCK_SIZE) as u64;
        if start + n > self.blocks || !self.io(self.offset * SECTOR + start * BLOCK_SIZE as u64, Some(buf), None) {
            return Err(aeternafs::dev::IoError);
        }
        Ok(())
    }
    fn write_blocks(&mut self, start: u64, buf: &[u8]) -> Result<(), aeternafs::dev::IoError> {
        let n = ((buf.len() + BLOCK_SIZE - 1) / BLOCK_SIZE) as u64;
        if start + n > self.blocks || !self.io(self.offset * SECTOR + start * BLOCK_SIZE as u64, None, Some(buf)) {
            return Err(aeternafs::dev::IoError);
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), aeternafs::dev::IoError> {
        for e in &mut self.extents {
            if e.writable && e.file.sync_all().is_err() {
                return Err(aeternafs::dev::IoError);
            }
        }
        Ok(())
    }
}

enum Device {
    Raw(FileDevice),
    Vmdk(VmdkDevice),
}

impl BlockDevice for Device {
    fn block_count(&self) -> u64 {
        match self {
            Device::Raw(d) => d.block_count(),
            Device::Vmdk(d) => d.block_count(),
        }
    }
    fn read_blocks(&mut self, start: u64, buf: &mut [u8]) -> Result<(), aeternafs::dev::IoError> {
        match self {
            Device::Raw(d) => d.read_blocks(start, buf),
            Device::Vmdk(d) => d.read_blocks(start, buf),
        }
    }
    fn write_blocks(&mut self, start: u64, buf: &[u8]) -> Result<(), aeternafs::dev::IoError> {
        match self {
            Device::Raw(d) => d.write_blocks(start, buf),
            Device::Vmdk(d) => d.write_blocks(start, buf),
        }
    }
    fn flush(&mut self) -> Result<(), aeternafs::dev::IoError> {
        match self {
            Device::Raw(d) => d.flush(),
            Device::Vmdk(d) => d.flush(),
        }
    }
}

/// A VMDK descriptor (text) or a monolithic sparse VMDK (binary, "KDMV").
fn is_vmdk(path: &Path) -> bool {
    let mut head = [0u8; 21];
    let Ok(mut f) = File::open(path) else { return false };
    let n = f.read(&mut head).unwrap_or(0);
    head[..n].starts_with(b"KDMV") || head[..n].starts_with(b"# Disk DescriptorFile")
}

/// VMware keeps `<disk>.vmdk.lck` (a directory) while a VM has the disk open.
fn refuse_if_locked(o: &Opts, path: &Path) {
    let mut lck = path.as_os_str().to_owned();
    lck.push(".lck");
    if Path::new(&lck).exists() && !o.force {
        die(&format!(
            "{} is in use by a running VM ({} exists). Power the VM off first; --force skips this check",
            path.display(),
            Path::new(&lck).display()
        ));
    }
}

fn open_device(o: &Opts, path: &str, create: bool) -> Device {
    let p = Path::new(path);
    if is_vmdk(p) {
        if create && o.part.is_none() && o.offset.is_none() {
            die("mkfs on a VMDK needs --part N (format a partition inside the virtual disk)");
        }
        refuse_if_locked(o, p);
        let mut device = VmdkDevice::open(p);
        if let Some(part) = o.part {
            let partition = disk_part(&mut device, part);
            let (off, len) = locate_aeterna_v2(&mut device, partition);
            if o.verbose {
                eprintln!("[oosfs] VMDK partition {}: offset={} bytes, length={} bytes", part, off, len);
            }
            device.offset = off / SECTOR;
            device.blocks = len / BLOCK_SIZE as u64;
        } else if let Some(off) = o.offset {
            device.offset = off / SECTOR;
            device.blocks -= off / BLOCK_SIZE as u64;
        }
        return Device::Vmdk(device);
    }
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create && o.part.is_none())
        .open(path)
        .unwrap_or_else(|e| die(&format!("cannot open {}: {}", path, e)));
    let flen = f.metadata().map(|m| m.len()).unwrap_or(0);
    let (off, len) = if let Some(p) = o.part {
        let partition = disk_part(&mut f, p);
        let region = locate_aeterna_v2(&mut f, partition);
        if o.verbose {
            eprintln!("[oosfs] disk partition {}: offset={} bytes, length={} bytes", p, region.0, region.1);
        }
        region
    } else {
        let off = o.offset.unwrap_or(0);
        let want = match o.size {
            Some(s) if create => s,
            _ => flen.saturating_sub(off),
        };
        if create && flen < off + want {
            f.set_len(off + want)
                .unwrap_or_else(|e| die(&format!("cannot size image: {}", e)));
        }
        (off, want)
    };
    if off + len > f.metadata().map(|m| m.len()).unwrap_or(0) {
        die("region is larger than the file");
    }
    Device::Raw(FileDevice::new(f, off, len))
}

fn log_probe(device: &mut Device) {
    eprintln!(
        "[oosfs] filesystem device: {} blocks ({} bytes)",
        device.block_count(),
        device.block_count() * BLOCK_SIZE as u64
    );
    for block_no in 0..2 {
        let mut block = [0u8; BLOCK_SIZE];
        match device.read_blocks(block_no, &mut block) {
            Ok(()) => {
                let hex = block[..32]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                let text = String::from_utf8_lossy(&block[4..12]);
                eprintln!(
                    "[oosfs] read block {}: ok; bytes[0..32]={}; magic[4..12]={:?}",
                    block_no, hex, text
                );
            }
            Err(_) => eprintln!("[oosfs] read block {}: FAILED", block_no),
        }
    }
}

fn now_ns() -> i64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    (d.as_secs() as i64 - OSPAB_EPOCH_UNIX_SECS) * 1_000_000_000 + d.subsec_nanos() as i64
}

fn open_fs(o: &Opts, path: &str) -> Fs<Device> {
    let mut device = open_device(o, path, false);
    if o.verbose {
        log_probe(&mut device);
    }
    // The kernel's old RAM snapshot format (vfs/disk_sync.rs): SUPER_MAGIC, then "AETERNA_FS".
    let mut probe = [0u8; BLOCK_SIZE];
    if device.read_blocks(0, &mut probe).is_ok() && &probe[12..22] == b"AETERNA_FS" {
        die("this is the old RAM snapshot format, not AeternaFS v2: boot the installed system once \
and it migrates the data");
    }
    let mut fs = Fs::mount(device).unwrap_or_else(|e| {
        die(&format!("mount {}: {}{}", path, e, if o.verbose { "" } else { " (-v shows what was read)" }))
    });
    fs.set_time(now_ns());
    fs
}

fn fmt_time(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000) + OSPAB_EPOCH_UNIX_SECS;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // civil from days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m,
        d,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn mode_str(mode: u32) -> String {
    let t = match mode & S_IFMT {
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        _ => '-',
    };
    let mut s = String::from(t);
    for i in (0..3).rev() {
        let b = (mode >> (i * 3)) & 7;
        s.push(if b & 4 != 0 { 'r' } else { '-' });
        s.push(if b & 2 != 0 { 'w' } else { '-' });
        s.push(if b & 1 != 0 { 'x' } else { '-' });
    }
    s
}

fn need<'a>(o: &'a Opts, i: usize, what: &str) -> &'a str {
    o.pos
        .get(i)
        .map(|s| s.as_str())
        .unwrap_or_else(|| die(&format!("missing {}\n\n{}", what, USAGE)))
}

fn fatal<T>(r: aeternafs::Result<T>, what: &str) -> T {
    r.unwrap_or_else(|e| die(&format!("{}: {}", what, e)))
}

fn put_file(fs: &mut Fs<Device>, src: &Path, dest: &str) {
    let mut f =
        File::open(src).unwrap_or_else(|e| die(&format!("cannot read {}: {}", src.display(), e)));
    let (dir, name) = fatal(fs.split_parent(dest), dest);
    let ino = match fs.lookup(dir, &name) {
        Ok(i) => {
            fatal(fs.truncate(i, 0), dest);
            i
        }
        Err(_) => fatal(fs.create(dir, &name, 0o644), dest),
    };
    let mut buf = vec![0u8; 4 << 20];
    let mut off = 0u64;
    loop {
        let n = f
            .read(&mut buf)
            .unwrap_or_else(|e| die(&format!("read {}: {}", src.display(), e)));
        if n == 0 {
            break;
        }
        fatal(fs.write(ino, off, &buf[..n]), dest);
        off += n as u64;
    }
}

fn put_tree(fs: &mut Fs<Device>, src: &Path, dest: &str, count: &mut u64) {
    match fs.mkdir_path(dest, 0o755) {
        Ok(_) | Err(aeternafs::Error::Exists) => {}
        Err(e) => die(&format!("{}: {}", dest, e)),
    }
    let mut entries: Vec<_> = std::fs::read_dir(src)
        .unwrap_or_else(|e| die(&format!("{}: {}", src.display(), e)))
        .flatten()
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let target = format!("{}/{}", dest.trim_end_matches('/'), name);
        let ft = e.file_type().unwrap();
        if ft.is_dir() {
            put_tree(fs, &e.path(), &target, count);
        } else if ft.is_file() {
            put_file(fs, &e.path(), &target);
            *count += 1;
        }
    }
}

fn rm_tree(fs: &mut Fs<Device>, dir: u64, name: &str) {
    let ino = fatal(fs.lookup(dir, name), name);
    if fatal(fs.stat(ino), name).is_dir() {
        for e in fatal(fs.readdir(ino), name) {
            rm_tree(fs, ino, &e.name);
        }
        fatal(fs.rmdir(dir, name), name);
    } else {
        fatal(fs.unlink(dir, name), name);
    }
}

fn shell_path(cwd: &str, path: &str) -> String {
    let raw = if path.starts_with('/') {
        path.to_string()
    } else if cwd == "/" {
        format!("/{}", path)
    } else {
        format!("{}/{}", cwd.trim_end_matches('/'), path)
    };
    let mut parts = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            component => parts.push(component),
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn run_shell(o: &Opts, image: &str) {
    let mut fs = open_fs(o, image);
    let mut cwd = String::from("/");
    println!("oosfs shell: {} (type 'help' for commands)", image);
    let stdin = std::io::stdin();
    loop {
        print!("oosfs:{}$ ", cwd);
        std::io::stdout().flush().unwrap_or(());
        let mut line = String::new();
        if stdin.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let args: Vec<&str> = line.split_whitespace().collect();
        let Some(command) = args.first().copied() else {
            continue;
        };
        match command {
            "exit" | "quit" => break,
            "help" => println!(
                "ls [path] [-l] | cd [path] | pwd | cat <path> | stat <path>\n\
                 info | fsck [--deep] | mkdir [-p] <path> | rm [-r] <path>\n\
                 mv <from> <to> | get <path> <host-file> | put <host-file> <path>"
            ),
            "pwd" => println!("{}", cwd),
            "cd" => {
                let path = shell_path(&cwd, args.get(1).copied().unwrap_or("/"));
                match fs.resolve(&path).and_then(|i| fs.stat(i)) {
                    Ok(s) if s.is_dir() => cwd = if path.is_empty() { "/".into() } else { path },
                    Ok(_) => println!("cd: not a directory: {}", path),
                    Err(e) => println!("cd: {}: {}", path, e),
                }
            }
            "ls" => {
                let mut long = false;
                let mut path = None;
                for arg in args.iter().skip(1) {
                    if *arg == "-l" {
                        long = true;
                    } else {
                        path = Some(*arg);
                    }
                }
                let path = shell_path(&cwd, path.unwrap_or("."));
                match fs.resolve(&path).and_then(|i| fs.stat(i)).and_then(|s| {
                    let ino = fs.resolve(&path)?;
                    if s.is_dir() {
                        fs.readdir(ino)
                    } else {
                        Ok(Vec::new())
                    }
                }) {
                    Ok(mut entries) => {
                        entries.sort_by(|a, b| a.name.cmp(&b.name));
                        for e in entries {
                            if long {
                                match fs.stat(e.ino) {
                                    Ok(s) => {
                                        println!("{} {:>12} {}", mode_str(s.mode), s.size, e.name)
                                    }
                                    Err(e) => println!("ls: {}", e),
                                }
                            } else {
                                println!(
                                    "{}{}",
                                    e.name,
                                    if e.mode_type == S_IFDIR { "/" } else { "" }
                                );
                            }
                        }
                    }
                    Err(e) => println!("ls: {}: {}", path, e),
                }
            }
            "cat" => {
                let Some(raw) = args.get(1) else {
                    println!("cat: missing path");
                    continue;
                };
                let path = shell_path(&cwd, raw);
                match fs.resolve(&path).and_then(|ino| {
                    let size = fs.stat(ino)?.size;
                    let mut data = vec![0u8; size as usize];
                    let mut off = 0;
                    while off < size {
                        let n = fs.read(ino, off, &mut data[off as usize..])?;
                        if n == 0 {
                            break;
                        }
                        off += n as u64;
                    }
                    Ok(data)
                }) {
                    Ok(data) => print!("{}", String::from_utf8_lossy(&data)),
                    Err(e) => println!("cat: {}: {}", path, e),
                }
            }
            "stat" => {
                let Some(raw) = args.get(1) else {
                    println!("stat: missing path");
                    continue;
                };
                let path = shell_path(&cwd, raw);
                match fs.resolve(&path).and_then(|i| fs.stat(i)) {
                    Ok(s) => println!(
                        "inode: {}\nmode: {} ({:o})\nsize: {}\nmodified: {}",
                        s.ino,
                        mode_str(s.mode),
                        s.mode,
                        s.size,
                        fmt_time(s.mtime)
                    ),
                    Err(e) => println!("stat: {}: {}", path, e),
                }
            }
            "info" => {
                let s = fs.statfs();
                println!(
                    "label: {}\ngeneration: {}\nblocks: {} total, {} free",
                    s.label, s.generation, s.total_blocks, s.free_blocks
                );
            }
            "mkdir" => {
                let parents = args.contains(&"-p");
                let Some(raw) = args.iter().skip(1).find(|a| **a != "-p") else {
                    println!("mkdir: missing path");
                    continue;
                };
                let path = shell_path(&cwd, raw);
                let result = if parents {
                    let mut result = Ok(());
                    let mut cur = String::new();
                    for part in path.split('/').filter(|p| !p.is_empty()) {
                        cur = format!("{}/{}", cur, part);
                        match fs.mkdir_path(&cur, 0o755) {
                            Ok(_) | Err(aeternafs::Error::Exists) => {}
                            Err(e) => {
                                result = Err(e);
                                break;
                            }
                        }
                    }
                    result
                } else {
                    fs.mkdir_path(&path, 0o755).map(|_| ())
                };
                match result {
                    Ok(()) => {
                        if let Err(e) = fs.commit() {
                            println!("mkdir: commit: {}", e);
                        }
                    }
                    Err(e) => println!("mkdir: {}: {}", path, e),
                }
            }
            "rm" => {
                let recursive = args.contains(&"-r") || args.contains(&"-R");
                let Some(raw) = args.iter().skip(1).find(|a| **a != "-r" && **a != "-R") else {
                    println!("rm: missing path");
                    continue;
                };
                let path = shell_path(&cwd, raw);
                match fs.split_parent(&path).and_then(|(dir, name)| {
                    if recursive {
                        rm_tree(&mut fs, dir, &name);
                        Ok(())
                    } else {
                        let ino = fs.lookup(dir, &name)?;
                        if fs.stat(ino)?.is_dir() {
                            fs.rmdir(dir, &name)
                        } else {
                            fs.unlink(dir, &name)
                        }
                    }
                }) {
                    Ok(()) => {
                        if let Err(e) = fs.commit() {
                            println!("rm: commit: {}", e);
                        }
                    }
                    Err(e) => println!("rm: {}: {}", path, e),
                }
            }
            "mv" => {
                if args.len() < 3 {
                    println!("mv: needs FROM TO");
                    continue;
                }
                let from = shell_path(&cwd, args[1]);
                let to = shell_path(&cwd, args[2]);
                match fs.rename_path(&from, &to).and_then(|_| fs.commit()) {
                    Ok(()) => {}
                    Err(e) => println!("mv: {}", e),
                }
            }
            "get" => {
                if args.len() < 3 {
                    println!("get: needs PATH HOST-FILE");
                    continue;
                }
                let path = shell_path(&cwd, args[1]);
                match fs.resolve(&path).and_then(|ino| {
                    let size = fs.stat(ino)?.size;
                    let mut out = File::create(args[2]).map_err(|_| aeternafs::Error::Io)?;
                    let mut data = vec![0u8; 4 << 20];
                    let mut off = 0;
                    while off < size {
                        let n = fs.read(ino, off, &mut data)?;
                        if n == 0 {
                            break;
                        }
                        out.write_all(&data[..n])
                            .map_err(|_| aeternafs::Error::Io)?;
                        off += n as u64;
                    }
                    Ok(())
                }) {
                    Ok(()) => println!("copied {}", path),
                    Err(e) => println!("get: {}: {}", path, e),
                }
            }
            "put" => {
                if args.len() < 3 {
                    println!("put: needs HOST-FILE PATH");
                    continue;
                }
                let path = shell_path(&cwd, args[2]);
                put_file(&mut fs, Path::new(args[1]), &path);
                if let Err(e) = fs.commit() {
                    println!("put: commit: {}", e);
                }
            }
            "fsck" => {
                let report = fs.fsck(args.contains(&"--deep"));
                match report {
                    Ok(r) if r.is_ok() => println!("clean"),
                    Ok(r) => println!("fsck: {} error(s)", r.errors.len()),
                    Err(e) => println!("fsck: {}", e),
                }
            }
            _ => println!("unknown command '{}'; type 'help'", command),
        }
    }
}

fn main() {
    let o = parse_args();
    let cmd = match o.pos.first() {
        Some(c) => c.clone(),
        None => {
            print!("{}", USAGE);
            exit(2);
        }
    };
    if cmd == "snap" {
        let sub = need(&o, 1, "snapshot command").to_string();
        let img = need(&o, 2, "image").to_string();
        let mut fs = open_fs(&o, &img);
        match sub.as_str() {
            "list" => {
                for s in fatal(fs.snapshot_list(), "snapshots") {
                    println!(
                        "{:>4}  gen {:<8} {}  {}",
                        s.id,
                        s.gen,
                        fmt_time(s.time),
                        s.name
                    );
                }
            }
            "create" => fatal(
                fs.snapshot_create(need(&o, 3, "snapshot name")),
                "snapshot create",
            ),
            "delete" => fatal(
                fs.snapshot_delete(need(&o, 3, "snapshot name")),
                "snapshot delete",
            ),
            "rollback" => fatal(
                fs.snapshot_rollback(need(&o, 3, "snapshot name")),
                "snapshot rollback",
            ),
            _ => die("snap: create, list, delete or rollback"),
        }
        return;
    }
    if cmd == "shell" {
        let img = need(&o, 1, "image").to_string();
        run_shell(&o, &img);
        return;
    }
    let img = need(&o, 1, "image").to_string();
    if cmd == "mkfs" {
        let dev = open_device(&o, &img, true);
        let blocks = aeternafs::BlockDevice::block_count(&dev);
        let mut dev = fatal(Fs::mkfs(dev, &o.label, now_ns()), "mkfs");
        let _ = aeternafs::BlockDevice::flush(&mut dev);
        println!(
            "formatted {} ({} blocks of 4096, {} MiB), label '{}'",
            img,
            blocks,
            blocks * 4096 >> 20,
            o.label
        );
        return;
    }
    let mut fs = open_fs(&o, &img);
    match cmd.as_str() {
        "ls" => {
            let path = o.pos.get(2).map(|s| s.as_str()).unwrap_or("/");
            let ino = fatal(fs.resolve(path), path);
            let st = fatal(fs.stat(ino), path);
            let list = if st.is_dir() {
                fatal(fs.readdir(ino), path)
            } else {
                Vec::new()
            };
            let mut list = list;
            list.sort_by(|a, b| a.name.cmp(&b.name));
            for e in list {
                if o.long {
                    let s = fatal(fs.stat(e.ino), &e.name);
                    println!(
                        "{} {:>12} {} {}{}",
                        mode_str(s.mode),
                        s.size,
                        fmt_time(s.mtime),
                        e.name,
                        if s.is_dir() { "/" } else { "" }
                    );
                } else {
                    println!(
                        "{}{}",
                        e.name,
                        if e.mode_type == S_IFDIR { "/" } else { "" }
                    );
                }
            }
        }
        "cat" | "get" => {
            let path = need(&o, 2, "path");
            let ino = fatal(fs.resolve(path), path);
            let size = fatal(fs.stat(ino), path).size;
            let mut out: Box<dyn Write> = if cmd == "get" {
                Box::new(
                    File::create(need(&o, 3, "output file"))
                        .unwrap_or_else(|e| die(&format!("{}", e))),
                )
            } else {
                Box::new(std::io::stdout().lock())
            };
            let mut buf = vec![0u8; 4 << 20];
            let mut off = 0;
            while off < size {
                let n = fatal(fs.read(ino, off, &mut buf), path);
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n])
                    .unwrap_or_else(|e| die(&format!("write: {}", e)));
                off += n as u64;
            }
        }
        "put" => {
            let src = Path::new(need(&o, 2, "source"));
            let mut dest = need(&o, 3, "destination").to_string();
            if o.recursive {
                let mut count = 0;
                put_tree(&mut fs, src, &dest, &mut count);
                fatal(fs.commit(), "commit");
                println!("copied {} files", count);
            } else {
                let is_dir = dest.ends_with('/')
                    || fs
                        .resolve(&dest)
                        .and_then(|i| fs.stat(i))
                        .map(|s| s.is_dir())
                        .unwrap_or(false);
                if is_dir {
                    let name = src
                        .file_name()
                        .unwrap_or_else(|| die("bad source name"))
                        .to_string_lossy()
                        .into_owned();
                    dest = format!("{}/{}", dest.trim_end_matches('/'), name);
                }
                put_file(&mut fs, src, &dest);
                fatal(fs.commit(), "commit");
            }
        }
        "rm" => {
            let path = need(&o, 2, "path");
            let (dir, name) = fatal(fs.split_parent(path), path);
            if o.recursive {
                rm_tree(&mut fs, dir, &name);
            } else {
                let ino = fatal(fs.lookup(dir, &name), path);
                if fatal(fs.stat(ino), path).is_dir() {
                    fatal(fs.rmdir(dir, &name), path)
                } else {
                    fatal(fs.unlink(dir, &name), path)
                }
            }
            fatal(fs.commit(), "commit");
        }
        "mkdir" => {
            let path = need(&o, 2, "path");
            if o.parents {
                let mut cur = String::new();
                for c in path.split('/').filter(|c| !c.is_empty()) {
                    cur = format!("{}/{}", cur, c);
                    match fs.mkdir_path(&cur, 0o755) {
                        Ok(_) | Err(aeternafs::Error::Exists) => {}
                        Err(e) => die(&format!("{}: {}", cur, e)),
                    }
                }
            } else {
                fatal(fs.mkdir_path(path, 0o755), path);
            }
            fatal(fs.commit(), "commit");
        }
        "mv" => {
            fatal(fs.rename_path(need(&o, 2, "from"), need(&o, 3, "to")), "mv");
            fatal(fs.commit(), "commit");
        }
        "stat" => {
            let path = need(&o, 2, "path");
            let ino = fatal(fs.resolve(path), path);
            let s = fatal(fs.stat(ino), path);
            println!("inode:   {}", s.ino);
            println!("mode:    {} ({:o})", mode_str(s.mode), s.mode);
            println!("size:    {}", s.size);
            println!("parent:  {}", s.parent);
            println!("created: {}", fmt_time(s.crtime));
            println!("changed: {}", fmt_time(s.ctime));
            println!("modified: {}", fmt_time(s.mtime));
            if s.is_symlink() {
                println!("target:  {}", fatal(fs.readlink(ino), path));
            }
        }
        "info" => {
            let s = fs.statfs();
            println!("label:      {}", s.label);
            println!("generation: {}", s.generation);
            println!(
                "blocks:     {} total, {} free ({} MiB free)",
                s.total_blocks,
                s.free_blocks,
                s.free_blocks * 4096 >> 20
            );
            println!(
                "snapshots:  {}",
                fatal(fs.snapshot_list(), "snapshots").len()
            );
        }
        "fsck" => {
            let r = fatal(fs.fsck(o.deep), "fsck");
            println!("{} trees, {} inodes ({} dirs, {} files, {} symlinks), {} tree nodes, {} data blocks, {} free blocks, {} snapshots",
                r.trees, r.inodes, r.dirs, r.files, r.symlinks, r.nodes, r.data_blocks, r.free_blocks, r.snapshots);
            if r.is_ok() {
                println!(
                    "clean{}",
                    if o.deep {
                        " (data checksums verified)"
                    } else {
                        ""
                    }
                );
            } else {
                for e in &r.errors {
                    println!("ERROR: {}", e);
                }
                exit(1);
            }
        }
        _ => die(&format!("unknown command '{}'\n\n{}", cmd, USAGE)),
    }
}
