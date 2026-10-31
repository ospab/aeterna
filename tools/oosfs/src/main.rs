// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// oosfs: work with AeternaFS v2 images and partitions from the host.

use aeternafs::dev::host::FileDevice;
use aeternafs::{Fs, S_IFDIR, S_IFLNK, S_IFMT, OSPAB_EPOCH_UNIX_SECS};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
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
  snap create|list|delete|rollback <image> [name]
  fsck  <image> [--deep]                    check trees, checksums, free space

region options (any command):
  --offset <bytes>    the filesystem starts at this byte offset in the file
  --part <N>          use GPT partition N (1-based) of a disk image
  --size <bytes>      region size for mkfs (K, M, G, T suffixes)
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
    n.parse::<u64>().unwrap_or_else(|_| die(&format!("bad size '{}'", s))) * mul
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
    pos: Vec<String>,
}

fn parse_args() -> Opts {
    let mut o = Opts { label: "ospab".into(), ..Default::default() };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().unwrap_or_else(|| die(&format!("{} needs a value", name)));
        match a.as_str() {
            "--offset" => o.offset = Some(parse_size(&val("--offset"))),
            "--part" => o.part = Some(val("--part").parse().unwrap_or_else(|_| die("bad --part"))),
            "--size" => o.size = Some(parse_size(&val("--size"))),
            "--label" => o.label = val("--label"),
            "-r" | "-R" => o.recursive = true,
            "-l" => o.long = true,
            "-p" => o.parents = true,
            "--deep" => o.deep = true,
            "-h" | "--help" => { print!("{}", USAGE); exit(0); }
            _ => o.pos.push(a),
        }
    }
    o
}

/// (offset, length) of GPT partition `n` (1-based), 512-byte sectors.
fn gpt_part(f: &mut File, n: usize) -> (u64, u64) {
    let mut hdr = [0u8; 512];
    read_at(f, 512, &mut hdr);
    if &hdr[0..8] != b"EFI PART" { die("no GPT header at LBA 1"); }
    let lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let count = u32::from_le_bytes(hdr[80..84].try_into().unwrap()) as usize;
    let esz = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as usize;
    if n == 0 || n > count || esz < 128 || esz > 4096 { die("partition number out of range"); }
    let mut e = vec![0u8; esz];
    read_at(f, lba * 512 + ((n - 1) * esz) as u64, &mut e);
    if e[..16].iter().all(|&b| b == 0) { die(&format!("partition {} is empty", n)); }
    let first = u64::from_le_bytes(e[32..40].try_into().unwrap());
    let last = u64::from_le_bytes(e[40..48].try_into().unwrap());
    (first * 512, (last - first + 1) * 512)
}

fn read_at(f: &mut File, off: u64, buf: &mut [u8]) {
    use std::io::{Seek, SeekFrom};
    f.seek(SeekFrom::Start(off)).unwrap_or_else(|e| die(&format!("seek: {}", e)));
    f.read_exact(buf).unwrap_or_else(|e| die(&format!("read: {}", e)));
}

fn open_device(o: &Opts, path: &str, create: bool) -> FileDevice {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create && o.part.is_none())
        .open(path)
        .unwrap_or_else(|e| die(&format!("cannot open {}: {}", path, e)));
    let flen = f.metadata().map(|m| m.len()).unwrap_or(0);
    let (off, len) = if let Some(p) = o.part {
        gpt_part(&mut f, p)
    } else {
        let off = o.offset.unwrap_or(0);
        let want = match o.size {
            Some(s) if create => s,
            _ => flen.saturating_sub(off),
        };
        if create && flen < off + want {
            f.set_len(off + want).unwrap_or_else(|e| die(&format!("cannot size image: {}", e)));
        }
        (off, want)
    };
    if off + len > f.metadata().map(|m| m.len()).unwrap_or(0) { die("region is larger than the file"); }
    FileDevice::new(f, off, len)
}

fn now_ns() -> i64 {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    (d.as_secs() as i64 - OSPAB_EPOCH_UNIX_SECS) * 1_000_000_000 + d.subsec_nanos() as i64
}

fn open_fs(o: &Opts, path: &str) -> Fs<FileDevice> {
    let mut fs = Fs::mount(open_device(o, path, false)).unwrap_or_else(|e| die(&format!("mount {}: {}", path, e)));
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
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

fn mode_str(mode: u32) -> String {
    let t = match mode & S_IFMT { S_IFDIR => 'd', S_IFLNK => 'l', _ => '-' };
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
    o.pos.get(i).map(|s| s.as_str()).unwrap_or_else(|| die(&format!("missing {}\n\n{}", what, USAGE)))
}

fn fatal<T>(r: aeternafs::Result<T>, what: &str) -> T {
    r.unwrap_or_else(|e| die(&format!("{}: {}", what, e)))
}

fn put_file(fs: &mut Fs<FileDevice>, src: &Path, dest: &str) {
    let mut f = File::open(src).unwrap_or_else(|e| die(&format!("cannot read {}: {}", src.display(), e)));
    let (dir, name) = fatal(fs.split_parent(dest), dest);
    let ino = match fs.lookup(dir, &name) {
        Ok(i) => { fatal(fs.truncate(i, 0), dest); i }
        Err(_) => fatal(fs.create(dir, &name, 0o644), dest),
    };
    let mut buf = vec![0u8; 4 << 20];
    let mut off = 0u64;
    loop {
        let n = f.read(&mut buf).unwrap_or_else(|e| die(&format!("read {}: {}", src.display(), e)));
        if n == 0 { break; }
        fatal(fs.write(ino, off, &buf[..n]), dest);
        off += n as u64;
    }
}

fn put_tree(fs: &mut Fs<FileDevice>, src: &Path, dest: &str, count: &mut u64) {
    match fs.mkdir_path(dest, 0o755) {
        Ok(_) | Err(aeternafs::Error::Exists) => {}
        Err(e) => die(&format!("{}: {}", dest, e)),
    }
    let mut entries: Vec<_> = std::fs::read_dir(src).unwrap_or_else(|e| die(&format!("{}: {}", src.display(), e))).flatten().collect();
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

fn rm_tree(fs: &mut Fs<FileDevice>, dir: u64, name: &str) {
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

fn main() {
    let o = parse_args();
    let cmd = match o.pos.first() { Some(c) => c.clone(), None => { print!("{}", USAGE); exit(2); } };
    if cmd == "snap" {
        let sub = need(&o, 1, "snapshot command").to_string();
        let img = need(&o, 2, "image").to_string();
        let mut fs = open_fs(&o, &img);
        match sub.as_str() {
            "list" => {
                for s in fatal(fs.snapshot_list(), "snapshots") {
                    println!("{:>4}  gen {:<8} {}  {}", s.id, s.gen, fmt_time(s.time), s.name);
                }
            }
            "create" => fatal(fs.snapshot_create(need(&o, 3, "snapshot name")), "snapshot create"),
            "delete" => fatal(fs.snapshot_delete(need(&o, 3, "snapshot name")), "snapshot delete"),
            "rollback" => fatal(fs.snapshot_rollback(need(&o, 3, "snapshot name")), "snapshot rollback"),
            _ => die("snap: create, list, delete or rollback"),
        }
        return;
    }
    let img = need(&o, 1, "image").to_string();
    if cmd == "mkfs" {
        let dev = open_device(&o, &img, true);
        let blocks = aeternafs::BlockDevice::block_count(&dev);
        let mut dev = fatal(Fs::mkfs(dev, &o.label, now_ns()), "mkfs");
        let _ = aeternafs::BlockDevice::flush(&mut dev);
        println!("formatted {} ({} blocks of 4096, {} MiB), label '{}'", img, blocks, blocks * 4096 >> 20, o.label);
        return;
    }
    let mut fs = open_fs(&o, &img);
    match cmd.as_str() {
        "ls" => {
            let path = o.pos.get(2).map(|s| s.as_str()).unwrap_or("/");
            let ino = fatal(fs.resolve(path), path);
            let st = fatal(fs.stat(ino), path);
            let list = if st.is_dir() { fatal(fs.readdir(ino), path) } else { Vec::new() };
            let mut list = list;
            list.sort_by(|a, b| a.name.cmp(&b.name));
            for e in list {
                if o.long {
                    let s = fatal(fs.stat(e.ino), &e.name);
                    println!("{} {:>12} {} {}{}", mode_str(s.mode), s.size, fmt_time(s.mtime), e.name, if s.is_dir() { "/" } else { "" });
                } else {
                    println!("{}{}", e.name, if e.mode_type == S_IFDIR { "/" } else { "" });
                }
            }
        }
        "cat" | "get" => {
            let path = need(&o, 2, "path");
            let ino = fatal(fs.resolve(path), path);
            let size = fatal(fs.stat(ino), path).size;
            let mut out: Box<dyn Write> = if cmd == "get" {
                Box::new(File::create(need(&o, 3, "output file")).unwrap_or_else(|e| die(&format!("{}", e))))
            } else {
                Box::new(std::io::stdout().lock())
            };
            let mut buf = vec![0u8; 4 << 20];
            let mut off = 0;
            while off < size {
                let n = fatal(fs.read(ino, off, &mut buf), path);
                if n == 0 { break; }
                out.write_all(&buf[..n]).unwrap_or_else(|e| die(&format!("write: {}", e)));
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
                let is_dir = dest.ends_with('/') || fs.resolve(&dest).and_then(|i| fs.stat(i)).map(|s| s.is_dir()).unwrap_or(false);
                if is_dir {
                    let name = src.file_name().unwrap_or_else(|| die("bad source name")).to_string_lossy().into_owned();
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
                if fatal(fs.stat(ino), path).is_dir() { fatal(fs.rmdir(dir, &name), path) } else { fatal(fs.unlink(dir, &name), path) }
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
            if s.is_symlink() { println!("target:  {}", fatal(fs.readlink(ino), path)); }
        }
        "info" => {
            let s = fs.statfs();
            println!("label:      {}", s.label);
            println!("generation: {}", s.generation);
            println!("blocks:     {} total, {} free ({} MiB free)", s.total_blocks, s.free_blocks, s.free_blocks * 4096 >> 20);
            println!("snapshots:  {}", fatal(fs.snapshot_list(), "snapshots").len());
        }
        "fsck" => {
            let r = fatal(fs.fsck(o.deep), "fsck");
            println!("{} trees, {} inodes ({} dirs, {} files, {} symlinks), {} tree nodes, {} data blocks, {} free blocks, {} snapshots",
                r.trees, r.inodes, r.dirs, r.files, r.symlinks, r.nodes, r.data_blocks, r.free_blocks, r.snapshots);
            if r.is_ok() {
                println!("clean{}", if o.deep { " (data checksums verified)" } else { "" });
            } else {
                for e in &r.errors { println!("ERROR: {}", e); }
                exit(1);
            }
        }
        _ => die(&format!("unknown command '{}'\n\n{}", cmd, USAGE)),
    }
}
