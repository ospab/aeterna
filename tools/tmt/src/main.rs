// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! tmt — host tool for ospab.os `.tmt` packages and the tmt.ospab.org repository.
//!
//! ```text
//! tmt keygen [--force] [--key FILE] [--pub FILE]
//! tmt pack <manifest.toml> [-o OUTDIR]
//! tmt list <file.tmt>
//! tmt verify <file.tmt>
//! tmt repo add <repo-dir> <file.tmt>...      copy packages into <repo-dir>/x86_64/
//! tmt repo index <repo-dir>                  write <repo-dir>/x86_64/index
//! tmt repo sign <repo-dir> [--key FILE]      write <repo-dir>/x86_64/index.sig
//! tmt repo verify <repo-dir> [--pub FILE]    check index.sig and every package listed
//! ```
//!
//! The `.tmt` layout is the one tomato (userland/tomato/src/lib.rs) reads; see `pack_tmt`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;

const TMT_MAGIC: [u8; 8] = [b'T', b'M', b'T', 0x01, 0, 0, 0, 0];
const TMT_VERSION: u32 = 1;
const TMT_HEADER_SIZE: usize = 156;
const ARCH_DIR: &str = "x86_64";

type Res<T> = Result<T, String>;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("keygen") => cmd_keygen(&args[1..]),
        Some("pack") => cmd_pack(&args[1..]),
        Some("list") => cmd_list(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        Some("repo") => cmd_repo(&args[1..]),
        _ => {
            usage();
            exit(2);
        }
    };
    if let Err(e) = r {
        eprintln!("tmt: {}", e);
        exit(1);
    }
}

fn usage() {
    eprintln!(
        "usage:
  tmt keygen [--force] [--key FILE] [--pub FILE]
  tmt pack <manifest.toml> [-o OUTDIR]
  tmt list <file.tmt>
  tmt verify <file.tmt>
  tmt repo add <repo-dir> <file.tmt>...
  tmt repo index <repo-dir>
  tmt repo sign <repo-dir> [--key FILE]
  tmt repo verify <repo-dir> [--pub FILE]"
    );
}

// --- helpers ----------------------------------------------------------------

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Res<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.is_ascii() {
        return Err("bad hex string".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| "bad hex digit".to_string()))
        .collect()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn opt(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

fn default_key_path() -> PathBuf {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).unwrap_or_default();
    PathBuf::from(home).join(".ospab").join("tmt.key")
}

fn default_pub_path() -> PathBuf {
    PathBuf::from("userland/tomato/repo_key.pub")
}

fn load_signing_key(path: &Path) -> Res<SigningKey> {
    let txt = fs::read_to_string(path).map_err(|e| format!("cannot read key {}: {}", path.display(), e))?;
    let raw = unhex(&txt)?;
    let seed: [u8; 32] = raw.try_into().map_err(|_| "key file must hold 32 bytes of hex".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

fn load_verifying_key(path: &Path) -> Res<VerifyingKey> {
    let txt = fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let raw = unhex(&txt)?;
    let k: [u8; 32] = raw.try_into().map_err(|_| "public key must be 32 bytes of hex".to_string())?;
    VerifyingKey::from_bytes(&k).map_err(|e| format!("bad public key: {}", e))
}

// --- keygen -----------------------------------------------------------------

fn cmd_keygen(args: &[String]) -> Res<()> {
    let key_path = opt(args, "--key").map(PathBuf::from).unwrap_or_else(default_key_path);
    let pub_path = opt(args, "--pub").map(PathBuf::from).unwrap_or_else(default_pub_path);
    let force = args.iter().any(|a| a == "--force");
    if key_path.exists() && !force {
        return Err(format!(
            "{} already exists; refusing to overwrite the signing key (use --force to replace it)",
            key_path.display()
        ));
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("no entropy: {}", e))?;
    let sk = SigningKey::from_bytes(&seed);
    if let Some(dir) = key_path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    }
    fs::write(&key_path, format!("{}\n", hex(&seed))).map_err(|e| format!("{}: {}", key_path.display(), e))?;
    let pubhex = hex(sk.verifying_key().as_bytes());
    if let Some(dir) = pub_path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
        }
    }
    fs::write(&pub_path, format!("{}\n", pubhex)).map_err(|e| format!("{}: {}", pub_path.display(), e))?;
    // The private key is never printed.
    println!("private key written to {}", key_path.display());
    println!("public key  written to {}", pub_path.display());
    println!("public key (hex): {}", pubhex);
    Ok(())
}

// --- manifest ---------------------------------------------------------------

#[derive(Default, Debug)]
struct Manifest {
    name: String,
    version: String,
    description: String,
    arch: String,
    depends: Vec<String>,
    files: Vec<(String, String)>, // (src, dest)
}

fn unquote(v: &str) -> Res<String> {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        let inner = &v[1..v.len() - 1];
        let mut out = String::new();
        let mut it = inner.chars();
        while let Some(c) = it.next() {
            if c == '\\' {
                match it.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some(o) => out.push(o),
                    None => return Err("dangling backslash in string".into()),
                }
            } else {
                out.push(c);
            }
        }
        Ok(out)
    } else if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
        Ok(v[1..v.len() - 1].to_string())
    } else {
        Err(format!("expected a quoted string, got `{}`", v))
    }
}

fn parse_str_array(v: &str) -> Res<Vec<String>> {
    let v = v.trim();
    let inner = v.strip_prefix('[').and_then(|r| r.strip_suffix(']')).ok_or("expected [..] array")?;
    let mut out = Vec::new();
    for part in inner.split(',') {
        let p = part.trim();
        if !p.is_empty() {
            out.push(unquote(p)?);
        }
    }
    Ok(out)
}

/// Strip a trailing `# comment` that is not inside a string.
fn strip_comment(line: &str) -> &str {
    let mut in_str: Option<char> = None;
    for (i, c) in line.char_indices() {
        match (in_str, c) {
            (None, '"') | (None, '\'') => in_str = Some(c),
            (Some(q), c2) if c2 == q => in_str = None,
            (None, '#') => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Parses the small TOML subset used by package manifests: top-level
/// `key = "string"` / `key = ["a", "b"]` and `[[files]]` tables with `src` / `dest`.
fn parse_manifest(text: &str) -> Res<Manifest> {
    let mut m = Manifest::default();
    let mut cur: Option<(String, String)> = None;
    let flush = |cur: &mut Option<(String, String)>, m: &mut Manifest| -> Res<()> {
        if let Some((s, d)) = cur.take() {
            if s.is_empty() || d.is_empty() {
                return Err("every [[files]] entry needs both src and dest".into());
            }
            m.files.push((s, d));
        }
        Ok(())
    };
    let mut in_files = false;
    for (n, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let ctx = |e: String| format!("manifest line {}: {}", n + 1, e);
        if line == "[[files]]" {
            flush(&mut cur, &mut m).map_err(ctx)?;
            cur = Some((String::new(), String::new()));
            in_files = true;
            continue;
        }
        if line.starts_with('[') {
            return Err(ctx(format!("unsupported table `{}`", line)));
        }
        let (k, v) = line.split_once('=').ok_or_else(|| ctx("expected key = value".into()))?;
        let (k, v) = (k.trim(), v.trim());
        if in_files {
            let c = cur.as_mut().unwrap();
            match k {
                "src" => c.0 = unquote(v).map_err(ctx)?,
                "dest" => c.1 = unquote(v).map_err(ctx)?,
                _ => return Err(ctx(format!("unknown key `{}` in [[files]]", k))),
            }
        } else {
            match k {
                "name" => m.name = unquote(v).map_err(ctx)?,
                "version" => m.version = unquote(v).map_err(ctx)?,
                "description" => m.description = unquote(v).map_err(ctx)?,
                "arch" => m.arch = unquote(v).map_err(ctx)?,
                "depends" => m.depends = parse_str_array(v).map_err(ctx)?,
                _ => return Err(ctx(format!("unknown key `{}`", k))),
            }
        }
    }
    flush(&mut cur, &mut m)?;
    if m.name.is_empty() || m.version.is_empty() {
        return Err("manifest needs name and version".into());
    }
    if m.arch.is_empty() {
        m.arch = "x86_64".into();
    }
    Ok(m)
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 63
        && !n.starts_with('.')
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

// --- .tmt writer / reader ---------------------------------------------------

/// Layout (identical to userland/tomato/src/lib.rs `tmt_pack`):
/// magic(8) version(4) flags(4) arch(4) name(64) pkg_version(32) meta_len(4) payload_len(4)
/// sha256(32, computed with this field zeroed) | metadata `key=value\n`... |
/// payload: repeated [u32 path_len][path][u32 data_len][data].
fn pack_tmt(name: &str, version: &str, arch: u32, meta: &[(&str, String)], files: &[(String, Vec<u8>)]) -> Res<Vec<u8>> {
    if name.len() > 63 || version.len() > 31 {
        return Err("name (max 63) or version (max 31) too long".into());
    }
    let mut meta_bytes = Vec::new();
    for (k, v) in meta {
        if v.contains('\n') {
            return Err(format!("metadata `{}` must be a single line", k));
        }
        meta_bytes.extend_from_slice(format!("{}={}\n", k, v).as_bytes());
    }
    let mut payload = Vec::new();
    for (p, d) in files {
        payload.extend_from_slice(&(p.len() as u32).to_le_bytes());
        payload.extend_from_slice(p.as_bytes());
        payload.extend_from_slice(&u32::try_from(d.len()).map_err(|_| "file larger than 4 GiB")?.to_le_bytes());
        payload.extend_from_slice(d);
    }
    let mut blob = Vec::with_capacity(TMT_HEADER_SIZE + meta_bytes.len() + payload.len());
    blob.extend_from_slice(&TMT_MAGIC);
    blob.extend_from_slice(&TMT_VERSION.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&arch.to_le_bytes());
    let mut nb = [0u8; 64];
    nb[..name.len()].copy_from_slice(name.as_bytes());
    blob.extend_from_slice(&nb);
    let mut vb = [0u8; 32];
    vb[..version.len()].copy_from_slice(version.as_bytes());
    blob.extend_from_slice(&vb);
    blob.extend_from_slice(&(meta_bytes.len() as u32).to_le_bytes());
    blob.extend_from_slice(&u32::try_from(payload.len()).map_err(|_| "payload larger than 4 GiB")?.to_le_bytes());
    blob.extend_from_slice(&[0u8; 32]);
    blob.extend_from_slice(&meta_bytes);
    blob.extend_from_slice(&payload);
    let d = sha256(&blob);
    blob[124..156].copy_from_slice(&d);
    Ok(blob)
}

struct TmtInfo {
    name: String,
    version: String,
    arch: u32,
    meta: String,
    files: Vec<(String, usize)>,
}

fn le32(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn read_tmt(data: &[u8]) -> Res<TmtInfo> {
    if data.len() < TMT_HEADER_SIZE || data[0..8] != TMT_MAGIC {
        return Err("not a .tmt package".into());
    }
    let mut copy = data.to_vec();
    copy[124..156].fill(0);
    if sha256(&copy)[..] != data[124..156] {
        return Err("internal SHA-256 mismatch (package corrupted)".into());
    }
    let arch = le32(data, 16) as u32;
    let (meta_len, payload_len) = (le32(data, 116), le32(data, 120));
    let meta_end = TMT_HEADER_SIZE + meta_len;
    if meta_end + payload_len > data.len() {
        return Err("package truncated".into());
    }
    let payload = &data[meta_end..meta_end + payload_len];
    let mut files = Vec::new();
    let mut c = 0;
    while c < payload.len() {
        if c + 4 > payload.len() {
            return Err("corrupt payload".into());
        }
        let pl = le32(payload, c);
        c += 4;
        if c + pl + 4 > payload.len() {
            return Err("corrupt payload".into());
        }
        let path = String::from_utf8_lossy(&payload[c..c + pl]).into_owned();
        c += pl;
        let dl = le32(payload, c);
        c += 4 + dl;
        if c > payload.len() {
            return Err("corrupt payload".into());
        }
        files.push((path, dl));
    }
    Ok(TmtInfo {
        name: cstr(&data[20..84]),
        version: cstr(&data[84..116]),
        arch,
        meta: String::from_utf8_lossy(&data[TMT_HEADER_SIZE..meta_end]).into_owned(),
        files,
    })
}

fn meta_field<'a>(meta: &'a str, key: &str) -> &'a str {
    meta.lines().find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('='))).unwrap_or("")
}

// --- pack / list / verify ---------------------------------------------------

fn cmd_pack(args: &[String]) -> Res<()> {
    let mpath = args.first().ok_or("usage: tmt pack <manifest.toml> [-o OUTDIR]")?;
    let mpath = Path::new(mpath);
    let text = fs::read_to_string(mpath).map_err(|e| format!("{}: {}", mpath.display(), e))?;
    let m = parse_manifest(&text)?;
    if !valid_name(&m.name) {
        return Err(format!("invalid package name `{}`", m.name));
    }
    for d in &m.depends {
        if !valid_name(d) {
            return Err(format!("invalid dependency name `{}`", d));
        }
    }
    let arch = match m.arch.as_str() {
        "any" => 0u32,
        "x86_64" => 1,
        "aarch64" => 2,
        o => return Err(format!("unknown arch `{}` (any, x86_64, aarch64)", o)),
    };
    let base = mpath.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut files = Vec::new();
    for (src, dest) in &m.files {
        if !dest.starts_with('/') || dest.split('/').any(|c| c == "..") {
            return Err(format!("dest `{}` must be an absolute path without `..`", dest));
        }
        let p = base.join(src);
        let data = fs::read(&p).map_err(|e| format!("{}: {}", p.display(), e))?;
        files.push((dest.clone(), data));
    }
    if files.is_empty() {
        return Err("manifest lists no files".into());
    }
    let mut meta = vec![("description", m.description.replace('\n', " "))];
    if !m.depends.is_empty() {
        meta.push(("depends", m.depends.join(",")));
    }
    let blob = pack_tmt(&m.name, &m.version, arch, &meta, &files)?;
    let outdir = opt(args, "-o").map(PathBuf::from).unwrap_or_else(|| base.to_path_buf());
    fs::create_dir_all(&outdir).map_err(|e| format!("{}: {}", outdir.display(), e))?;
    let out = outdir.join(format!("{}-{}.tmt", m.name, m.version));
    fs::write(&out, &blob).map_err(|e| format!("{}: {}", out.display(), e))?;
    println!("packed {} {} ({} file(s), {} bytes) -> {}", m.name, m.version, files.len(), blob.len(), out.display());
    Ok(())
}

fn cmd_list(args: &[String]) -> Res<()> {
    let p = args.first().ok_or("usage: tmt list <file.tmt>")?;
    let data = fs::read(p).map_err(|e| format!("{}: {}", p, e))?;
    let i = read_tmt(&data)?;
    println!("{} {} (arch {})", i.name, i.version, i.arch);
    println!("description: {}", meta_field(&i.meta, "description"));
    let dep = meta_field(&i.meta, "depends");
    if !dep.is_empty() {
        println!("depends: {}", dep);
    }
    for (f, n) in &i.files {
        println!("  {}  ({} bytes)", f, n);
    }
    Ok(())
}

fn cmd_verify(args: &[String]) -> Res<()> {
    let p = args.first().ok_or("usage: tmt verify <file.tmt>")?;
    let data = fs::read(p).map_err(|e| format!("{}: {}", p, e))?;
    read_tmt(&data)?;
    println!("{}: checksum OK", p);
    Ok(())
}

// --- repository -------------------------------------------------------------

fn cmd_repo(args: &[String]) -> Res<()> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    let dir = args.get(1).map(PathBuf::from).ok_or("usage: tmt repo <add|index|sign|verify> <repo-dir> ...")?;
    let arch_dir = dir.join(ARCH_DIR);
    match sub {
        "add" => {
            fs::create_dir_all(&arch_dir).map_err(|e| format!("{}: {}", arch_dir.display(), e))?;
            for f in &args[2..] {
                let data = fs::read(f).map_err(|e| format!("{}: {}", f, e))?;
                let info = read_tmt(&data).map_err(|e| format!("{}: {}", f, e))?;
                let name = Path::new(f).file_name().ok_or("bad file name")?;
                fs::write(arch_dir.join(name), &data).map_err(|e| e.to_string())?;
                println!("added {}", name.to_string_lossy());
                // Other versions of the same package are removed, so the repository holds one.
                for e in fs::read_dir(&arch_dir).map_err(|e| e.to_string())? {
                    let p = e.map_err(|e| e.to_string())?.path();
                    if p.extension().and_then(|x| x.to_str()) != Some("tmt") || p.file_name() == Some(name) {
                        continue;
                    }
                    let Ok(old) = fs::read(&p) else { continue };
                    if read_tmt(&old).map(|o| o.name == info.name).unwrap_or(false) {
                        fs::remove_file(&p).map_err(|e| format!("{}: {}", p.display(), e))?;
                        println!("removed {}", p.file_name().unwrap().to_string_lossy());
                    }
                }
            }
            Ok(())
        }
        "index" => repo_index(&arch_dir),
        "sign" => {
            let key = opt(args, "--key").map(PathBuf::from).unwrap_or_else(default_key_path);
            let sk = load_signing_key(&key)?;
            let idx = fs::read(arch_dir.join("index"))
                .map_err(|e| format!("index: {} (run `tmt repo index` first)", e))?;
            let sig = sk.sign(&idx);
            fs::write(arch_dir.join("index.sig"), sig.to_bytes()).map_err(|e| e.to_string())?;
            println!(
                "signed {} ({} bytes) -> {}",
                arch_dir.join("index").display(),
                idx.len(),
                arch_dir.join("index.sig").display()
            );
            Ok(())
        }
        "verify" => {
            let pubp = opt(args, "--pub").map(PathBuf::from).unwrap_or_else(default_pub_path);
            repo_verify(&arch_dir, &load_verifying_key(&pubp)?)
        }
        _ => Err("usage: tmt repo <add|index|sign|verify> <repo-dir> ...".into()),
    }
}

/// Numeric-aware version comparison, the same rule as tomato: 1.10 > 1.9, 1.0.1 > 1.0.
fn ver_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let mut x = a.split(|c: char| c == '.' || c == '-');
    let mut y = b.split(|c: char| c == '.' || c == '-');
    loop {
        match (x.next(), y.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(p), Some(q)) => {
                let o = match (p.parse::<u64>(), q.parse::<u64>()) {
                    (Ok(m), Ok(n)) => m.cmp(&n),
                    _ => p.cmp(q),
                };
                if o != std::cmp::Ordering::Equal {
                    return o;
                }
            }
        }
    }
}

/// Index format (UTF-8 text, signed byte-for-byte):
///   line 1:  `tmt-index 1`
///   then one line per package, TAB separated:
///   name  version  size  sha256-hex  depends(comma list or `-`)  filename  description
fn repo_index(arch_dir: &Path) -> Res<()> {
    let mut entries = Vec::new();
    for e in fs::read_dir(arch_dir).map_err(|e| format!("{}: {}", arch_dir.display(), e))? {
        let p = e.map_err(|e| e.to_string())?.path();
        if p.extension().and_then(|x| x.to_str()) != Some("tmt") {
            continue;
        }
        let data = fs::read(&p).map_err(|e| format!("{}: {}", p.display(), e))?;
        let info = read_tmt(&data).map_err(|e| format!("{}: {}", p.display(), e))?;
        let fname = p.file_name().unwrap().to_string_lossy().into_owned();
        let deps = meta_field(&info.meta, "depends");
        let desc = meta_field(&info.meta, "description").replace(['\t', '\n', '\r'], " ");
        entries.push((
            info.name.clone(),
            info.version.clone(),
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                info.name,
                info.version,
                data.len(),
                hex(&sha256(&data)),
                if deps.is_empty() { "-" } else { deps },
                fname,
                desc
            ),
        ));
    }
    // Older versions of a package may stay in the directory; only the newest one is indexed,
    // because clients take the first entry with a matching name.
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| ver_cmp(&b.1, &a.1)));
    entries.dedup_by(|later, first| later.0 == first.0);
    let mut out = String::from("tmt-index 1\n");
    for (_, _, l) in &entries {
        out.push_str(l);
    }
    fs::write(arch_dir.join("index"), out.as_bytes()).map_err(|e| e.to_string())?;
    // A stale signature would make clients reject the repo; remove it so `sign` must run again.
    let _ = fs::remove_file(arch_dir.join("index.sig"));
    println!(
        "indexed {} package(s) -> {}  (now run: tmt repo sign)",
        entries.len(),
        arch_dir.join("index").display()
    );
    Ok(())
}

fn repo_verify(arch_dir: &Path, vk: &VerifyingKey) -> Res<()> {
    let idx = fs::read(arch_dir.join("index")).map_err(|e| format!("index: {}", e))?;
    let sig = fs::read(arch_dir.join("index.sig")).map_err(|e| format!("index.sig: {}", e))?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| "index.sig must be 64 bytes".to_string())?;
    vk.verify(&idx, &Signature::from_bytes(&sig)).map_err(|_| "index signature INVALID".to_string())?;
    println!("index signature OK");
    for line in String::from_utf8_lossy(&idx).lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 7 {
            return Err(format!("malformed index line: {}", line));
        }
        let data = fs::read(arch_dir.join(f[5])).map_err(|e| format!("{}: {}", f[5], e))?;
        if data.len().to_string() != f[2] || hex(&sha256(&data)) != f[3] {
            return Err(format!("{}: size/sha256 does not match the index", f[5]));
        }
        println!("  {} {} OK", f[0], f[1]);
    }
    Ok(())
}
