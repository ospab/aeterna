/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

tomato — package manager for ospab.os (AETERNA)

Packages are `.tmt` files (format below). They can be installed from a local
file, from the local cache, or from a signed repository:

  tomato -Sy                  download + verify the repository index
  tomato -S <name>...         install (dependencies are resolved from the index)
  tomato -Syu | -Su           upgrade installed packages
  tomato -Ss [text]           search the synced index
  tomato -U <file.tmt>        install a package file (no signature: the file's
                              own SHA-256 only detects corruption, not forgery)
  tomato -Q / -Qi / -Ql / -R  query / remove installed packages

Repository: https://tmt.ospab.org/x86_64/ (built in), overridable with
`repo=<url>` lines in /etc/tomato.conf (http:// is allowed for local testing).
The repository serves two files that matter:
    index      "tmt-index 1" + one TAB-separated line per package:
               name version size sha256 depends(comma list or "-") filename description
    index.sig  64-byte Ed25519 signature over the exact bytes of `index`
The signature is checked against the public key compiled into this kernel
(userland/tomato/repo_key.pub); a package is only installed if its size and
SHA-256 match the (signed) index. Anything that fails is refused.

Installed package records: /var/lib/tomato/local/<name>
  (name=, version=, depends=, installed_from=, file=<path> per installed file)
*/

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::userspace::plum::io;

const LOCAL_PATH: &str = "/var/lib/tomato/local";
const SYNC_PATH: &str = "/var/lib/tomato/sync";
const CACHE_PATH: &str = "/var/cache/tomato/pkg";
const CONF_PATH: &str = "/etc/tomato.conf";
const DEFAULT_REPO: &str = "https://tmt.ospab.org/x86_64/";
/// Ed25519 public key of the official repository (32 bytes, hex).
const REPO_PUBKEY_HEX: &str = include_str!("../repo_key.pub");
const MAX_INDEX: usize = 1024 * 1024;
const MAX_PACKAGE: usize = 8 * 1024 * 1024;

fn ensure_dirs() {
    for d in ["/etc", "/var", "/var/lib", "/var/lib/tomato", LOCAL_PATH, SYNC_PATH, "/var/cache", "/var/cache/tomato", CACHE_PATH] {
        if !crate::fs::exists(d) { crate::fs::mkdir(d); }
    }
}

fn usage() {
    io::out_c("tomato", io::FG_OK);
    io::out(" - package manager for ospab.os (.tmt packages)

");
    io::out("  tomato update                  download and verify the package index
");
    io::out("  tomato upgrade                 upgrade installed packages (run update first)
");
    io::out("  tomato install <name>...       install packages and their dependencies
");
    io::out("  tomato install <file.tmt>...   install package files
");
    io::out("  tomato remove <name>...        remove packages (only the files they installed)
");
    io::out("  tomato search [text]           search the package index
");
    io::out("  tomato list                    list installed packages
");
    io::out("  tomato show <name>             package info
");
    io::out("  tomato files <name>            files installed by a package
");
    io::out("  tomato --tmt pack <name> <version> <out.tmt> [-d desc] <file>...  build a package
");
    io::out("  tomato --tmt list|verify|install <file.tmt>
");
    io::out("
The pacman-style flags (-Sy, -S, -Syu, -Ss, -U, -R, -Q, -Qi, -Ql) still work.
");
    io::out("repository: ");
    io::out(&repos().join(" "));
    io::out("  (override with repo=<url> in /etc/tomato.conf)
");
}

fn record_path(name: &str) -> String {
    alloc::format!("{}/{}", LOCAL_PATH, name)
}

fn valid_pkg_name(n: &str) -> bool {
    !n.is_empty() && !n.starts_with('.')
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn read_record(name: &str) -> Option<String> {
    if !valid_pkg_name(name) { return None; }
    crate::fs::read_file(&record_path(name)).map(|d| String::from_utf8_lossy(&d).into_owned())
}

fn record_field<'a>(rec: &'a str, key: &str) -> Option<&'a str> {
    rec.lines().find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
}

/// Execute tomato with the given arguments.
pub fn run(args: &str) {
    let args = args.trim();
    if let Some(rest) = args.strip_prefix("--tmt") {
        tmt_dispatch(rest.trim());
        return;
    }
    let mut parts = args.split_whitespace();
    let op = parts.next().unwrap_or("");
    // apt-style answers to "are you sure" are not asked, so -y is accepted and ignored
    let targets: Vec<&str> = parts.filter(|t| *t != "-y" && *t != "--yes").collect();
    // apt-style verbs map onto the original pacman-style operations
    let op = match op {
        "update" => "-Sy",
        "upgrade" | "full-upgrade" => "-Su",
        "install" if !targets.is_empty() && targets.iter().all(|t| t.ends_with(".tmt") || t.contains('/')) => "-U",
        "install" => "-S",
        "remove" | "uninstall" | "purge" => "-R",
        "search" => "-Ss",
        "list" => "-Q",
        "show" | "info" => "-Qi",
        "files" => "-Ql",
        o => o,
    };
    match op {
        "" | "-h" | "--help" | "help" => usage(),
        "-Sy" | "-Syy" => {
            if !sync() { return; }
            if !targets.is_empty() { for t in &targets { install_by_name(t); } }
        }
        "-Syu" | "-Syyu" => {
            if sync() { upgrade(); }
        }
        "-Su" => upgrade(),
        "-S" => {
            if targets.is_empty() { io::err("tomato: no targets specified\n"); return; }
            install_many(&targets);
        }
        "-U" => {
            if targets.is_empty() { io::err("tomato: no package files specified\n"); return; }
            for t in targets {
                let p = crate::userspace::plum::resolve_path(t);
                tmt_install(&p);
            }
        }
        "-R" | "-Rs" | "-Rns" | "-Rdd" => {
            if targets.is_empty() { io::err("tomato: no targets specified\n"); return; }
            for t in targets { remove(t, op == "-Rdd"); }
        }
        "-Q" => {
            if targets.is_empty() {
                list_installed();
            } else {
                for t in targets {
                    match read_record(t) {
                        Some(r) => io::out(&alloc::format!("{} {}\n", t, record_field(&r, "version").unwrap_or("?"))),
                        None => { io::err("tomato: package '"); io::err(t); io::err("' was not found\n"); }
                    }
                }
            }
        }
        "-Qi" | "-Ql" => {
            if targets.is_empty() { io::err("tomato: no targets specified\n"); return; }
            for t in targets { info(t, op == "-Ql"); }
        }
        "-Ss" => search(&targets.join(" ")),
        _ => {
            io::err("tomato: invalid operation '");
            io::err(op);
            io::err("' (try: tomato --help)\n");
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Repository: configuration, signed index, dependency resolution, download
// ══════════════════════════════════════════════════════════════════════════════

/// Repository base URLs (each ends with '/'), from /etc/tomato.conf or the built-in default.
fn repos() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    if let Some(d) = crate::fs::read_file(CONF_PATH) {
        for line in String::from_utf8_lossy(&d).lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if let Some(rest) = line.strip_prefix("repo") {
                if let Some(url) = rest.trim_start().strip_prefix('=') {
                    let url = url.trim();
                    if url.starts_with("https://") || url.starts_with("http://") {
                        let mut u = String::from(url);
                        if !u.ends_with('/') { u.push('/'); }
                        v.push(u);
                    }
                }
            }
        }
    }
    if v.is_empty() { v.push(String::from(DEFAULT_REPO)); }
    v
}

/// One package line of the repository index.
#[derive(Clone)]
struct RepoPkg {
    name: String,
    version: String,
    size: usize,
    sha256: [u8; 32],
    depends: Vec<String>,
    filename: String,
    desc: String,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.is_ascii() { return None; }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..s.len() / 2 {
        out.push(u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?);
    }
    Some(out)
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b { s.push_str(&alloc::format!("{:02x}", x)); }
    s
}

/// Check `sig` (64 bytes) over `msg` against the compiled-in repository key.
fn verify_index_signature(msg: &[u8], sig: &[u8]) -> Result<(), &'static str> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let key: [u8; 32] = unhex(REPO_PUBKEY_HEX).and_then(|k| k.try_into().ok()).ok_or("built-in repository key is malformed")?;
    let vk = VerifyingKey::from_bytes(&key).map_err(|_| "built-in repository key is invalid")?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| "signature file is not 64 bytes")?;
    vk.verify(msg, &Signature::from_bytes(&sig)).map_err(|_| "signature does not match")
}

/// Parse a (already verified) index.
fn parse_index(idx: &[u8]) -> Option<Vec<RepoPkg>> {
    let text = core::str::from_utf8(idx).ok()?;
    let mut lines = text.lines();
    if lines.next()? != "tmt-index 1" { return None; }
    let mut v = Vec::new();
    for l in lines {
        if l.is_empty() { continue; }
        let f: Vec<&str> = l.splitn(7, '\t').collect();
        if f.len() < 7 || !valid_pkg_name(f[0]) { return None; }
        let sha: [u8; 32] = unhex(f[3])?.try_into().ok()?;
        if f[5].contains('/') || f[5].contains("..") || f[5].is_empty() { return None; }
        v.push(RepoPkg {
            name: String::from(f[0]),
            version: String::from(f[1]),
            size: f[2].parse().ok()?,
            sha256: sha,
            depends: if f[4] == "-" || f[4].is_empty() { Vec::new() } else { f[4].split(',').map(String::from).collect() },
            filename: String::from(f[5]),
            desc: String::from(f[6]),
        });
    }
    // An index may list several versions of a package; keep only the newest, so every lookup
    // by name (which takes the first match) gets it.
    v.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| ver_cmp(&b.version, &a.version)));
    v.dedup_by(|later, first| later.name == first.name);
    Some(v)
}

/// Synced index + the repository it came from. The signature is re-checked on every load,
/// so a tampered file in /var/lib/tomato/sync is rejected as well.
fn load_synced() -> Option<(String, Vec<RepoPkg>)> {
    let idx = crate::fs::read_file(&alloc::format!("{}/index", SYNC_PATH))?;
    let sig = crate::fs::read_file(&alloc::format!("{}/index.sig", SYNC_PATH))?;
    let base = String::from_utf8_lossy(&crate::fs::read_file(&alloc::format!("{}/repo", SYNC_PATH))?).trim().into();
    if let Err(e) = verify_index_signature(&idx, &sig) {
        io::err("tomato: the synced index failed signature verification (");
        io::err(e);
        io::err("); ignoring it - run 'tomato update'\n");
        return None;
    }
    Some((base, parse_index(&idx)?))
}

fn http_get(url: &str, max: usize) -> Result<Vec<u8>, String> {
    crate::userspace::axon::net_tools::http_get(url, max)
}

/// `tomato -Sy`: fetch index + signature, verify, store. Returns true on success.
fn sync() -> bool {
    ensure_dirs();
    let mut last_err = String::new();
    for base in repos() {
        io::out(&alloc::format!(":: synchronizing {}\n", base));
        let idx = match http_get(&alloc::format!("{}index", base), MAX_INDEX) {
            Ok(d) => d,
            Err(e) => { last_err = alloc::format!("{}: {}", base, e); io::err(&alloc::format!("tomato: {}\n", last_err)); continue; }
        };
        let sig = match http_get(&alloc::format!("{}index.sig", base), 1024) {
            Ok(d) => d,
            Err(e) => { last_err = alloc::format!("{}: {}", base, e); io::err(&alloc::format!("tomato: {}\n", last_err)); continue; }
        };
        if let Err(e) = verify_index_signature(&idx, &sig) {
            io::err(&alloc::format!(
                "tomato: SIGNATURE CHECK FAILED for {}index ({}).\n        The index was not signed by the ospab.os repository key; refusing to use it.\n",
                base, e));
            last_err = String::from("signature check failed");
            continue;
        }
        let pkgs = match parse_index(&idx) {
            Some(p) => p,
            None => { io::err("tomato: the index is signed but malformed; refusing to use it\n"); continue; }
        };
        crate::fs::write_file(&alloc::format!("{}/index", SYNC_PATH), &idx);
        crate::fs::write_file(&alloc::format!("{}/index.sig", SYNC_PATH), &sig);
        crate::fs::write_file(&alloc::format!("{}/repo", SYNC_PATH), base.as_bytes());
        io::out(&alloc::format!("   index signature OK, {} package(s) available\n", pkgs.len()));
        return true;
    }
    io::err("tomato: synchronization failed");
    if !last_err.is_empty() { io::err(": "); io::err(&last_err); }
    io::err("\n");
    false
}

/// Numeric-aware version comparison: 1.10 > 1.9, 1.0.1 > 1.0.
fn ver_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    let mut ai = a.split(|c| c == '.' || c == '-' || c == '+');
    let mut bi = b.split(|c| c == '.' || c == '-' || c == '+');
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (Some(x), None) => return if x.parse::<u64>() == Ok(0) { Ordering::Equal } else { Ordering::Greater },
            (None, Some(y)) => return if y.parse::<u64>() == Ok(0) { Ordering::Equal } else { Ordering::Less },
            (Some(x), Some(y)) => {
                let o = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(p), Ok(q)) => p.cmp(&q),
                    _ => x.cmp(y),
                };
                if o != Ordering::Equal { return o; }
            }
        }
    }
}

/// Add `name` and (first) its dependencies to `plan`, dependencies before dependents.
fn resolve(name: &str, pkgs: &[RepoPkg], plan: &mut Vec<RepoPkg>, stack: &mut Vec<String>, force: bool) -> Result<(), String> {
    if plan.iter().any(|p| p.name == name) { return Ok(()); }
    if stack.iter().any(|s| s == name) {
        return Err(alloc::format!("dependency cycle involving '{}'", name));
    }
    let p = pkgs.iter().find(|p| p.name == name)
        .ok_or_else(|| alloc::format!("target not found: {}", name))?;
    // A dependency that is already installed is satisfied; explicit targets are (re)installed.
    if !force {
        if let Some(rec) = read_record(name) {
            if ver_cmp(record_field(&rec, "version").unwrap_or("0"), &p.version) != core::cmp::Ordering::Less {
                return Ok(());
            }
        }
    }
    stack.push(String::from(name));
    for d in &p.depends {
        resolve(d, pkgs, plan, stack, false).map_err(|e| {
            if e.starts_with("target not found") {
                alloc::format!("{} (required by {})", e, name)
            } else { e }
        })?;
    }
    stack.pop();
    plan.push(p.clone());
    Ok(())
}

/// Download `p` from `base`, verify size + SHA-256 against the signed index, cache it.
/// Returns the verified package bytes.
fn fetch_verified(base: &str, p: &RepoPkg) -> Option<Vec<u8>> {
    let url = alloc::format!("{}{}", base, p.filename);
    io::out(&alloc::format!("   downloading {} ({} bytes)\n", p.filename, p.size));
    let data = match http_get(&url, p.size.max(1).min(MAX_PACKAGE)) {
        Ok(d) => d,
        Err(e) => { io::err(&alloc::format!("tomato: {}\n", e)); return None; }
    };
    if data.len() != p.size {
        io::err(&alloc::format!(
            "tomato: {}: size {} does not match the signed index ({}); refusing to install\n",
            p.filename, data.len(), p.size));
        return None;
    }
    if sha256_hash(&data) != p.sha256 {
        io::err(&alloc::format!(
            "tomato: {}: SHA-256 does not match the signed index; the download is corrupted or tampered with.\n        refusing to install\n",
            p.filename));
        return None;
    }
    Some(data)
}

/// Install the planned packages in order. Everything is downloaded and verified
/// before the first file is written.
fn install_plan(base: &str, plan: &[RepoPkg]) -> bool {
    if plan.is_empty() { return true; }
    let names: Vec<String> = plan.iter().map(|p| alloc::format!("{}-{}", p.name, p.version)).collect();
    io::out(&alloc::format!("Packages ({}): {}\n", plan.len(), names.join(" ")));
    let total: usize = plan.iter().map(|p| p.size).sum();
    io::out(&alloc::format!("Total download size: {} bytes\n", total));
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    for p in plan {
        match fetch_verified(base, p) {
            Some(d) => blobs.push(d),
            None => { io::err("tomato: nothing was installed\n"); return false; }
        }
    }
    for (p, blob) in plan.iter().zip(blobs.iter()) {
        match tmt_parse_header(blob) {
            Some(h) if h.name == p.name && h.pkg_version == p.version => {}
            _ => {
                io::err(&alloc::format!("tomato: {}: package header does not match the index entry; refusing to install\n", p.filename));
                return false;
            }
        }
        let cached = alloc::format!("{}/{}", CACHE_PATH, p.filename);
        crate::fs::write_file(&cached, blob);
        if !install_blob(blob, &cached) { return false; }
    }
    true
}

fn install_many(targets: &[&str]) {
    ensure_dirs();
    let synced = load_synced();
    let mut plan: Vec<RepoPkg> = Vec::new();
    let mut local: Vec<&str> = Vec::new();
    for t in targets {
        match &synced {
            Some((_, pkgs)) if pkgs.iter().any(|p| p.name == *t) => {
                if let Err(e) = resolve(t, pkgs, &mut plan, &mut Vec::new(), true) {
                    io::err(&alloc::format!("tomato: {}\n", e));
                    io::err("tomato: nothing was installed\n");
                    return;
                }
            }
            _ => local.push(t),
        }
    }
    if let Some((base, _)) = &synced {
        if !install_plan(base, &plan) { return; }
    }
    for t in local {
        install_by_name_local(t, synced.is_some());
    }
}

fn install_by_name(name: &str) { install_many(&[name]); }

/// Upgrade every installed package that is older than the synced index.
fn upgrade() {
    ensure_dirs();
    let (base, pkgs) = match load_synced() {
        Some(s) => s,
        None => { io::err("tomato: no valid synced index; run 'tomato update' first\n"); return; }
    };
    let mut plan: Vec<RepoPkg> = Vec::new();
    if let Some(entries) = crate::fs::readdir(LOCAL_PATH) {
        for e in entries {
            let rec = match read_record(&e.name) { Some(r) => r, None => continue };
            let have = record_field(&rec, "version").unwrap_or("0");
            if let Some(p) = pkgs.iter().find(|p| p.name == e.name) {
                if ver_cmp(have, &p.version) == core::cmp::Ordering::Less {
                    io::out(&alloc::format!(":: {} {} -> {}\n", e.name, have, p.version));
                    if let Err(err) = resolve(&e.name, &pkgs, &mut plan, &mut Vec::new(), true) {
                        io::err(&alloc::format!("tomato: {}\n", err));
                        return;
                    }
                }
            }
        }
    }
    if plan.is_empty() {
        io::out("there is nothing to do: all installed packages are up to date\n");
        return;
    }
    install_plan(&base, &plan);
}

// ─── local cache (packages copied into /var/cache/tomato/pkg by hand) ──────────

/// Packages in the local cache: (path, header, description)
fn cache_packages() -> Vec<(String, TmtHeader, String)> {
    let mut v = Vec::new();
    if let Some(entries) = crate::fs::readdir(CACHE_PATH) {
        for e in entries {
            if !e.name.ends_with(".tmt") { continue; }
            let p = alloc::format!("{}/{}", CACHE_PATH, e.name);
            if let Some(data) = crate::fs::read_file(&p) {
                if let Some(h) = tmt_parse_header(&data) {
                    let start = TMT_HEADER_SIZE.min(data.len());
                    let end = (TMT_HEADER_SIZE + h.meta_len as usize).min(data.len());
                    let meta = String::from_utf8_lossy(&data[start..end]).into_owned();
                    let desc = String::from(record_field(&meta, "description").unwrap_or(""));
                    v.push((p, h, desc));
                }
            }
        }
    }
    v
}

fn install_by_name_local(name: &str, have_index: bool) {
    ensure_dirs();
    match cache_packages().into_iter().find(|(_, h, _)| h.name == name) {
        Some((path, _, _)) => { tmt_install(&path); }
        None => {
            io::err("tomato: target not found: ");
            io::err(name);
            if have_index {
                io::err("\n");
            } else {
                io::err("\n        (no package index yet: run 'tomato update'; local packages are looked up in ");
                io::err(CACHE_PATH);
                io::err(")\n");
            }
        }
    }
}

fn search(q: &str) {
    let q = q.to_ascii_lowercase();
    let mut found = 0;
    if let Some((base, pkgs)) = load_synced() {
        io::out_c(&alloc::format!("repository {}\n", base), io::FG_DIM);
        for p in &pkgs {
            if !q.is_empty() && !p.name.to_ascii_lowercase().contains(&q) && !p.desc.to_ascii_lowercase().contains(&q) {
                continue;
            }
            found += 1;
            io::out_c(&p.name, io::FG_OK);
            io::out(" ");
            io::out_c(&p.version, io::FG_WARN);
            if let Some(rec) = read_record(&p.name) {
                io::out_c(&alloc::format!(" [installed {}]", record_field(&rec, "version").unwrap_or("?")), io::FG_DIM);
            }
            io::out("\n    ");
            io::out(if p.desc.is_empty() { "(no description)" } else { &p.desc });
            io::out("\n");
        }
        if found == 0 { io::err("tomato: no matching packages in the synced index\n"); }
        return;
    }
    for (path, h, desc) in cache_packages() {
        if !q.is_empty() && !h.name.to_ascii_lowercase().contains(&q) && !desc.to_ascii_lowercase().contains(&q) {
            continue;
        }
        found += 1;
        io::out_c(&h.name, io::FG_OK);
        io::out(" ");
        io::out_c(&h.pkg_version, io::FG_WARN);
        if read_record(&h.name).is_some() { io::out_c(" [installed]", io::FG_DIM); }
        io::out("\n    ");
        io::out(if desc.is_empty() { "(no description)" } else { &desc });
        io::out_c(&alloc::format!("  ({})\n", path), io::FG_DIM);
    }
    if found == 0 {
        io::err("tomato: no synced index (run 'tomato update') and no matching packages in ");
        io::err(CACHE_PATH);
        io::err("\n");
    }
}

fn list_installed() {
    let mut n = 0;
    if let Some(mut entries) = crate::fs::readdir(LOCAL_PATH) {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for e in entries {
            let rec = read_record(&e.name).unwrap_or_default();
            io::out_c(&e.name, io::FG_OK);
            io::out(" ");
            io::out(record_field(&rec, "version").unwrap_or("?"));
            io::out("\n");
            n += 1;
        }
    }
    if n == 0 {
        io::out_c("No packages installed.\n", io::FG_DIM);
    }
}

fn info(name: &str, files_only: bool) {
    let rec = match read_record(name) {
        Some(r) => r,
        None => { io::err("tomato: package '"); io::err(name); io::err("' was not found\n"); return; }
    };
    if files_only {
        for l in rec.lines() {
            if let Some(f) = l.strip_prefix("file=") { io::out(name); io::out(" "); io::out(f); io::out("\n"); }
        }
        return;
    }
    let files = rec.lines().filter(|l| l.starts_with("file=")).count();
    io::out(&alloc::format!("Name           : {}\n", name));
    io::out(&alloc::format!("Version        : {}\n", record_field(&rec, "version").unwrap_or("?")));
    io::out(&alloc::format!("Description    : {}\n", record_field(&rec, "description").unwrap_or("")));
    io::out(&alloc::format!("Depends on     : {}\n", record_field(&rec, "depends").filter(|d| !d.is_empty()).unwrap_or("None")));
    io::out(&alloc::format!("Installed from : {}\n", record_field(&rec, "installed_from").unwrap_or("?")));
    io::out(&alloc::format!("Files          : {}\n", files));
}

fn remove(name: &str, skip_dep_check: bool) {
    let rec = match read_record(name) {
        Some(r) => r,
        None => { io::err("tomato: target not found: "); io::err(name); io::err("\n"); return; }
    };
    if !skip_dep_check {
        if let Some(entries) = crate::fs::readdir(LOCAL_PATH) {
            for e in entries {
                if e.name == name { continue; }
                let other = read_record(&e.name).unwrap_or_default();
                let needs = record_field(&other, "depends").unwrap_or("").split(',').any(|d| d == name);
                if needs {
                    io::err(&alloc::format!("tomato: cannot remove {}: required by {} (use -Rdd to override)\n", name, e.name));
                    return;
                }
            }
        }
    }
    let mut removed = 0;
    let mut missing = 0;
    for l in rec.lines() {
        if let Some(f) = l.strip_prefix("file=") {
            if crate::fs::exists(f) {
                if crate::fs::remove(f) {
                    removed += 1;
                } else {
                    io::err("tomato: could not remove ");
                    io::err(f);
                    io::err("\n");
                }
            } else {
                missing += 1;
            }
        }
    }
    crate::fs::remove(&record_path(name));
    io::out(&alloc::format!("removed {}: {} file(s) deleted", name, removed));
    if missing > 0 { io::out(&alloc::format!(", {} were already missing", missing)); }
    io::out("\n");
}

// ══════════════════════════════════════════════════════════════════════════════
//  .tmt — AETERNA binary package format
//
//  Offset  Size  Field
//       0     8  Magic: [b'T',b'M',b'T',0x01, 0x00,0x00,0x00,0x00]
//       8     4  Format version (LE u32 = 1)
//      12     4  Flags (LE u32; bit 0 = compressed, bit 1 = signed)
//      16     4  Architecture (LE u32; 0=any, 1=x86_64, 2=aarch64)
//      20    64  Package name (UTF-8, null-padded, max 63 chars)
//      84    32  Package version (UTF-8, null-padded, max 31 chars)
//     116     4  meta_len    — length of metadata section (LE u32)
//     120     4  payload_len — length of payload section (LE u32)
//     124    32  SHA-256 over the blob with bytes 124..156 zeroed
//     156    meta_len  metadata: UTF-8 key=value lines (description, ...)
//    156+meta_len  payload: [u32 path_len][path][u32 data_len][data] ...
// ══════════════════════════════════════════════════════════════════════════════

/// Magic bytes for .tmt format
pub const TMT_MAGIC: [u8; 8] = [b'T', b'M', b'T', 0x01, 0x00, 0x00, 0x00, 0x00];
pub const TMT_VERSION: u32 = 1;
pub const TMT_HEADER_SIZE: usize = 156; // bytes before metadata section

// Architecture constants
pub const TMT_ARCH_ANY:   u32 = 0;
pub const TMT_ARCH_X64:   u32 = 1;
pub const TMT_ARCH_AA64:  u32 = 2;

/// A single file entry inside a .tmt payload
pub struct TmtFile<'a> {
    pub path: &'a str,
    pub data: &'a [u8],
}

/// Metadata parsed from a .tmt header
pub struct TmtHeader {
    pub version:     u32,
    pub flags:       u32,
    pub arch:        u32,
    pub name:        String,
    pub pkg_version: String,
    pub meta_len:    u32,
    pub payload_len: u32,
    pub checksum:    [u8; 32],
}

// ─── Pack: create a .tmt blob from metadata + files ──────────────────────

/// Create a `.tmt` package blob in memory.
///
/// # Arguments
/// * `name`       — package name (max 63 bytes)
/// * `version`    — package version string (max 31 bytes)
/// * `arch`       — TMT_ARCH_ANY / TMT_ARCH_X64 / TMT_ARCH_AA64
/// * `metadata`   — UTF-8 key=value lines (appended together with '\n')
/// * `files`      — slice of (path, data) tuples to embed
///
/// Returns the complete .tmt blob with a valid SHA-256 checksum.
pub fn tmt_pack(
    name: &str,
    version: &str,
    arch: u32,
    metadata: &[(&str, &str)],
    files: &[(&str, &[u8])],
) -> alloc::vec::Vec<u8>
{
    // ── Build metadata section ───────────────────────────────────────────
    let mut meta_bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for (k, v) in metadata {
        for b in k.as_bytes() { meta_bytes.push(*b); }
        meta_bytes.push(b'=');
        for b in v.as_bytes() { meta_bytes.push(*b); }
        meta_bytes.push(b'\n');
    }

    // ── Build payload section ────────────────────────────────────────────
    let mut payload: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for (path, data) in files {
        let pb = path.as_bytes();
        let path_len = pb.len() as u32;
        let data_len = data.len() as u32;
        for b in &path_len.to_le_bytes() { payload.push(*b); }
        payload.extend_from_slice(pb);
        for b in &data_len.to_le_bytes() { payload.push(*b); }
        payload.extend_from_slice(data);
    }

    // ── Build header ─────────────────────────────────────────────────────
    let mut blob: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(
        TMT_HEADER_SIZE + meta_bytes.len() + payload.len()
    );

    // Magic (8)
    blob.extend_from_slice(&TMT_MAGIC);
    // Version (4)
    blob.extend_from_slice(&TMT_VERSION.to_le_bytes());
    // Flags (4) — no compression, no external sig
    blob.extend_from_slice(&0u32.to_le_bytes());
    // Arch (4)
    blob.extend_from_slice(&arch.to_le_bytes());
    // Name (64)
    let nb = name.as_bytes();
    let nlen = nb.len().min(63);
    blob.extend_from_slice(&nb[..nlen]);
    for _ in nlen..64 { blob.push(0); }
    // Version (32)
    let vb = version.as_bytes();
    let vlen = vb.len().min(31);
    blob.extend_from_slice(&vb[..vlen]);
    for _ in vlen..32 { blob.push(0); }
    // meta_len (4)
    blob.extend_from_slice(&(meta_bytes.len() as u32).to_le_bytes());
    // payload_len (4)
    blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    // SHA-256 placeholder (32 zeros — to be replaced after hash)
    for _ in 0..32 { blob.push(0); }

    // Append data sections
    blob.extend_from_slice(&meta_bytes);
    blob.extend_from_slice(&payload);

    // ── Compute SHA-256 over the full blob (checksum field = zeros) ──────
    let digest = sha256_hash(&blob);
    // Write digest at offset 124
    blob[124..156].copy_from_slice(&digest);

    blob
}

// ─── Verify: check SHA-256 checksum ──────────────────────────────────────

/// Verify the SHA-256 checksum of a `.tmt` blob.  
/// Returns `true` if the checksum matches.
pub fn tmt_verify(data: &[u8]) -> bool {
    if data.len() < TMT_HEADER_SIZE { return false; }
    // Check magic
    if &data[0..8] != &TMT_MAGIC { return false; }

    // Extract stored checksum
    let stored: [u8; 32] = match data[124..156].try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    // Zero the checksum field in a copy, then hash
    let mut copy: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(data.len());
    copy.extend_from_slice(data);
    for b in &mut copy[124..156] { *b = 0; }
    let computed = sha256_hash(&copy);

    computed == stored
}

// ─── Parse header ────────────────────────────────────────────────────────

/// Parse the header from a `.tmt` blob.
pub fn tmt_parse_header(data: &[u8]) -> Option<TmtHeader> {
    if data.len() < TMT_HEADER_SIZE { return None; }
    if &data[0..8] != &TMT_MAGIC { return None; }

    let version     = u32::from_le_bytes(data[8..12].try_into().ok()?);
    let flags       = u32::from_le_bytes(data[12..16].try_into().ok()?);
    let arch        = u32::from_le_bytes(data[16..20].try_into().ok()?);

    let name_end = data[20..84].iter().position(|&b| b == 0).unwrap_or(64);
    let name    = String::from(core::str::from_utf8(&data[20..20+name_end]).unwrap_or("?"));

    let ver_end = data[84..116].iter().position(|&b| b == 0).unwrap_or(32);
    let pkg_version = String::from(core::str::from_utf8(&data[84..84+ver_end]).unwrap_or("?"));

    let meta_len    = u32::from_le_bytes(data[116..120].try_into().ok()?);
    let payload_len = u32::from_le_bytes(data[120..124].try_into().ok()?);
    let checksum: [u8; 32] = data[124..156].try_into().ok()?;

    Some(TmtHeader { version, flags, arch, name, pkg_version, meta_len, payload_len, checksum })
}

// ─── List contents: peek inside a .tmt without extracting ────────────────

/// List all files embedded in a `.tmt` blob without extracting them.
/// Returns a Vec of paths, or empty if the blob is invalid.
pub fn tmt_list_contents(data: &[u8]) -> alloc::vec::Vec<String> {
    let mut paths: alloc::vec::Vec<String> = alloc::vec::Vec::new();

    let hdr = match tmt_parse_header(data) { Some(h) => h, None => return paths };
    let payload_start = TMT_HEADER_SIZE + hdr.meta_len as usize;
    let payload_end   = payload_start + hdr.payload_len as usize;
    if payload_end > data.len() { return paths; }

    let payload = &data[payload_start..payload_end];
    let mut cursor = 0usize;

    while cursor + 8 <= payload.len() {
        let path_len = u32::from_le_bytes(
            payload[cursor..cursor+4].try_into().unwrap_or([0u8;4])
        ) as usize;
        cursor += 4;
        if cursor + path_len > payload.len() { break; }
        if let Ok(p) = core::str::from_utf8(&payload[cursor..cursor+path_len]) {
            paths.push(String::from(p));
        }
        cursor += path_len;
        if cursor + 4 > payload.len() { break; }
        let data_len = u32::from_le_bytes(
            payload[cursor..cursor+4].try_into().unwrap_or([0u8;4])
        ) as usize;
        cursor += 4 + data_len;
    }
    paths
}

// ─── SHA-256 implementation (FIPS 180-4, no_std) ─────────────────────────

/// Compute SHA-256 over arbitrary data. Pure Rust, no_std.
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    // Initial hash values (first 32 bits of fractional parts of sqrt of primes 2..19)
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Round constants (first 32 bits of fractional parts of cbrt of primes 2..311)
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // Pre-processing: add padding
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(
        data.len() + 64 + 8
    );
    padded.extend_from_slice(data);
    padded.push(0x80); // append bit '1'
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    // Append original length as big-endian u64
    for b in &bit_len.to_be_bytes() { padded.push(*b); }

    // Process each 512-bit (64-byte) chunk
    for chunk in padded.chunks_exact(64) {
        // Prepare message schedule
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7)  ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17)  ^ w[i-2].rotate_right(19)  ^ (w[i-2]  >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        // Initialize working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        // 64-round compression function
        for i in 0..64 {
            let s1    = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch    = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0    = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj   = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g; g = f; f = e;
            e = d.wrapping_add(temp1);
            d = c; c = b; b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add compressed chunk to current hash value
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    // Produce final digest (big-endian)
    let mut digest = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        digest[i*4..i*4+4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

// ─── Install: extract a .tmt from a VFS path ─────────────────────────────

fn safe_path(p: &str) -> Option<String> {
    let p = if p.starts_with('/') { String::from(p) } else { alloc::format!("/{}", p) };
    if p.split('/').any(|c| c == "..") || p == "/" || p.starts_with("/proc") {
        return None;
    }
    Some(p)
}

fn le_u32(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize
}

/// Read a `.tmt` file, verify its SHA-256 and extract the embedded files.
pub fn tmt_install(vfs_path: &str) -> bool {
    ensure_dirs();
    let data = match crate::fs::read_file(vfs_path) {
        Some(d) => d,
        None => { io::err("tomato: "); io::err(vfs_path); io::err(": No such file\n"); return false; }
    };
    if tmt_parse_header(&data).is_none() {
        io::err("tomato: "); io::err(vfs_path); io::err(": not a .tmt package\n");
        return false;
    }
    install_blob(&data, vfs_path)
}

/// Verify the package's own checksum and extract it. `source` is recorded as `installed_from`.
fn install_blob(data: &[u8], source: &str) -> bool {
    let vfs_path = source;
    let hdr = match tmt_parse_header(data) {
        Some(h) => h,
        None => { io::err("tomato: "); io::err(vfs_path); io::err(": not a .tmt package\n"); return false; }
    };
    if hdr.arch != TMT_ARCH_ANY && hdr.arch != TMT_ARCH_X64 {
        io::err("tomato: package is built for another architecture; nothing installed\n");
        return false;
    }
    if !tmt_verify(data) {
        io::err("tomato: SHA-256 checksum mismatch - package is corrupted; nothing installed\n");
        return false;
    }
    if !valid_pkg_name(&hdr.name) {
        io::err("tomato: invalid package name in header\n");
        return false;
    }
    let meta_end = TMT_HEADER_SIZE + hdr.meta_len as usize;
    let payload_end = meta_end + hdr.payload_len as usize;
    if payload_end > data.len() {
        io::err("tomato: package truncated\n");
        return false;
    }
    let meta = String::from_utf8_lossy(&data[TMT_HEADER_SIZE..meta_end]).into_owned();
    let payload = &data[meta_end..payload_end];

    // Parse every entry first; refuse the whole package on any bad entry.
    let mut entries: Vec<(String, &[u8])> = Vec::new();
    let mut c = 0usize;
    while c < payload.len() {
        if c + 4 > payload.len() { io::err("tomato: corrupt payload\n"); return false; }
        let pl = le_u32(payload, c);
        c += 4;
        if c + pl + 4 > payload.len() { io::err("tomato: corrupt payload\n"); return false; }
        let path = match core::str::from_utf8(&payload[c..c + pl]).ok().and_then(safe_path) {
            Some(p) => p,
            None => { io::err("tomato: package contains an unsafe path; nothing installed\n"); return false; }
        };
        c += pl;
        let dl = le_u32(payload, c);
        c += 4;
        if c + dl > payload.len() { io::err("tomato: corrupt payload\n"); return false; }
        entries.push((path, &payload[c..c + dl]));
        c += dl;
    }

    // Conflicts: existing files not owned by an installed version of this package.
    let old = read_record(&hdr.name);
    for (p, _) in &entries {
        let owned = old.as_ref()
            .map(|r| r.lines().any(|l| l.strip_prefix("file=") == Some(p.as_str())))
            .unwrap_or(false);
        if crate::fs::exists(p) && !owned {
            io::err("tomato: ");
            io::err(p);
            io::err(" already exists and is not owned by this package; nothing installed\n");
            return false;
        }
    }

    let mut rec = alloc::format!("name={}\nversion={}\ninstalled_from={}\n", hdr.name, hdr.pkg_version, vfs_path);
    if let Some(d) = record_field(&meta, "description") {
        rec.push_str("description=");
        rec.push_str(d);
        rec.push('\n');
    }
    if let Some(d) = record_field(&meta, "depends") {
        if !d.is_empty() {
            rec.push_str("depends=");
            rec.push_str(d);
            rec.push('\n');
            for dep in d.split(',') {
                if read_record(dep).is_none() {
                    io::err(&alloc::format!("tomato: warning: dependency '{}' is not installed\n", dep));
                }
            }
        }
    }
    let mut n = 0;
    for (p, d) in &entries {
        if let Some(slash) = p.rfind('/') {
            if slash > 0 && !crate::fs::exists(&p[..slash]) {
                crate::fs::mkdir(&p[..slash]);
            }
        }
        if !crate::fs::write_file(p, d) {
            io::err("tomato: failed to write ");
            io::err(p);
            io::err("\n");
            continue;
        }
        rec.push_str("file=");
        rec.push_str(p);
        rec.push('\n');
        n += 1;
    }
    crate::fs::write_file(&record_path(&hdr.name), rec.as_bytes());
    io::out(&alloc::format!("installed {} {} ({} file(s))\n", hdr.name, hdr.pkg_version, n));
    true
}

// ─── .tmt command integration ─────────────────────────────────────────────

/// `tomato --tmt <install|list|verify|pack> ...`
pub fn tmt_dispatch(args: &str) {
    let toks: Vec<&str> = args.split_whitespace().collect();
    let arg = |i: usize| toks.get(i).copied().unwrap_or("");
    let sub = arg(0);
    let resolve = |p: &str| crate::userspace::plum::resolve_path(p);
    match sub {
        "install" if !arg(1).is_empty() => { tmt_install(&resolve(arg(1))); }
        "list" | "verify" if !arg(1).is_empty() => {
            let data = match crate::fs::read_file(&resolve(arg(1))) {
                Some(d) => d,
                None => { io::err("tomato: file not found\n"); return; }
            };
            let hdr = match tmt_parse_header(&data) {
                Some(h) => h,
                None => { io::err("tomato: not a .tmt package\n"); return; }
            };
            let ok = tmt_verify(&data);
            if sub == "verify" {
                if ok { io::out("checksum OK\n"); } else { io::err("checksum FAILED\n"); }
                return;
            }
            if !ok { io::err("warning: checksum invalid\n"); }
            io::out(&alloc::format!("{} {}\n", hdr.name, hdr.pkg_version));
            for p in tmt_list_contents(&data) {
                io::out("  ");
                io::out(&p);
                io::out("\n");
            }
        }
        "pack" if toks.len() >= 4 => {
            let (name, ver, out) = (arg(1), arg(2), resolve(arg(3)));
            if !valid_pkg_name(name) { io::err("tomato: invalid package name\n"); return; }
            let mut contents: Vec<(String, Vec<u8>)> = Vec::new();
            let mut desc = String::new();
            let mut i = 4;
            while i < toks.len() {
                if toks[i] == "-d" {
                    desc = String::from(arg(i + 1));
                    i += 2;
                    continue;
                }
                let p = resolve(toks[i]);
                match crate::fs::read_file(&p) {
                    Some(d) => contents.push((p, d)),
                    None => {
                        io::err("tomato: cannot read ");
                        io::err(toks[i]);
                        io::err(" (only regular files can be packed)\n");
                        return;
                    }
                }
                i += 1;
            }
            if contents.is_empty() { io::err("tomato: no files given to pack\n"); return; }
            let files: Vec<(&str, &[u8])> = contents.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
            let meta = [("description", desc.as_str())];
            let blob = tmt_pack(name, ver, TMT_ARCH_ANY, &meta, &files);
            if crate::fs::write_file(&out, &blob) {
                io::out(&alloc::format!("packed {} {} ({} file(s), {} bytes) -> {}\n", name, ver, files.len(), blob.len(), out));
            } else {
                io::err("tomato: cannot write ");
                io::err(&out);
                io::err("\n");
            }
        }
        _ => {
            io::out("Usage: tomato --tmt install <file.tmt>\n");
            io::out("       tomato --tmt list|verify <file.tmt>\n");
            io::out("       tomato --tmt pack <name> <version> <out.tmt> [-d description] <file>...\n");
        }
    }
}
