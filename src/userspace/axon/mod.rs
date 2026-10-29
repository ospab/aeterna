/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

axon — coreutils for ospab.os (AETERNA)

All utilities work through the VFS layer (crate::fs::*) and the plum
stream layer (plum::io): stdout/stderr can be piped or redirected, and
commands that read text accept file operands or piped stdin.

  files:  ls cat touch mkdir rmdir rm cp mv stat du df tree find tee
  text:   wc head tail grep sort uniq cut tr rev nl xxd diff awk
  misc:   basename dirname seq yes printf xargs sleep
  system: ps top kill netstat lspci fdisk lsblk mkfs mount
          ping traceroute ip curl nslookup  (network tools: net_tools.rs/ping.rs)
          verify_mem verify_sched verify_net verify_audio (ivs)

Exit status: 0 on success, 1 on failure (grep: 1 = no match, 2 = error).
*/

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

use crate::fs;
use crate::userspace::plum;
use crate::userspace::plum::io;

pub mod desktop;
pub mod disk_tools;
pub mod guidemo;
pub mod lspci;
pub mod net_tools;
pub mod netstat;
pub mod ostp;
pub mod clip;
pub mod display;
pub mod ping;
pub mod proc_tools;
pub mod ps;
pub mod regex;

// ─── Output helpers ─────────────────────────────────────────────────────────

fn out(s: &str) { io::out(s); }
fn outc(s: &str, c: u32) { io::out_c(s, c); }
fn err(s: &str) { io::err(s); }
fn errs(parts: &[&str]) { for p in parts { io::err(p); } }

// ─── Entry points ───────────────────────────────────────────────────────────

/// Console entry point: the console hands us any command it does not
/// implement itself.  The whole line is run by the plum shell (so pipes,
/// redirections, variables and scripts work).  Always returns true: plum
/// prints "command not found" itself.
pub fn dispatch(command: &str, args: &str) -> bool {
    let mut line = String::from(command);
    if !args.is_empty() {
        line.push(' ');
        line.push_str(args);
    }
    plum::run_line(&line);
    true
}

/// Run an axon command with already-expanded arguments.
/// Returns false if `name` is not an axon command.
pub fn run(name: &str, args: &[String]) -> bool {
    let joined = || args.join(" ");
    match name {
        "ls" => cmd_ls(args),
        "cat" => cmd_cat(args),
        "touch" => cmd_touch(args),
        "mkdir" => cmd_mkdir(args),
        "rmdir" => cmd_rmdir(args),
        "rm" => cmd_rm(args),
        "cp" => cmd_cp(args),
        "mv" => cmd_mv(args),
        "stat" => cmd_stat(args),
        "du" => cmd_du(args),
        "df" => cmd_df(args),
        "tree" => cmd_tree(args),
        "find" => cmd_find(args),
        "tee" => cmd_tee(args),
        "wc" => cmd_wc(args),
        "head" => cmd_head(args),
        "tail" => cmd_tail(args),
        "grep" => cmd_grep(args, false),
        "egrep" => cmd_grep(args, true),
        "sort" => cmd_sort(args),
        "uniq" => cmd_uniq(args),
        "cut" => cmd_cut(args),
        "tr" => cmd_tr(args),
        "rev" => cmd_rev(args),
        "nl" => cmd_nl(args),
        "xxd" => cmd_xxd(args),
        "diff" => cmd_diff(args),
        "awk" => cmd_awk(args),
        "basename" => cmd_basename(args),
        "dirname" => cmd_dirname(args),
        "seq" => cmd_seq(args),
        "yes" => cmd_yes(args),
        "printf" => cmd_printf(args),
        "xargs" => cmd_xargs(args),
        "sleep" => cmd_sleep(args),
        "ps" => ps::run(&joined()),
        "top" => proc_tools::cmd_top(&joined()),
        "kill" => proc_tools::cmd_kill(&joined()),
        "netstat" => netstat::run(&joined()),
        "ostp" => ostp::run(&joined()),
        "clip" => clip::run(&joined()),
        "display" => display::run(&joined()),
        "ping" => ping::run(&joined()),
        "traceroute" => net_tools::cmd_traceroute(&joined()),
        "ip" => net_tools::cmd_ip_show(&joined()),
        "curl" => net_tools::cmd_curl(&joined()),
        "nslookup" => net_tools::cmd_nslookup(&joined()),
        "lspci" => lspci::run(&joined()),
        "guidemo" => guidemo::run(&joined()),
        "desktop" => desktop::run(&joined()),
        "fdisk" => disk_tools::run_fdisk(&joined()),
        "lsblk" => disk_tools::run_lsblk(&joined()),
        "mkfs" => disk_tools::run_mkfs(&joined()),
        "mount" => disk_tools::run_mount(&joined()),
        "verify_mem" | "verify_sched" | "verify_net" | "verify_audio" => {
            crate::userspace::ivs::dispatch(name, &joined());
        }
        _ => return false,
    }
    true
}

/// All axon command names (for Tab completion and `type`).
pub fn command_list() -> &'static [&'static str] {
    &[
        "ls", "cat", "touch", "mkdir", "rmdir", "rm", "cp", "mv", "stat", "du", "df", "tree",
        "find", "tee", "wc", "head", "tail", "grep", "egrep", "sort", "uniq", "cut", "tr", "rev",
        "nl", "xxd", "diff", "awk", "basename", "dirname", "seq", "yes", "printf", "xargs",
        "sleep", "ps", "top", "kill", "netstat", "ping", "traceroute", "ip", "curl", "nslookup",
        "lspci", "desktop", "fdisk", "lsblk", "mkfs", "mount", "ostp", "clip", "display",
        "verify_mem", "verify_sched", "verify_net", "verify_audio",
    ]
}

// ─── Shared helpers ─────────────────────────────────────────────────────────

fn is_dir(path: &str) -> bool {
    path == "/" || matches!(fs::stat(path), Some(s) if s.node_type == fs::NodeType::Directory)
}

fn exists(path: &str) -> bool {
    path == "/" || fs::exists(path)
}

fn parent_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => String::from("/"),
        Some(p) => String::from(&path[..p]),
    }
}

fn base_of(path: &str) -> &str {
    let p = path.trim_end_matches('/');
    match p.rfind('/') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" { format!("/{}", name) } else { format!("{}/{}", dir, name) }
}

/// Split args into (flags, operands).  Flags are `-x` style (grouped
/// single letters allowed); `--` ends flags.  `-` alone is an operand.
fn split_flags(args: &[String]) -> (Vec<char>, Vec<String>) {
    let mut flags = Vec::new();
    let mut ops = Vec::new();
    let mut done = false;
    for a in args {
        if !done && a == "--" { done = true; continue; }
        if !done && a.len() > 1 && a.starts_with('-') {
            flags.extend(a[1..].chars());
        } else {
            ops.push(a.clone());
        }
    }
    (flags, ops)
}

/// Read a file for a text command. Prints an error and returns None on failure.
fn load(cmd: &str, name: &str) -> Option<Vec<u8>> {
    let path = plum::resolve_path(name);
    if is_dir(&path) {
        errs(&[cmd, ": ", name, ": Is a directory\n"]);
        return None;
    }
    match fs::read_file(&path) {
        Some(d) => Some(d),
        None => {
            errs(&[cmd, ": ", name, ": No such file or directory\n"]);
            None
        }
    }
}

/// Collect input texts: one per file operand, or stdin if none (or "-").
/// Returns None if nothing could be read at all.
fn inputs(cmd: &str, files: &[String]) -> Option<Vec<(String, String)>> {
    let mut v = Vec::new();
    if files.is_empty() {
        match io::take_stdin() {
            Some(s) => v.push((String::from("-"), s)),
            None => { io::no_stdin(cmd); return None; }
        }
        return Some(v);
    }
    for f in files {
        if f == "-" {
            match io::take_stdin() {
                Some(s) => v.push((String::from("-"), s)),
                None => io::no_stdin(cmd),
            }
            continue;
        }
        if let Some(d) = load(cmd, f) {
            v.push((f.clone(), String::from_utf8_lossy(&d).into_owned()));
        }
    }
    Some(v)
}

fn all_text(cmd: &str, files: &[String]) -> Option<String> {
    let v = inputs(cmd, files)?;
    let mut s = String::new();
    for (_, t) in v { s.push_str(&t); }
    Some(s)
}

fn pad_left(s: &str, w: usize) -> String {
    let mut o = String::new();
    for _ in s.chars().count()..w { o.push(' '); }
    o.push_str(s);
    o
}

fn pad_right(s: &str, w: usize) -> String {
    let mut o = String::from(s);
    for _ in s.chars().count()..w { o.push(' '); }
    o
}

fn parse_num(cmd: &str, s: &str) -> Option<usize> {
    match s.parse::<usize>() {
        Ok(n) => Some(n),
        Err(_) => { errs(&[cmd, ": invalid number '", s, "'\n"]); io::set_status(1); None }
    }
}

fn human(n: usize) -> String {
    if n >= 1024 * 1024 * 1024 {
        format!("{}.{}G", n / (1024 * 1024 * 1024), (n % (1024 * 1024 * 1024)) * 10 / (1024 * 1024 * 1024))
    } else if n >= 1024 * 1024 {
        format!("{}.{}M", n / (1024 * 1024), (n % (1024 * 1024)) * 10 / (1024 * 1024))
    } else if n >= 1024 {
        format!("{}.{}K", n / 1024, (n % 1024) * 10 / 1024)
    } else {
        format!("{}", n)
    }
}

fn lines_of(t: &str) -> Vec<&str> {
    t.lines().collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// File commands
// ═══════════════════════════════════════════════════════════════════════════

fn cmd_ls(args: &[String]) {
    let (flags, mut ops) = split_flags(args);
    for f in &flags {
        if !matches!(f, 'a' | 'l' | '1' | 'h' | 'A' | 'F') {
            errs(&["ls: invalid option -- '", &String::from(*f), "'\n"]);
            out("Usage: ls [-a] [-l] [-h] [-1] [path...]\n");
            return;
        }
    }
    let all = flags.contains(&'a') || flags.contains(&'A');
    let dots = flags.contains(&'a');
    let long = flags.contains(&'l');
    let hum = flags.contains(&'h');
    let one = flags.contains(&'1') || io::out_is_captured();
    if ops.is_empty() { ops.push(String::from(".")); }

    // files first, then directories (like GNU ls)
    let mut file_entries: Vec<fs::DirEntry> = Vec::new();
    let mut dirs: Vec<(String, String)> = Vec::new();
    for o in &ops {
        let p = plum::resolve_path(o);
        if is_dir(&p) {
            dirs.push((o.clone(), p));
        } else if let Some(st) = fs::stat(&p) {
            let mut e = st.clone();
            e.name = o.clone();
            file_entries.push(e);
        } else {
            errs(&["ls: cannot access '", o, "': No such file or directory\n"]);
        }
    }
    let multi = ops.len() > 1;
    if !file_entries.is_empty() {
        print_entries(&file_entries, long, hum, one);
    }
    for (k, (shown, p)) in dirs.iter().enumerate() {
        if multi {
            if k > 0 || !file_entries.is_empty() { out("\n"); }
            out(shown);
            out(":\n");
        }
        let mut entries = match fs::readdir(p) {
            Some(e) => e,
            None => Vec::new(),
        };
        entries.retain(|e| all || !e.name.starts_with('.'));
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries.dedup_by(|a, b| a.name == b.name);
        if dots {
            let mut v = Vec::new();
            v.push(fs::DirEntry { name: String::from("."), node_type: fs::NodeType::Directory, size: 0 });
            v.push(fs::DirEntry { name: String::from(".."), node_type: fs::NodeType::Directory, size: 0 });
            v.extend(entries);
            entries = v;
        }
        print_entries(&entries, long, hum, one);
    }
}

fn type_char(t: fs::NodeType) -> char {
    match t {
        fs::NodeType::Directory => 'd',
        fs::NodeType::File => '-',
        fs::NodeType::CharDevice => 'c',
    }
}

fn print_entries(entries: &[fs::DirEntry], long: bool, hum: bool, one: bool) {
    if long {
        let mut w = 1;
        for e in entries {
            let s = if hum { human(e.size) } else { format!("{}", e.size) };
            w = w.max(s.len());
        }
        for e in entries {
            let s = if hum { human(e.size) } else { format!("{}", e.size) };
            let mut line = String::new();
            line.push(type_char(e.node_type));
            line.push(' ');
            line.push_str(&pad_left(&s, w));
            line.push(' ');
            out(&line);
            name_out(e);
            out("\n");
        }
        return;
    }
    if one {
        for e in entries {
            name_out(e);
            out("\n");
        }
        return;
    }
    // columns
    let cols = crate::arch::x86_64::framebuffer::screen_cols() as usize;
    let mut width = 1;
    for e in entries {
        let extra = if e.node_type == fs::NodeType::Directory { 1 } else { 0 };
        width = width.max(e.name.chars().count() + extra);
    }
    width += 2;
    let per_line = (cols / width).max(1);
    let rows = (entries.len() + per_line - 1) / per_line;
    for r in 0..rows {
        for c in 0..per_line {
            let idx = c * rows + r;
            if idx >= entries.len() { break; }
            let e = &entries[idx];
            name_out(e);
            let len = e.name.chars().count() + if e.node_type == fs::NodeType::Directory { 1 } else { 0 };
            let last = c + 1 == per_line || (c + 1) * rows + r >= entries.len();
            if !last {
                let mut pad = String::new();
                for _ in len..width { pad.push(' '); }
                out(&pad);
            }
        }
        out("\n");
    }
}

fn name_out(e: &fs::DirEntry) {
    match e.node_type {
        fs::NodeType::Directory => {
            outc(&e.name, io::FG_DIR);
            if !io::out_is_captured() && e.name != "." && e.name != ".." { outc("/", io::FG_DIR); }
        }
        fs::NodeType::CharDevice => outc(&e.name, io::FG_WARN),
        fs::NodeType::File => out(&e.name),
    }
}

fn looks_binary(d: &[u8]) -> bool {
    d.iter().take(4096).any(|&b| b == 0) || core::str::from_utf8(d).is_err()
}

fn cmd_cat(args: &[String]) {
    let (flags, files) = split_flags(args);
    let number = flags.contains(&'n');
    let mut texts: Vec<(String, Vec<u8>)> = Vec::new();
    if files.is_empty() {
        match io::take_stdin() {
            Some(s) => texts.push((String::from("-"), s.into_bytes())),
            None => {
                err("cat: no input: give a file argument or pipe data in (keyboard stdin is not supported)\n");
                return;
            }
        }
    } else {
        for f in &files {
            if f == "-" {
                if let Some(s) = io::take_stdin() { texts.push((String::from("-"), s.into_bytes())); }
                continue;
            }
            if let Some(d) = load("cat", f) { texts.push((f.clone(), d)); }
        }
    }
    let mut n = 0usize;
    for (name, data) in texts {
        if !io::out_is_captured() && looks_binary(&data) {
            errs(&["cat: ", &name, ": binary file ("]);
            err(&io::fmt_usize(data.len()));
            err(" bytes) not shown; use xxd to view it\n");
            continue;
        }
        let text = String::from_utf8_lossy(&data);
        if number {
            for l in text.split_inclusive('\n') {
                n += 1;
                out(&pad_left(&io::fmt_usize(n), 6));
                out("\t");
                out(l);
            }
        } else {
            out(&text);
        }
    }
}

fn cmd_touch(args: &[String]) {
    let (_, files) = split_flags(args);
    if files.is_empty() {
        err("touch: missing file operand\n");
        return;
    }
    for f in &files {
        let p = plum::resolve_path(f);
        if exists(&p) { continue; } // no timestamps in the VFS: nothing to update
        if !is_dir(&parent_of(&p)) {
            errs(&["touch: cannot touch '", f, "': No such file or directory\n"]);
            continue;
        }
        if !fs::touch(&p) {
            errs(&["touch: cannot touch '", f, "'\n"]);
        }
    }
}

fn cmd_mkdir(args: &[String]) {
    let (flags, dirs) = split_flags(args);
    let parents = flags.contains(&'p');
    if dirs.is_empty() {
        err("mkdir: missing operand\n");
        return;
    }
    for d in &dirs {
        let p = plum::resolve_path(d);
        if exists(&p) {
            if parents && is_dir(&p) { continue; }
            errs(&["mkdir: cannot create directory '", d, "': File exists\n"]);
            continue;
        }
        if !parents && !is_dir(&parent_of(&p)) {
            errs(&["mkdir: cannot create directory '", d, "': No such file or directory\n"]);
            continue;
        }
        if !fs::mkdir(&p) {
            errs(&["mkdir: cannot create directory '", d, "'\n"]);
        }
    }
}

fn cmd_rmdir(args: &[String]) {
    let (_, dirs) = split_flags(args);
    if dirs.is_empty() {
        err("rmdir: missing operand\n");
        return;
    }
    for d in &dirs {
        let p = plum::resolve_path(d);
        if !exists(&p) {
            errs(&["rmdir: failed to remove '", d, "': No such file or directory\n"]);
        } else if !is_dir(&p) {
            errs(&["rmdir: failed to remove '", d, "': Not a directory\n"]);
        } else if fs::readdir(&p).map(|e| !e.is_empty()).unwrap_or(false) {
            errs(&["rmdir: failed to remove '", d, "': Directory not empty\n"]);
        } else if p == "/" || !fs::remove(&p) {
            errs(&["rmdir: failed to remove '", d, "'\n"]);
        }
    }
}

fn remove_tree(path: &str) -> bool {
    if is_dir(path) {
        if let Some(entries) = fs::readdir(path) {
            for e in entries {
                if io::poll_interrupt() { return false; }
                if !remove_tree(&join(path, &e.name)) { return false; }
            }
        }
    }
    fs::remove(path)
}

fn cmd_rm(args: &[String]) {
    let (flags, ops) = split_flags(args);
    let recursive = flags.contains(&'r') || flags.contains(&'R');
    let force = flags.contains(&'f');
    if ops.is_empty() {
        if !force { err("rm: missing operand\n"); }
        return;
    }
    for o in &ops {
        let p = plum::resolve_path(o);
        if p == "/" {
            err("rm: refusing to remove '/'\n");
            continue;
        }
        if !exists(&p) {
            if !force { errs(&["rm: cannot remove '", o, "': No such file or directory\n"]); }
            continue;
        }
        if is_dir(&p) {
            if !recursive {
                errs(&["rm: cannot remove '", o, "': Is a directory (use rm -r)\n"]);
                continue;
            }
            if !remove_tree(&p) {
                errs(&["rm: cannot remove '", o, "'\n"]);
            }
        } else if !fs::remove(&p) {
            errs(&["rm: cannot remove '", o, "'\n"]);
        }
    }
}

fn copy_tree(src: &str, dst: &str) -> bool {
    if is_dir(src) {
        if !exists(dst) && !fs::mkdir(dst) { return false; }
        if let Some(entries) = fs::readdir(src) {
            for e in entries {
                if !copy_tree(&join(src, &e.name), &join(dst, &e.name)) { return false; }
            }
        }
        true
    } else {
        match fs::read_file(src) {
            Some(d) => fs::write_file(dst, &d),
            None => false,
        }
    }
}

/// Resolve the destination for cp/mv. Returns list of (src_abs, src_shown, dst_abs).
fn plan_copy(cmd: &str, ops: &[String]) -> Option<Vec<(String, String, String)>> {
    if ops.len() < 2 {
        errs(&[cmd, ": missing destination file operand\n"]);
        return None;
    }
    let dst_raw = &ops[ops.len() - 1];
    let dst = plum::resolve_path(dst_raw);
    let srcs = &ops[..ops.len() - 1];
    let dst_is_dir = is_dir(&dst);
    if srcs.len() > 1 && !dst_is_dir {
        errs(&[cmd, ": target '", dst_raw, "' is not a directory\n"]);
        return None;
    }
    let mut plan = Vec::new();
    for s in srcs {
        let sp = plum::resolve_path(s);
        if !exists(&sp) {
            errs(&[cmd, ": cannot stat '", s, "': No such file or directory\n"]);
            continue;
        }
        let target = if dst_is_dir { join(&dst, base_of(&sp)) } else { dst.clone() };
        if target == sp {
            errs(&[cmd, ": '", s, "' and '", dst_raw, "' are the same file\n"]);
            continue;
        }
        if is_dir(&sp) && (target.starts_with(&format!("{}/", sp))) {
            errs(&[cmd, ": cannot ", if cmd == "cp" { "copy" } else { "move" }, " '", s, "' into itself\n"]);
            continue;
        }
        plan.push((sp, s.clone(), target));
    }
    Some(plan)
}

fn cmd_cp(args: &[String]) {
    let (flags, ops) = split_flags(args);
    let recursive = flags.contains(&'r') || flags.contains(&'R') || flags.contains(&'a');
    let plan = match plan_copy("cp", &ops) { Some(p) => p, None => return };
    for (src, shown, dst) in plan {
        if is_dir(&src) && !recursive {
            errs(&["cp: -r not specified; omitting directory '", &shown, "'\n"]);
            continue;
        }
        if is_dir(&dst) && !is_dir(&src) {
            errs(&["cp: cannot overwrite directory '", &dst, "' with a file\n"]);
            continue;
        }
        if !copy_tree(&src, &dst) {
            errs(&["cp: cannot copy '", &shown, "' to '", &dst, "'\n"]);
        }
    }
}

fn cmd_mv(args: &[String]) {
    let (_, ops) = split_flags(args);
    let plan = match plan_copy("mv", &ops) { Some(p) => p, None => return };
    for (src, shown, dst) in plan {
        if is_dir(&dst) {
            errs(&["mv: cannot overwrite directory '", &dst, "'\n"]);
            continue;
        }
        if exists(&dst) { fs::remove(&dst); }
        if fs::rename(&src, &dst) && exists(&dst) && !exists(&src) {
            continue;
        }
        // fall back to copy + delete
        if copy_tree(&src, &dst) && remove_tree(&src) {
            continue;
        }
        errs(&["mv: cannot move '", &shown, "' to '", &dst, "'\n"]);
    }
}

fn cmd_stat(args: &[String]) {
    let (_, ops) = split_flags(args);
    if ops.is_empty() {
        err("stat: missing operand\n");
        return;
    }
    for o in &ops {
        let p = plum::resolve_path(o);
        let st = if p == "/" {
            Some(fs::DirEntry { name: String::from("/"), node_type: fs::NodeType::Directory, size: 0 })
        } else {
            fs::stat(&p)
        };
        match st {
            Some(e) => {
                out("  File: "); outc(o, io::FG_HL); out("\n");
                out("  Path: "); out(&p); out("\n");
                out("  Size: "); out(&io::fmt_usize(e.size)); out(" bytes\n");
                out("  Type: ");
                out(match e.node_type {
                    fs::NodeType::File => "regular file",
                    fs::NodeType::Directory => "directory",
                    fs::NodeType::CharDevice => "character device",
                });
                out("\n");
                if e.node_type == fs::NodeType::Directory {
                    let n = fs::readdir(&p).map(|v| v.len()).unwrap_or(0);
                    out("Entries: "); out(&io::fmt_usize(n)); out("\n");
                }
            }
            None => errs(&["stat: cannot stat '", o, "': No such file or directory\n"]),
        }
    }
}

fn tree_size(path: &str, report: &mut dyn FnMut(&str, usize, bool), depth: usize) -> usize {
    if depth > 64 { return 0; }
    match fs::readdir(path) {
        Some(entries) => {
            let mut total = 0;
            for e in entries {
                let full = join(path, &e.name);
                if e.node_type == fs::NodeType::Directory {
                    if full == "/proc" { continue; }
                    let s = tree_size(&full, report, depth + 1);
                    report(&full, s, true);
                    total += s;
                } else {
                    report(&full, e.size, false);
                    total += e.size;
                }
            }
            total
        }
        None => 0,
    }
}

fn cmd_du(args: &[String]) {
    let (flags, mut ops) = split_flags(args);
    let summary = flags.contains(&'s');
    let hum = flags.contains(&'h');
    let all = flags.contains(&'a');
    let bytes = flags.contains(&'b');
    if ops.is_empty() { ops.push(String::from(".")); }
    let fmt = |n: usize| -> String {
        if hum { human(n) } else if bytes { format!("{}", n) } else { format!("{}", (n + 1023) / 1024) }
    };
    for o in &ops {
        let p = plum::resolve_path(o);
        if !exists(&p) {
            errs(&["du: cannot access '", o, "': No such file or directory\n"]);
            continue;
        }
        if !is_dir(&p) {
            let s = fs::stat(&p).map(|e| e.size).unwrap_or(0);
            out(&format!("{}\t{}\n", fmt(s), o));
            continue;
        }
        let base = p.clone();
        let shown = o.clone();
        let mut lines: Vec<String> = Vec::new();
        let total = tree_size(&p, &mut |path: &str, size: usize, dir: bool| {
            if summary { return; }
            if dir || all {
                let rel = if base == "/" { String::from(path) } else { format!("{}{}", shown, &path[base.len()..]) };
                lines.push(format!("{}\t{}\n", fmt(size), rel));
            }
        }, 0);
        for l in lines { out(&l); }
        out(&format!("{}\t{}\n", fmt(total), o));
    }
    // Units: KiB of apparent size, rounded up (like `du --apparent-size`);
    // -b bytes, -h human readable.
}

fn cmd_df(args: &[String]) {
    let (flags, _) = split_flags(args);
    let hum = flags.contains(&'h');
    let fmt = |n: usize| -> String { if hum { human(n) } else { format!("{}", (n + 1023) / 1024) } };
    let used = tree_size("/", &mut |_: &str, _: usize, _: bool| {}, 0);
    let (heap_used, heap_free) = if crate::mm::heap::is_initialized() { crate::mm::heap::stats() } else { (0, 0) };
    let heap_total = heap_used + heap_free;
    let unit = if hum { "Size" } else { "1K-blocks" };
    outc(&format!("{} {} {} {} {}  {}\n", pad_right("Filesystem", 14), pad_left(unit, 10), pad_left("Used", 9),
        pad_left("Avail", 9), pad_left("Use%", 4), "Mounted on"), io::FG_HL);
    let pct = if heap_total > 0 { used * 100 / heap_total } else { 0 };
    out(&format!("{} {} {} {} {}  {}\n", pad_right("ramfs+cow", 14), pad_left(&fmt(heap_total), 10), pad_left(&fmt(used), 9),
        pad_left(&fmt(heap_free), 9), pad_left(&format!("{}%", pct), 4), "/"));
    for i in 0..crate::drivers::disk_count() {
        if let Some(info) = crate::drivers::disk_info(i) {
            let size = info.size_mb as usize * 1024 * 1024;
            let snap = crate::fs::disk_sync::last_snapshot_bytes();
            let pct = if size > 0 { snap * 100 / size } else { 0 };
            out(&format!("{} {} {} {} {}  {}\n", pad_right(&format!("disk{}", i), 14), pad_left(&fmt(size), 10),
                pad_left(&fmt(snap), 9), pad_left(&fmt(size.saturating_sub(snap)), 9), pad_left(&format!("{}%", pct), 4),
                "(not mounted; 'save' snapshot store)"));
        }
    }
    if !io::out_is_captured() {
        outc("note: / lives in the kernel heap. Size/Avail are the heap's (shared with the kernel);\n", io::FG_DIM);
        outc("      Used is the total size of all files. disk Used = size of the last saved snapshot.\n", io::FG_DIM);
    }
}

fn cmd_tree(args: &[String]) {
    let mut max_depth = 32usize;
    let mut ops = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-L" && i + 1 < args.len() {
            match parse_num("tree", &args[i + 1]) { Some(n) => max_depth = n, None => return }
            i += 2;
            continue;
        }
        ops.push(args[i].clone());
        i += 1;
    }
    if ops.is_empty() { ops.push(String::from(".")); }
    for o in &ops {
        let p = plum::resolve_path(o);
        if !is_dir(&p) {
            errs(&["tree: ", o, ": not a directory\n"]);
            continue;
        }
        outc(o, io::FG_DIR);
        out("\n");
        let (d, f) = tree_rec(&p, "", 0, max_depth);
        out(&format!("\n{} directories, {} files\n", d, f));
    }
}

fn tree_rec(path: &str, prefix: &str, depth: usize, max: usize) -> (usize, usize) {
    if depth >= max { return (0, 0); }
    let mut dirs = 0;
    let mut files = 0;
    if let Some(mut entries) = fs::readdir(path) {
        entries.retain(|e| !e.name.starts_with('.'));
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let n = entries.len();
        for (i, e) in entries.iter().enumerate() {
            let last = i + 1 == n;
            out(prefix);
            outc(if last { "`-- " } else { "|-- " }, io::FG_DIM);
            if e.node_type == fs::NodeType::Directory {
                outc(&e.name, io::FG_DIR);
                out("\n");
                dirs += 1;
                let child = format!("{}{}", prefix, if last { "    " } else { "|   " });
                let (d, f) = tree_rec(&join(path, &e.name), &child, depth + 1, max);
                dirs += d;
                files += f;
            } else {
                out(&e.name);
                out("\n");
                files += 1;
            }
        }
    }
    (dirs, files)
}

fn cmd_find(args: &[String]) {
    let mut roots = Vec::new();
    let mut name: Option<(String, bool)> = None;
    let mut ftype: Option<char> = None;
    let mut maxdepth = usize::MAX;
    let mut mindepth = 0usize;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = args.get(i + 1);
        match a {
            "-name" | "-iname" => {
                match next { Some(n) => name = Some((n.clone(), a == "-iname")), None => { err("find: missing argument to -name\n"); return; } }
                i += 2;
            }
            "-type" => {
                match next.and_then(|n| n.chars().next()) {
                    Some(c) if c == 'f' || c == 'd' => ftype = Some(c),
                    _ => { err("find: -type: use f or d\n"); return; }
                }
                i += 2;
            }
            "-maxdepth" | "-mindepth" => {
                let n = match next.and_then(|n| n.parse::<usize>().ok()) { Some(n) => n, None => { errs(&["find: ", a, " needs a number\n"]); return; } };
                if a == "-maxdepth" { maxdepth = n } else { mindepth = n }
                i += 2;
            }
            "-print" => i += 1,
            _ if a.starts_with('-') => {
                errs(&["find: unsupported expression '", a, "' (supported: -name -iname -type f|d -maxdepth -mindepth)\n"]);
                return;
            }
            _ => { roots.push(args[i].clone()); i += 1; }
        }
    }
    if roots.is_empty() { roots.push(String::from(".")); }
    for r in &roots {
        let p = plum::resolve_path(r);
        if !exists(&p) {
            errs(&["find: '", r, "': No such file or directory\n"]);
            continue;
        }
        let shown = r.trim_end_matches('/');
        let shown = if shown.is_empty() { "/" } else { shown };
        find_visit(&p, shown, is_dir(&p), 0, &name, ftype, maxdepth, mindepth);
    }
}

fn find_visit(path: &str, shown: &str, dir: bool, depth: usize, name: &Option<(String, bool)>,
              ftype: Option<char>, maxd: usize, mind: usize) {
    if io::interrupted() || (depth % 4 == 0 && io::poll_interrupt()) { return; }
    let base = if depth == 0 { base_of(shown) } else { base_of(path) };
    let name_ok = match name {
        None => true,
        Some((pat, ci)) => {
            if *ci { plum::glob_match(&pat.to_ascii_lowercase(), &base.to_ascii_lowercase()) } else { plum::glob_match(pat, base) }
        }
    };
    let type_ok = match ftype { None => true, Some('d') => dir, Some(_) => !dir };
    if depth >= mind && name_ok && type_ok {
        if dir { outc(shown, io::FG_DIR); } else { out(shown); }
        out("\n");
    }
    if dir && depth < maxd && depth < 64 {
        if let Some(mut entries) = fs::readdir(path) {
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            for e in entries {
                let child = join(path, &e.name);
                let child_shown = if shown == "/" { format!("/{}", e.name) } else { format!("{}/{}", shown, e.name) };
                find_visit(&child, &child_shown, e.node_type == fs::NodeType::Directory, depth + 1, name, ftype, maxd, mind);
            }
        }
    }
}

fn cmd_tee(args: &[String]) {
    let (flags, files) = split_flags(args);
    let append = flags.contains(&'a');
    let data = match io::take_stdin() {
        Some(s) => s,
        None => { io::no_stdin("tee"); return; }
    };
    for f in &files {
        let p = plum::resolve_path(f);
        let ok = if append { fs::append_file(&p, data.as_bytes()) } else { fs::write_file(&p, data.as_bytes()) };
        if !ok { errs(&["tee: ", f, ": cannot write\n"]); }
    }
    out(&data);
}

// ═══════════════════════════════════════════════════════════════════════════
// Text commands
// ═══════════════════════════════════════════════════════════════════════════

fn cmd_wc(args: &[String]) {
    let (mut flags, files) = split_flags(args);
    if flags.is_empty() { flags = alloc::vec!['l', 'w', 'c']; }
    let ins = match inputs("wc", &files) { Some(v) => v, None => return };
    let mut tot = (0usize, 0usize, 0usize, 0usize);
    let n = ins.len();
    let ncols = ['l', 'w', 'm', 'c'].iter().filter(|c| flags.contains(c)).count();
    // a single count for a single input is printed without padding (like GNU wc)
    let width = if ncols == 1 && n == 1 { 0 } else { 7 };
    let show = |l: usize, w: usize, c: usize, m: usize, name: &str| {
        let mut s = String::new();
        if flags.contains(&'l') { s.push_str(&pad_left(&io::fmt_usize(l), width)); s.push(' '); }
        if flags.contains(&'w') { s.push_str(&pad_left(&io::fmt_usize(w), width)); s.push(' '); }
        if flags.contains(&'m') { s.push_str(&pad_left(&io::fmt_usize(m), width)); s.push(' '); }
        if flags.contains(&'c') { s.push_str(&pad_left(&io::fmt_usize(c), width)); s.push(' '); }
        if name != "-" { s.push_str(name); }
        let s = String::from(s.trim_end());
        out(&s);
        out("\n");
    };
    for (name, t) in &ins {
        let l = t.matches('\n').count();
        let w = t.split_whitespace().count();
        let c = t.len();
        let m = t.chars().count();
        tot.0 += l; tot.1 += w; tot.2 += c; tot.3 += m;
        show(l, w, c, m, name);
    }
    if n > 1 { show(tot.0, tot.1, tot.2, tot.3, "total"); }
}

/// Parse -n N / -N / -nN. Returns (count, from_start(+N), remaining operands).
fn parse_count(cmd: &str, args: &[String]) -> Option<(usize, bool, Vec<String>)> {
    let mut n = 10usize;
    let mut plus = false;
    let mut files = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let val: Option<&str> = if a == "-n" {
            i += 1;
            match args.get(i) { Some(v) => Some(v.as_str()), None => { errs(&[cmd, ": option requires an argument -- 'n'\n"]); return None; } }
        } else if a.starts_with("-n") {
            Some(&a[2..])
        } else if a.len() > 1 && a.starts_with('-') && a[1..].bytes().all(|b| b.is_ascii_digit()) {
            Some(&a[1..])
        } else {
            files.push(args[i].clone());
            None
        };
        if let Some(v) = val {
            let v = if let Some(r) = v.strip_prefix('+') { plus = true; r } else { v };
            n = parse_num(cmd, v)?;
        }
        i += 1;
    }
    Some((n, plus, files))
}

fn cmd_head(args: &[String]) {
    let (n, _, files) = match parse_count("head", args) { Some(x) => x, None => return };
    let ins = match inputs("head", &files) { Some(v) => v, None => return };
    let multi = ins.len() > 1;
    for (k, (name, t)) in ins.iter().enumerate() {
        if multi { if k > 0 { out("\n"); } out(&format!("==> {} <==\n", name)); }
        for l in t.split_inclusive('\n').take(n) {
            out(l);
        }
    }
}

fn cmd_tail(args: &[String]) {
    let (n, plus, files) = match parse_count("tail", args) { Some(x) => x, None => return };
    let ins = match inputs("tail", &files) { Some(v) => v, None => return };
    let multi = ins.len() > 1;
    for (k, (name, t)) in ins.iter().enumerate() {
        if multi { if k > 0 { out("\n"); } out(&format!("==> {} <==\n", name)); }
        let lines: Vec<&str> = t.split_inclusive('\n').collect();
        let start = if plus { n.saturating_sub(1).min(lines.len()) } else { lines.len().saturating_sub(n) };
        for l in &lines[start..] {
            out(l);
        }
    }
}

fn regex_escape(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        if "\\.[]*^$+?(){}|".contains(c) { o.push('\\'); }
        o.push(c);
    }
    o
}

fn cmd_grep(args: &[String], egrep: bool) {
    let mut flags: Vec<char> = Vec::new();
    let mut pattern: Option<String> = None;
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    let mut done = false;
    while i < args.len() {
        let a = &args[i];
        if !done && a == "--" { done = true; i += 1; continue; }
        if !done && a == "-e" {
            match args.get(i + 1) { Some(p) => pattern = Some(p.clone()), None => { err("grep: option requires an argument -- 'e'\n"); io::set_status(2); return; } }
            i += 2;
            continue;
        }
        if !done && a.len() > 1 && a.starts_with('-') {
            flags.extend(a[1..].chars());
        } else if pattern.is_none() {
            pattern = Some(a.clone());
        } else {
            files.push(a.clone());
        }
        i += 1;
    }
    for f in &flags {
        if !"ivnclLqsoEFrRwxhH".contains(*f) {
            errs(&["grep: invalid option -- '", &String::from(*f), "'\n"]);
            out("Usage: grep [-ivnclLqoEFrwxhH] [-e] PATTERN [FILE...]\n");
            io::set_status(2);
            return;
        }
    }
    let pattern = match pattern {
        Some(p) => p,
        None => {
            err("grep: missing pattern\nUsage: grep [-ivnclLqoEFrwxhH] [-e] PATTERN [FILE...]\n");
            io::set_status(2);
            return;
        }
    };
    let f = |c: char| flags.contains(&c);
    let (ignore, invert, number, count, list, list_not, quiet, only) =
        (f('i'), f('v'), f('n'), f('c'), f('l'), f('L'), f('q'), f('o'));
    let recursive = f('r') || f('R');
    let extended = egrep || f('E');
    let mut pat = if f('F') { regex_escape(&pattern) } else { pattern.clone() };
    let basic = !extended && !f('F');
    if f('w') {
        pat = if basic { format!("\\b\\({}\\)\\b", pat) } else { format!("\\b({})\\b", pat) };
    }
    if f('x') {
        pat = if basic { format!("^\\({}\\)$", pat) } else { format!("^({})$", pat) };
    }
    let re = match regex::Regex::build(&pat, basic, ignore) {
        Ok(r) => r,
        Err(e) => {
            errs(&["grep: invalid pattern '", &pattern, "': ", &e, "\n"]);
            io::set_status(2);
            return;
        }
    };

    // collect inputs
    let mut ins: Vec<(String, String)> = Vec::new();
    let mut errors = false;
    if recursive {
        if files.is_empty() { files.push(String::from(".")); }
        for fl in &files {
            let p = plum::resolve_path(fl);
            if is_dir(&p) {
                let mut stack = alloc::vec![(p.clone(), String::from(fl.trim_end_matches('/')))];
                while let Some((dir, shown)) = stack.pop() {
                    if let Some(mut entries) = fs::readdir(&dir) {
                        entries.sort_by(|a, b| b.name.cmp(&a.name));
                        for e in entries {
                            let full = join(&dir, &e.name);
                            if full == "/proc" { continue; }
                            let sh = format!("{}/{}", shown, e.name);
                            if e.node_type == fs::NodeType::Directory {
                                stack.push((full, sh));
                            } else if let Some(d) = fs::read_file(&full) {
                                if !d.contains(&0) {
                                    ins.push((sh, String::from_utf8_lossy(&d).into_owned()));
                                }
                            }
                        }
                    }
                }
            } else {
                match load("grep", fl) {
                    Some(d) => ins.push((fl.clone(), String::from_utf8_lossy(&d).into_owned())),
                    None => errors = true,
                }
            }
        }
        ins.sort_by(|a, b| a.0.cmp(&b.0));
    } else {
        match inputs("grep", &files) {
            Some(v) => {
                if v.len() < files.len() { errors = true; }
                ins = v;
            }
            None => { io::set_status(2); return; }
        }
    }
    let show_names = if f('h') { false } else { f('H') || recursive || ins.len() > 1 };
    let mut any = false;
    for (name, text) in &ins {
        let mut cnt = 0usize;
        for (ln, line) in text.lines().enumerate() {
            let m = re.find(line);
            let hit = m.is_some() != invert;
            if !hit { continue; }
            cnt += 1;
            any = true;
            if quiet { io::set_status(0); return; }
            if count || list || list_not { continue; }
            let mut prefix = String::new();
            if show_names { prefix.push_str(name); prefix.push(':'); }
            if number { prefix.push_str(&io::fmt_usize(ln + 1)); prefix.push(':'); }
            if only && !invert {
                let mut off = 0;
                while off <= line.len() {
                    let rest = &line[off..];
                    match re.find(rest) {
                        Some((s, e)) => {
                            if e > s {
                                outc(&prefix, io::FG_DIM);
                                outc(&rest[s..e], io::FG_HL);
                                out("\n");
                                off += e;
                            } else {
                                off += rest[s..].chars().next().map(|c| c.len_utf8()).unwrap_or(1) + s;
                            }
                        }
                        None => break,
                    }
                    if off >= line.len() { break; }
                }
                continue;
            }
            outc(&prefix, io::FG_DIM);
            match (m, invert) {
                (Some((s, e)), false) if e > s => {
                    out(&line[..s]);
                    outc(&line[s..e], io::FG_HL);
                    out(&line[e..]);
                }
                _ => out(line),
            }
            out("\n");
        }
        if count {
            if show_names { out(name); out(":"); }
            out(&io::fmt_usize(cnt));
            out("\n");
        }
        if list && cnt > 0 { out(name); out("\n"); }
        if list_not && cnt == 0 { out(name); out("\n"); }
    }
    io::set_status(if errors && !f('s') { 2 } else if any { 0 } else { 1 });
}

fn leading_number(s: &str) -> f64 {
    let s = s.trim_start();
    let mut end = 0;
    let b = s.as_bytes();
    if end < b.len() && (b[end] == b'-' || b[end] == b'+') { end += 1; }
    while end < b.len() && (b[end].is_ascii_digit() || b[end] == b'.') { end += 1; }
    s[..end].parse::<f64>().unwrap_or(0.0)
}

fn sort_key<'a>(line: &'a str, key: Option<usize>, sep: Option<char>) -> &'a str {
    match key {
        None => line,
        Some(k) => {
            let fields: Vec<&str> = match sep {
                Some(c) => line.split(c).collect(),
                None => line.split_whitespace().collect(),
            };
            fields.get(k.saturating_sub(1)).copied().unwrap_or("")
        }
    }
}

fn cmd_sort(args: &[String]) {
    let mut flags = Vec::new();
    let mut files = Vec::new();
    let mut key: Option<usize> = None;
    let mut sep: Option<char> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-k" || a == "-t" {
            let v = match args.get(i + 1) { Some(v) => v.clone(), None => { errs(&["sort: option ", a, " needs an argument\n"]); return; } };
            if a == "-k" {
                key = match parse_num("sort", v.split(|c| c == ',' || c == '.').next().unwrap_or("")) { Some(k) => Some(k), None => return };
            } else {
                sep = v.chars().next();
            }
            i += 2;
            continue;
        }
        if a.len() > 1 && a.starts_with('-') { flags.extend(a[1..].chars()); } else { files.push(args[i].clone()); }
        i += 1;
    }
    let text = match all_text("sort", &files) { Some(t) => t, None => return };
    let mut lines = lines_of(&text);
    let numeric = flags.contains(&'n');
    let fold = flags.contains(&'f');
    if numeric {
        lines.sort_by(|a, b| {
            let (x, y) = (leading_number(sort_key(a, key, sep)), leading_number(sort_key(b, key, sep)));
            x.partial_cmp(&y).unwrap_or(core::cmp::Ordering::Equal).then_with(|| a.cmp(b))
        });
    } else if fold {
        lines.sort_by(|a, b| sort_key(a, key, sep).to_ascii_lowercase().cmp(&sort_key(b, key, sep).to_ascii_lowercase()));
    } else {
        lines.sort_by(|a, b| sort_key(a, key, sep).cmp(sort_key(b, key, sep)).then_with(|| a.cmp(b)));
    }
    if flags.contains(&'r') { lines.reverse(); }
    if flags.contains(&'u') {
        lines.dedup_by(|a, b| sort_key(a, key, sep) == sort_key(b, key, sep));
    }
    let mut s = String::new();
    for l in lines { s.push_str(l); s.push('\n'); }
    out(&s);
}

fn cmd_uniq(args: &[String]) {
    let (flags, files) = split_flags(args);
    let text = match all_text("uniq", &files[..files.len().min(1)]) { Some(t) => t, None => return };
    let (cnt, dups, uniq_only, ci) = (flags.contains(&'c'), flags.contains(&'d'), flags.contains(&'u'), flags.contains(&'i'));
    let mut groups: Vec<(&str, usize)> = Vec::new();
    for l in text.lines() {
        if let Some(last) = groups.last_mut() {
            let same = if ci { last.0.eq_ignore_ascii_case(l) } else { last.0 == l };
            if same { last.1 += 1; continue; }
        }
        groups.push((l, 1));
    }
    let mut s = String::new();
    for (l, n) in groups {
        if dups && n < 2 { continue; }
        if uniq_only && n > 1 { continue; }
        if cnt { s.push_str(&pad_left(&io::fmt_usize(n), 7)); s.push(' '); }
        s.push_str(l);
        s.push('\n');
    }
    out(&s);
}

/// Parse a cut list like "1,3-5,7-". Returns ranges (1-based, inclusive).
fn parse_list(s: &str) -> Option<Vec<(usize, usize)>> {
    let mut v = Vec::new();
    for part in s.split(',') {
        if part.is_empty() { return None; }
        if let Some(d) = part.find('-') {
            let lo = if d == 0 { 1 } else { part[..d].parse().ok()? };
            let hi = if d + 1 == part.len() { usize::MAX } else { part[d + 1..].parse().ok()? };
            if lo == 0 || hi < lo { return None; }
            v.push((lo, hi));
        } else {
            let n: usize = part.parse().ok()?;
            if n == 0 { return None; }
            v.push((n, n));
        }
    }
    Some(v)
}

fn cmd_cut(args: &[String]) {
    let mut delim = '\t';
    let mut fields: Option<Vec<(usize, usize)>> = None;
    let mut chars: Option<Vec<(usize, usize)>> = None;
    let mut only_delim = false;
    let mut files = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let take = |i: &mut usize, flag: &str| -> Option<String> {
            if a.len() > 2 { Some(String::from(&a[2..])) } else {
                *i += 1;
                match args.get(*i) { Some(v) => Some(v.clone()), None => { errs(&["cut: option ", flag, " requires an argument\n"]); None } }
            }
        };
        if a.starts_with("-d") {
            let v = match take(&mut i, "-d") { Some(v) => v, None => return };
            delim = v.chars().next().unwrap_or('\t');
        } else if a.starts_with("-f") {
            let v = match take(&mut i, "-f") { Some(v) => v, None => return };
            fields = parse_list(&v);
            if fields.is_none() { errs(&["cut: invalid field list '", &v, "'\n"]); return; }
        } else if a.starts_with("-c") || a.starts_with("-b") {
            let v = match take(&mut i, "-c") { Some(v) => v, None => return };
            chars = parse_list(&v);
            if chars.is_none() { errs(&["cut: invalid list '", &v, "'\n"]); return; }
        } else if a == "-s" {
            only_delim = true;
        } else {
            files.push(args[i].clone());
        }
        i += 1;
    }
    if fields.is_none() && chars.is_none() {
        err("cut: you must specify a list of fields (-f) or characters (-c)\n");
        out("Usage: cut -f LIST [-d DELIM] [-s] [file]  |  cut -c LIST [file]\n");
        return;
    }
    let text = match all_text("cut", &files) { Some(t) => t, None => return };
    let inr = |r: &[(usize, usize)], n: usize| r.iter().any(|(lo, hi)| n >= *lo && n <= *hi);
    let mut s = String::new();
    for line in text.lines() {
        if let Some(r) = &chars {
            for (k, c) in line.chars().enumerate() {
                if inr(r, k + 1) { s.push(c); }
            }
            s.push('\n');
        } else if let Some(r) = &fields {
            if !line.contains(delim) {
                if !only_delim { s.push_str(line); s.push('\n'); }
                continue;
            }
            let mut first = true;
            for (k, fl) in line.split(delim).enumerate() {
                if inr(r, k + 1) {
                    if !first { s.push(delim); }
                    s.push_str(fl);
                    first = false;
                }
            }
            s.push('\n');
        }
    }
    out(&s);
}

fn expand_tr_set(s: &str) -> Vec<char> {
    let mut raw: Vec<char> = Vec::new();
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '[' && i + 1 < c.len() && c[i + 1] == ':' {
            let rest: String = c[i..].iter().collect();
            if let Some(end) = rest.find(":]") {
                let name = &rest[2..end];
                let set: Vec<char> = match name {
                    "upper" => ('A'..='Z').collect(),
                    "lower" => ('a'..='z').collect(),
                    "digit" => ('0'..='9').collect(),
                    "alpha" => ('A'..='Z').chain('a'..='z').collect(),
                    "alnum" => ('0'..='9').chain('A'..='Z').chain('a'..='z').collect(),
                    "space" => alloc::vec![' ', '\t', '\n', '\r', '\x0b', '\x0c'],
                    "blank" => alloc::vec![' ', '\t'],
                    "punct" => (0x21u8..0x7f).map(|b| b as char).filter(|c| c.is_ascii_punctuation()).collect(),
                    _ => Vec::new(),
                };
                raw.extend(set);
                i += end + 2;
                continue;
            }
        }
        let ch = if c[i] == '\\' && i + 1 < c.len() {
            i += 1;
            match c[i] { 'n' => '\n', 't' => '\t', 'r' => '\r', '\\' => '\\', o => o }
        } else { c[i] };
        if i + 2 < c.len() && c[i + 1] == '-' {
            let hi = c[i + 2];
            let (lo, hi) = (ch as u32, hi as u32);
            if lo <= hi {
                for x in lo..=hi { if let Some(ch) = char::from_u32(x) { raw.push(ch); } }
            }
            i += 3;
        } else {
            raw.push(ch);
            i += 1;
        }
    }
    raw
}

fn cmd_tr(args: &[String]) {
    let (flags, ops) = split_flags(args);
    let delete = flags.contains(&'d');
    let squeeze = flags.contains(&'s');
    let usage = || err("tr: usage: tr [-d] [-s] SET1 [SET2]  (reads stdin)\n");
    if ops.is_empty() || (!delete && !squeeze && ops.len() < 2) { usage(); return; }
    let text = match io::take_stdin() { Some(t) => t, None => { io::no_stdin("tr"); return; } };
    let s1 = expand_tr_set(&ops[0]);
    let s2 = if ops.len() > 1 { expand_tr_set(&ops[1]) } else { Vec::new() };
    let mut o = String::new();
    let mut last: Option<char> = None;
    let sq_set: &Vec<char> = if !s2.is_empty() { &s2 } else { &s1 };
    for c in text.chars() {
        let mapped = if delete {
            if s1.contains(&c) { continue; }
            c
        } else if !s2.is_empty() {
            match s1.iter().position(|x| *x == c) {
                Some(p) => *s2.get(p).unwrap_or(s2.last().unwrap()),
                None => c,
            }
        } else { c };
        if squeeze && last == Some(mapped) && sq_set.contains(&mapped) { continue; }
        last = Some(mapped);
        o.push(mapped);
    }
    out(&o);
}

fn cmd_rev(args: &[String]) {
    let (_, files) = split_flags(args);
    let text = match all_text("rev", &files) { Some(t) => t, None => return };
    let mut s = String::new();
    for l in text.lines() {
        s.extend(l.chars().rev());
        s.push('\n');
    }
    out(&s);
}

fn cmd_nl(args: &[String]) {
    let mut all = false;
    let mut files = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-ba" { all = true; }
        else if args[i] == "-b" && args.get(i + 1).map(|s| s.as_str()) == Some("a") { all = true; i += 1; }
        else { files.push(args[i].clone()); }
        i += 1;
    }
    let text = match all_text("nl", &files) { Some(t) => t, None => return };
    let mut n = 0;
    let mut s = String::new();
    for l in text.lines() {
        if l.is_empty() && !all {
            s.push('\n');
            continue;
        }
        n += 1;
        s.push_str(&pad_left(&io::fmt_usize(n), 6));
        s.push('\t');
        s.push_str(l);
        s.push('\n');
    }
    out(&s);
}

fn cmd_xxd(args: &[String]) {
    let mut limit = usize::MAX;
    let mut files = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-l" {
            match args.get(i + 1).and_then(|v| v.parse::<usize>().ok()) { Some(n) => limit = n, None => { err("xxd: -l needs a number\n"); return; } }
            i += 2;
            continue;
        }
        files.push(args[i].clone());
        i += 1;
    }
    let data: Vec<u8> = if files.is_empty() {
        match io::take_stdin() { Some(s) => s.into_bytes(), None => { io::no_stdin("xxd"); return; } }
    } else {
        match load("xxd", &files[0]) { Some(d) => d, None => return }
    };
    let data = &data[..data.len().min(limit)];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (row, chunk) in data.chunks(16).enumerate() {
        if row % 64 == 63 && io::poll_interrupt() { return; }
        let mut s = format!("{:08x}: ", row * 16);
        for k in 0..16 {
            if k < chunk.len() {
                s.push(HEX[(chunk[k] >> 4) as usize] as char);
                s.push(HEX[(chunk[k] & 15) as usize] as char);
            } else {
                s.push_str("  ");
            }
            if k % 2 == 1 { s.push(' '); }
        }
        s.push(' ');
        for &b in chunk {
            s.push(if (0x20..0x7f).contains(&b) { b as char } else { '.' });
        }
        s.push('\n');
        out(&s);
    }
}

fn cmd_diff(args: &[String]) {
    let (_, ops) = split_flags(args);
    if ops.len() != 2 {
        err("diff: usage: diff FILE1 FILE2\n");
        io::set_status(2);
        return;
    }
    let a = match load("diff", &ops[0]) { Some(d) => String::from_utf8_lossy(&d).into_owned(), None => { io::set_status(2); return; } };
    let b = match load("diff", &ops[1]) { Some(d) => String::from_utf8_lossy(&d).into_owned(), None => { io::set_status(2); return; } };
    let la: Vec<&str> = a.lines().collect();
    let lb: Vec<&str> = b.lines().collect();
    // trim common prefix/suffix
    let mut pre = 0;
    while pre < la.len() && pre < lb.len() && la[pre] == lb[pre] { pre += 1; }
    let mut suf = 0;
    while suf < la.len() - pre && suf < lb.len() - pre && la[la.len() - 1 - suf] == lb[lb.len() - 1 - suf] { suf += 1; }
    let xa = &la[pre..la.len() - suf];
    let xb = &lb[pre..lb.len() - suf];
    if xa.is_empty() && xb.is_empty() {
        io::set_status(0);
        return;
    }
    let (n, m) = (xa.len(), xb.len());
    if (n + 1) * (m + 1) > 1_000_000 {
        errs(&["diff: files differ, but the changed region is too large (", &io::fmt_usize(n), " x ",
            &io::fmt_usize(m), " lines) for this in-kernel diff\n"]);
        io::set_status(1);
        return;
    }
    // LCS table (lengths), u16 is enough because n,m <= 999_999 / 2 only when other is tiny
    let w = m + 1;
    let mut t: Vec<u32> = alloc::vec![0; (n + 1) * w];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            t[i * w + j] = if xa[i] == xb[j] { t[(i + 1) * w + j + 1] + 1 } else { t[(i + 1) * w + j].max(t[i * w + j + 1]) };
        }
    }
    // walk and emit hunks in normal diff format
    let (mut i, mut j) = (0usize, 0usize);
    let mut s = String::new();
    while i < n || j < m {
        if i < n && j < m && xa[i] == xb[j] { i += 1; j += 1; continue; }
        let (si, sj) = (i, j);
        while (i < n || j < m) && !(i < n && j < m && xa[i] == xb[j]) {
            if j >= m || (i < n && t[(i + 1) * w + j] >= t[i * w + j + 1]) { i += 1; } else { j += 1; }
        }
        let rng = |lo: usize, hi: usize| if hi - lo <= 1 { format!("{}", lo + pre + if hi > lo { 1 } else { 0 }) } else { format!("{},{}", lo + pre + 1, hi + pre) };
        let (da, db) = (i - si, j - sj);
        let head = if da > 0 && db > 0 {
            format!("{}c{}\n", rng(si, i), rng(sj, j))
        } else if da > 0 {
            format!("{}d{}\n", rng(si, i), sj + pre)
        } else {
            format!("{}a{}\n", si + pre, rng(sj, j))
        };
        s.push_str(&head);
        out(&s); s.clear();
        for k in si..i { outc(&format!("< {}\n", xa[k]), 0x00FF6666); }
        if da > 0 && db > 0 { out("---\n"); }
        for k in sj..j { outc(&format!("> {}\n", xb[k]), 0x0066FF66); }
    }
    io::set_status(1);
}

// ─── awk (small subset) ─────────────────────────────────────────────────────

enum AwkPat { All, Begin, End, Re(regex::Regex, bool), Cmp(String, String, String) }
enum AwkItem { Field(String), Lit(String), Nr, Nf }

fn awk_usage() {
    err("awk: unsupported program. This awk supports:\n");
    err("  awk [-F sep] '[PATTERN] { print ITEM[, ITEM...] }' [file]\n");
    err("  PATTERN: BEGIN | END | /regex/ | !/regex/ | EXPR OP EXPR  (OP: == != < > <= >= ~ !~)\n");
    err("  ITEM: $0 $1.. $NF NR NF \"text\"\n");
}

fn awk_value(expr: &str, fields: &[&str], line: &str, nr: usize) -> String {
    let e = expr.trim();
    if e == "NR" { return io::fmt_usize(nr); }
    if e == "NF" { return io::fmt_usize(fields.len()); }
    if let Some(f) = e.strip_prefix('$') {
        let idx = if f == "NF" { fields.len() } else { f.parse::<usize>().unwrap_or(usize::MAX) };
        if idx == 0 { return String::from(line); }
        return fields.get(idx.wrapping_sub(1)).map(|s| String::from(*s)).unwrap_or_default();
    }
    if e.len() >= 2 && e.starts_with('"') && e.ends_with('"') { return String::from(&e[1..e.len() - 1]); }
    String::from(e)
}

fn cmd_awk(args: &[String]) {
    let mut sep: Option<String> = None;
    let mut i = 0;
    let mut prog: Option<String> = None;
    let mut files = Vec::new();
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-F" { sep = args.get(i + 1).cloned(); i += 2; continue; }
        if let Some(s) = a.strip_prefix("-F") { sep = Some(String::from(s)); i += 1; continue; }
        if prog.is_none() { prog = Some(args[i].clone()); } else { files.push(args[i].clone()); }
        i += 1;
    }
    let prog = match prog { Some(p) => p, None => { awk_usage(); return; } };
    // parse rules: PATTERN? { print ... } ...
    let mut rules: Vec<(AwkPat, Option<Vec<AwkItem>>)> = Vec::new();
    let mut rest = prog.trim();
    while !rest.is_empty() {
        let brace = rest.find('{');
        let (pat_s, action) = match brace {
            Some(b) => {
                let close = match rest[b..].find('}') { Some(c) => b + c, None => { awk_usage(); return; } };
                (rest[..b].trim(), Some(rest[b + 1..close].trim()))
            }
            None => (rest, None),
        };
        let pat = if pat_s.is_empty() { AwkPat::All }
            else if pat_s == "BEGIN" { AwkPat::Begin }
            else if pat_s == "END" { AwkPat::End }
            else if (pat_s.starts_with('/') || pat_s.starts_with("!/")) && pat_s.ends_with('/') && pat_s.len() >= 2 {
                let neg = pat_s.starts_with('!');
                let body = &pat_s[if neg { 2 } else { 1 }..pat_s.len() - 1];
                match regex::Regex::new(body) { Ok(r) => AwkPat::Re(r, neg), Err(e) => { errs(&["awk: bad regex: ", &e, "\n"]); return; } }
            } else {
                let ops = ["==", "!=", "<=", ">=", "!~", "~", "<", ">"];
                let mut found = None;
                for op in ops { if let Some(p) = pat_s.find(op) { found = Some((p, op)); break; } }
                match found {
                    Some((p, op)) => AwkPat::Cmp(String::from(pat_s[..p].trim()), String::from(op), String::from(pat_s[p + op.len()..].trim())),
                    None => { awk_usage(); return; }
                }
            };
        let items = match action {
            None => None,
            Some(a) => {
                let a = a.trim().trim_end_matches(';').trim();
                let body = if a == "print" { "" } else if let Some(b) = a.strip_prefix("print ") { b } else if a.is_empty() { "" } else { awk_usage(); return; };
                let mut items = Vec::new();
                let mut cur = String::new();
                let mut in_q = false;
                let flush = |cur: &mut String, items: &mut Vec<AwkItem>| {
                    let t = cur.trim();
                    if !t.is_empty() {
                        items.push(if t == "NR" { AwkItem::Nr } else if t == "NF" { AwkItem::Nf }
                            else if t.starts_with('$') { AwkItem::Field(String::from(t)) }
                            else if t.starts_with('"') { AwkItem::Lit(String::from(t.trim_matches('"'))) }
                            else { AwkItem::Lit(String::from(t)) });
                    }
                    cur.clear();
                };
                for c in body.chars() {
                    if c == '"' { in_q = !in_q; cur.push(c); continue; }
                    if !in_q && c == ',' { flush(&mut cur, &mut items); items.push(AwkItem::Lit(String::from("\u{1}"))); continue; }
                    if !in_q && c == ' ' { flush(&mut cur, &mut items); continue; }
                    cur.push(c);
                }
                flush(&mut cur, &mut items);
                Some(items)
            }
        };
        rules.push((pat, items));
        rest = match brace {
            Some(b) => rest[b..].find('}').map(|c| rest[b + c + 1..].trim()).unwrap_or(""),
            None => "",
        };
    }
    let text = if rules.iter().all(|(p, _)| matches!(p, AwkPat::Begin)) { String::new() } else {
        match all_text("awk", &files) { Some(t) => t, None => return }
    };
    let mut o = String::new();
    let emit = |o: &mut String, items: &Option<Vec<AwkItem>>, fields: &[&str], line: &str, nr: usize| {
        match items {
            None => { o.push_str(line); }
            Some(items) if items.is_empty() => { o.push_str(line); }
            Some(items) => {
                for it in items {
                    match it {
                        AwkItem::Lit(s) if s == "\u{1}" => o.push(' '),
                        AwkItem::Lit(s) => o.push_str(s),
                        AwkItem::Nr => o.push_str(&io::fmt_usize(nr)),
                        AwkItem::Nf => o.push_str(&io::fmt_usize(fields.len())),
                        AwkItem::Field(f) => o.push_str(&awk_value(f, fields, line, nr)),
                    }
                }
            }
        }
        o.push('\n');
    };
    for (p, items) in &rules {
        if matches!(p, AwkPat::Begin) { emit(&mut o, items, &[], "", 0); }
    }
    let mut nr = 0;
    for line in text.lines() {
        nr += 1;
        let fields: Vec<&str> = match &sep {
            Some(s) if s.len() == 1 && s != " " => line.split(s.chars().next().unwrap()).collect(),
            Some(s) if s.len() > 1 => line.split(s.as_str()).collect(),
            _ => line.split_whitespace().collect(),
        };
        for (p, items) in &rules {
            let hit = match p {
                AwkPat::All => true,
                AwkPat::Begin | AwkPat::End => false,
                AwkPat::Re(r, neg) => r.is_match(line) != *neg,
                AwkPat::Cmp(l, op, r) => {
                    let lv = awk_value(l, &fields, line, nr);
                    if op == "~" || op == "!~" {
                        let pat = r.trim_matches('/');
                        match regex::Regex::new(pat) { Ok(re) => re.is_match(&lv) == (op == "~"), Err(_) => false }
                    } else {
                        let rv = awk_value(r, &fields, line, nr);
                        let (ln, rn) = (lv.trim().parse::<f64>(), rv.trim().parse::<f64>());
                        let ord = match (ln, rn) {
                            (Ok(a), Ok(b)) => a.partial_cmp(&b).unwrap_or(core::cmp::Ordering::Equal),
                            _ => lv.cmp(&rv),
                        };
                        match op.as_str() {
                            "==" => ord.is_eq(), "!=" => !ord.is_eq(), "<" => ord.is_lt(), ">" => ord.is_gt(),
                            "<=" => ord.is_le(), _ => ord.is_ge(),
                        }
                    }
                }
            };
            if hit { emit(&mut o, items, &fields, line, nr); }
        }
    }
    for (p, items) in &rules {
        if matches!(p, AwkPat::End) { emit(&mut o, items, &[], "", nr); }
    }
    out(&o);
}

// ═══════════════════════════════════════════════════════════════════════════
// Misc commands
// ═══════════════════════════════════════════════════════════════════════════

fn cmd_basename(args: &[String]) {
    if args.is_empty() { err("basename: missing operand\n"); return; }
    let p = args[0].trim_end_matches('/');
    let mut b = if p.is_empty() { "/" } else { base_of(p) };
    if let Some(suf) = args.get(1) {
        if b.len() > suf.len() && b.ends_with(suf.as_str()) { b = &b[..b.len() - suf.len()]; }
    }
    out(b);
    out("\n");
}

fn cmd_dirname(args: &[String]) {
    if args.is_empty() { err("dirname: missing operand\n"); return; }
    let p = args[0].trim_end_matches('/');
    let d = match p.rfind('/') {
        None => String::from("."),
        Some(0) => String::from("/"),
        Some(i) => String::from(p[..i].trim_end_matches('/')),
    };
    out(if args[0].starts_with('/') && p.is_empty() { "/" } else { &d });
    out("\n");
}

fn cmd_seq(args: &[String]) {
    let mut sep = String::from("\n");
    let mut nums = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-s" { sep = args.get(i + 1).cloned().unwrap_or_default(); i += 2; continue; }
        match args[i].parse::<i64>() {
            Ok(n) => nums.push(n),
            Err(_) => { errs(&["seq: invalid number '", &args[i], "'\n"]); return; }
        }
        i += 1;
    }
    let (first, step, last) = match nums.len() {
        1 => (1, 1, nums[0]),
        2 => (nums[0], 1, nums[1]),
        3 => (nums[0], nums[1], nums[2]),
        _ => { err("seq: usage: seq [-s SEP] [FIRST [INCREMENT]] LAST\n"); return; }
    };
    if step == 0 { err("seq: increment must not be 0\n"); return; }
    let mut v = first;
    let mut s = String::new();
    let mut count = 0usize;
    while (step > 0 && v <= last) || (step < 0 && v >= last) {
        if count > 0 { s.push_str(&sep); }
        s.push_str(&io::fmt_i64(v));
        count += 1;
        if s.len() > 4096 { out(&s); s.clear(); if io::poll_interrupt() { return; } }
        v += step;
    }
    if count > 0 { s.push('\n'); }
    out(&s);
}

fn cmd_yes(args: &[String]) {
    let text = if args.is_empty() { String::from("y") } else { args.join(" ") };
    let mut line = text;
    line.push('\n');
    if io::out_is_captured() {
        // Pipelines run one stage at a time, so `yes` cannot run forever
        // here; it produces a bounded amount of output.
        for _ in 0..10000 { out(&line); }
        return;
    }
    loop {
        for _ in 0..16 { out(&line); }
        if io::poll_interrupt() { return; }
    }
}

/// printf FORMAT [ARGS...] — %s %d %i %u %x %X %o %c %b %% with flags/width/precision.
pub fn format_printf(fmt: &str, args: &[String]) -> String {
    let f: Vec<char> = fmt.chars().collect();
    let mut o = String::new();
    let mut ai = 0usize;
    loop {
        let mut used_arg = false;
        let mut i = 0;
        while i < f.len() {
            let c = f[i];
            if c == '\\' && i + 1 < f.len() {
                // one escape sequence: \0nnn, \xHH or a single character
                let mut j = i + 2;
                if f[i + 1] == '0' {
                    while j < f.len() && j < i + 5 && ('0'..='7').contains(&f[j]) { j += 1; }
                } else if f[i + 1] == 'x' {
                    while j < f.len() && j < i + 4 && f[j].is_ascii_hexdigit() { j += 1; }
                }
                let seq: String = f[i..j].iter().collect();
                let (s, stop) = plum::builtins::unescape_echo(&seq);
                o.push_str(&s);
                if stop { return o; }
                i = j;
                continue;
            }
            if c != '%' { o.push(c); i += 1; continue; }
            i += 1;
            if i < f.len() && f[i] == '%' { o.push('%'); i += 1; continue; }
            let mut flags = String::new();
            while i < f.len() && "-+ 0#".contains(f[i]) { flags.push(f[i]); i += 1; }
            let mut width = String::new();
            while i < f.len() && f[i].is_ascii_digit() { width.push(f[i]); i += 1; }
            let mut prec: Option<usize> = None;
            if i < f.len() && f[i] == '.' {
                i += 1;
                let mut p = String::new();
                while i < f.len() && f[i].is_ascii_digit() { p.push(f[i]); i += 1; }
                prec = Some(p.parse().unwrap_or(0));
            }
            if i >= f.len() { o.push('%'); break; }
            let conv = f[i];
            i += 1;
            let arg = args.get(ai).cloned().unwrap_or_default();
            if ai < args.len() { used_arg = true; }
            ai += 1;
            let num = || -> i64 {
                let a = arg.trim();
                if let Some(ch) = a.strip_prefix('\'') { return ch.chars().next().map(|c| c as i64).unwrap_or(0); }
                if let Some(h) = a.strip_prefix("0x") { return i64::from_str_radix(h, 16).unwrap_or(0); }
                a.parse::<i64>().unwrap_or(0)
            };
            let mut body = match conv {
                's' => match prec { Some(p) => arg.chars().take(p).collect(), None => arg.clone() },
                'b' => plum::builtins::unescape_echo(&arg).0,
                'c' => arg.chars().next().map(String::from).unwrap_or_default(),
                'd' | 'i' => {
                    let n = num();
                    let mut s = io::fmt_i64(n);
                    if n >= 0 && flags.contains('+') { s.insert(0, '+'); }
                    s
                }
                'u' => format!("{}", num() as u64),
                'x' => format!("{:x}", num()),
                'X' => format!("{:X}", num()),
                'o' => format!("{:o}", num()),
                other => { let mut s = String::from("%"); s.push(other); ai -= 1; s }
            };
            let w: usize = width.parse().unwrap_or(0);
            let len = body.chars().count();
            if len < w {
                let padn = w - len;
                if flags.contains('-') {
                    for _ in 0..padn { body.push(' '); }
                } else if flags.contains('0') && "diuxXo".contains(conv) {
                    let neg = body.starts_with('-') || body.starts_with('+');
                    let mut z = String::new();
                    for _ in 0..padn { z.push('0'); }
                    if neg { body.insert_str(1, &z); } else { body.insert_str(0, &z); }
                } else {
                    let mut sp = String::new();
                    for _ in 0..padn { sp.push(' '); }
                    body.insert_str(0, &sp);
                }
            }
            o.push_str(&body);
        }
        // POSIX: reuse the format while arguments remain
        if !used_arg || ai >= args.len() { break; }
    }
    o
}

fn cmd_printf(args: &[String]) {
    if args.is_empty() {
        err("printf: usage: printf FORMAT [ARGUMENT...]\n");
        return;
    }
    let s = format_printf(&args[0], &args[1..]);
    out(&s);
}

fn cmd_xargs(args: &[String]) {
    let mut n: Option<usize> = None;
    let mut repl: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => { n = args.get(i + 1).and_then(|v| v.parse().ok()); if n.is_none() { err("xargs: -n needs a number\n"); return; } i += 2; }
            "-I" => { repl = args.get(i + 1).cloned(); if repl.is_none() { err("xargs: -I needs a string\n"); return; } i += 2; }
            _ => break,
        }
    }
    let mut cmd: Vec<String> = args[i..].to_vec();
    if cmd.is_empty() { cmd.push(String::from("echo")); }
    let input = match io::take_stdin() { Some(s) => s, None => { io::no_stdin("xargs"); return; } };
    let mut status = 0;
    if let Some(r) = repl {
        for line in input.lines() {
            if line.is_empty() { continue; }
            let argv: Vec<String> = cmd.iter().map(|a| a.replace(r.as_str(), line)).collect();
            let st = plum::run_argv(&argv);
            if st != 0 { status = 123; }
            if io::interrupted() { break; }
        }
    } else {
        let items: Vec<String> = input.split_whitespace().map(String::from).collect();
        let chunk = n.unwrap_or(usize::MAX).max(1);
        let mut k = 0;
        loop {
            let end = if items.len() - k > chunk { k + chunk } else { items.len() };
            let mut argv = cmd.clone();
            argv.extend_from_slice(&items[k..end]);
            let st = plum::run_argv(&argv);
            if st != 0 { status = 123; }
            k = end;
            if k >= items.len() || io::interrupted() { break; }
        }
    }
    io::set_status(status);
}

fn cmd_sleep(args: &[String]) {
    if args.is_empty() { err("sleep: missing operand\n"); return; }
    let mut total_us: u64 = 0;
    for a in args {
        let (num, mult) = match a.chars().last() {
            Some('s') => (&a[..a.len() - 1], 1_000_000u64),
            Some('m') => (&a[..a.len() - 1], 60_000_000u64),
            _ => (a.as_str(), 1_000_000u64),
        };
        let (int, frac) = match num.find('.') { Some(p) => (&num[..p], &num[p + 1..]), None => (num, "") };
        let i: u64 = match if int.is_empty() { Ok(0) } else { int.parse::<u64>() } {
            Ok(v) => v,
            Err(_) => { errs(&["sleep: invalid time interval '", a, "'\n"]); return; }
        };
        let mut f_us: u64 = 0;
        let mut scale = mult / 10;
        for c in frac.chars().take(6) {
            match c.to_digit(10) { Some(d) => { f_us += d as u64 * scale; scale /= 10; } None => { errs(&["sleep: invalid time interval '", a, "'\n"]); return; } }
        }
        total_us += i * mult + f_us;
    }
    let start = crate::arch::x86_64::tsc::tsc_stamp_us();
    while crate::arch::x86_64::tsc::tsc_stamp_us().wrapping_sub(start) < total_us {
        if io::poll_interrupt() { io::set_status(130); return; }
        unsafe { core::arch::asm!("hlt"); }
    }
}
