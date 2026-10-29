/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

plum/exec — runs parsed shell programs: word expansion, redirections,
pipelines, control flow, functions and command lookup.

Command lookup order: function → shell builtin → axon coreutils →
grape/tomato/seed → script path (./x.sh) → console handler (if the
console registered one) → "command not found" (127).
*/

extern crate alloc;

use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use super::io;
use super::parse::{self, Node, Redir, RedirKind};
use super::{shell, Control};

/// Hard limit on interpreter recursion (the console runs on a small kernel
/// stack; deep recursion would overflow it).
const MAX_NEST: usize = 96;
const MAX_FUNC_DEPTH: usize = 24;
const MAX_SUBST_DEPTH: usize = 8;

// ─── Node execution ─────────────────────────────────────────────────────────

pub fn run_node(n: &Node) -> i32 {
    let sh = shell();
    if sh.nest >= MAX_NEST {
        io::err("plum: maximum nesting depth exceeded\n");
        sh.control = Control::Exit(1);
        return 1;
    }
    sh.nest += 1;
    let st = run_inner(n);
    let sh = shell();
    sh.nest -= 1;
    super::set_exit_code(st);
    st
}

fn control_active() -> bool {
    shell().control != Control::None || io::interrupted()
}

fn run_inner(n: &Node) -> i32 {
    match n {
        Node::Simple { words, redirs } => run_simple(words, redirs),
        Node::Seq(items) => {
            let mut st = shell().last_exit;
            for item in items {
                st = run_node(item);
                if control_active() { break; }
                if shell().script_depth > 0 && io::poll_interrupt() { break; }
            }
            st
        }
        Node::Pipeline { cmds, negate } => {
            let st = run_pipeline(cmds);
            if *negate { (st == 0) as i32 } else { st }
        }
        Node::And(a, b) => {
            let st = run_node(a);
            if control_active() || st != 0 { return st; }
            run_node(b)
        }
        Node::Or(a, b) => {
            let st = run_node(a);
            if control_active() || st == 0 { return st; }
            run_node(b)
        }
        Node::Background(inner) => {
            io::note("plum: background jobs are not supported yet; running in the foreground\n");
            run_node(inner)
        }
        Node::If { branches, else_body } => {
            for (cond, body) in branches {
                let c = run_node(cond);
                if control_active() { return c; }
                if c == 0 {
                    return run_node(body);
                }
            }
            match else_body {
                Some(b) => run_node(b),
                None => 0,
            }
        }
        Node::For { var, items, body } => {
            let list: Vec<String> = match items {
                Some(words) => {
                    let mut v = Vec::new();
                    for w in words {
                        match expand_fields(w) {
                            Ok(f) => v.extend(f),
                            Err(e) => return expand_error(&e),
                        }
                    }
                    v
                }
                None => shell().positional.clone(),
            };
            let mut st = 0;
            shell().loop_depth += 1;
            for item in list {
                super::setenv(var, &item);
                st = run_node(body);
                if loop_control() { break; }
                if io::poll_interrupt() { break; }
            }
            shell().loop_depth -= 1;
            st
        }
        Node::While { cond, body, until } => {
            let mut st = 0;
            shell().loop_depth += 1;
            loop {
                let c = run_node(cond);
                if control_active() {
                    if loop_control() { break; }
                }
                let go = if *until { c != 0 } else { c == 0 };
                if !go { break; }
                st = run_node(body);
                if loop_control() { break; }
                if io::poll_interrupt() { break; }
            }
            shell().loop_depth -= 1;
            st
        }
        Node::Case { word, arms } => {
            let w = match expand_string(word) {
                Ok(s) => s,
                Err(e) => return expand_error(&e),
            };
            for arm in arms {
                for p in &arm.patterns {
                    let pat = match expand_pattern(p) {
                        Ok(s) => s,
                        Err(e) => return expand_error(&e),
                    };
                    if glob_match(&pat, &w) {
                        return run_node(&arm.body);
                    }
                }
            }
            0
        }
        Node::Group { body, subshell } => {
            if *subshell {
                let sh = shell();
                let saved_env = sh.env.clone();
                let saved_pos = sh.positional.clone();
                let saved_funcs = sh.functions.clone();
                let st = run_node(body);
                let sh = shell();
                sh.env = saved_env;
                sh.positional = saved_pos;
                sh.functions = saved_funcs;
                if let Control::Exit(_) = sh.control { sh.control = Control::None; }
                st
            } else {
                run_node(body)
            }
        }
        Node::FuncDef { name, body } => {
            shell().functions.insert(name.clone(), Rc::clone(body));
            0
        }
        Node::Arith(expr) => {
            let text = match expand_string(expr) {
                Ok(s) => s,
                Err(e) => return expand_error(&e),
            };
            match super::arith::eval(&text) {
                Ok(v) => if v != 0 { 0 } else { 1 },
                Err(e) => {
                    io::err("plum: ((");
                    io::err(&text);
                    io::err(")): ");
                    io::err(&e);
                    io::err("\n");
                    1
                }
            }
        }
        Node::Redirected { node, redirs } => {
            let rf = match setup_redirs(redirs) {
                Ok(r) => r,
                Err(()) => return 1,
            };
            let st = run_node(node);
            finish_redirs(rf);
            st
        }
    }
}

/// Handle break/continue at loop level. Returns true if the loop must stop.
fn loop_control() -> bool {
    let sh = shell();
    if io::interrupted() { return true; }
    match sh.control {
        Control::None => false,
        Control::Break(n) => {
            sh.control = if n > 1 { Control::Break(n - 1) } else { Control::None };
            true
        }
        Control::Continue(n) => {
            if n > 1 {
                sh.control = Control::Continue(n - 1);
                true
            } else {
                sh.control = Control::None;
                false
            }
        }
        Control::Return | Control::Exit(_) => true,
    }
}

fn expand_error(e: &str) -> i32 {
    io::err("plum: ");
    io::err(e);
    io::err("\n");
    1
}

// ─── Pipelines ──────────────────────────────────────────────────────────────

fn run_pipeline(cmds: &[Node]) -> i32 {
    if cmds.len() == 1 {
        return run_node(&cmds[0]);
    }
    let mut input: Option<String> = None;
    let mut st = 0;
    for (i, cmd) in cmds.iter().enumerate() {
        let last = i + 1 == cmds.len();
        let stdin = match input.take() {
            Some(s) => io::Stdin::Data(s, 0),
            None => io::Stdin::Inherit,
        };
        let out = if last { io::Sink::Inherit } else { io::Sink::Capture };
        io::push(out, io::ErrSink::Inherit, stdin);
        st = run_node(cmd);
        let (captured, _) = io::pop();
        if !last {
            input = Some(captured);
        }
        let sh = shell();
        // `exit`/`return`/`break` inside a pipeline stage only ends that stage
        if !last {
            if let Control::Exit(_) | Control::Break(_) | Control::Continue(_) = sh.control {
                sh.control = Control::None;
            }
        }
        if io::interrupted() { break; }
    }
    st
}

// ─── Redirections ───────────────────────────────────────────────────────────

pub struct RedirFrame {
    out_file: Option<(String, bool)>,
    err_file: Option<(String, bool)>,
    out_to_err: bool,
}

fn setup_redirs(redirs: &[Redir]) -> Result<RedirFrame, ()> {
    let mut out = io::Sink::Inherit;
    let mut err = io::ErrSink::Inherit;
    let mut stdin = io::Stdin::Inherit;
    let mut rf = RedirFrame { out_file: None, err_file: None, out_to_err: false };
    for r in redirs {
        let target = if r.target.is_empty() {
            String::new()
        } else {
            match expand_string(&r.target) {
                Ok(t) => t,
                Err(e) => { expand_error(&e); return Err(()); }
            }
        };
        let is_null = target == "/dev/null";
        let path = if target.is_empty() { String::new() } else { super::resolve_path(&target) };
        match r.kind {
            RedirKind::Out | RedirKind::Append | RedirKind::BothOut => {
                if is_null {
                    out = io::Sink::Null;
                    rf.out_file = None;
                } else {
                    if let Some(st) = crate::fs::stat(&path) {
                        if st.node_type == crate::fs::NodeType::Directory {
                            io::err("plum: ");
                            io::err(&target);
                            io::err(": Is a directory\n");
                            return Err(());
                        }
                    }
                    out = io::Sink::Capture;
                    rf.out_file = Some((path, r.kind == RedirKind::Append));
                }
                if r.kind == RedirKind::BothOut { err = io::ErrSink::ToOut; }
                rf.out_to_err = false;
            }
            RedirKind::ErrOut | RedirKind::ErrAppend => {
                if is_null {
                    err = io::ErrSink::Null;
                    rf.err_file = None;
                } else {
                    err = io::ErrSink::Capture;
                    rf.err_file = Some((path, r.kind == RedirKind::ErrAppend));
                }
            }
            RedirKind::ErrToOut => err = io::ErrSink::ToOut,
            RedirKind::OutToErr => {
                out = io::Sink::Capture;
                rf.out_file = None;
                rf.out_to_err = true;
            }
            RedirKind::In => {
                if is_null {
                    stdin = io::Stdin::Data(String::new(), 0);
                    continue;
                }
                match crate::fs::read_file(&path) {
                    Some(data) => {
                        let text = String::from_utf8_lossy(&data).into_owned();
                        stdin = io::Stdin::Data(text, 0);
                    }
                    None => {
                        io::err("plum: ");
                        io::err(&target);
                        io::err(": No such file or directory\n");
                        return Err(());
                    }
                }
            }
        }
    }
    // A plain `> file` with nothing else creates/truncates even if the
    // command prints nothing — handled in finish_redirs.
    io::push(out, err, stdin);
    Ok(rf)
}

fn write_target(path: &str, data: &str, append: bool) {
    let ok = if append {
        crate::fs::append_file(path, data.as_bytes())
    } else {
        crate::fs::write_file(path, data.as_bytes())
    };
    if !ok {
        io::err("plum: cannot write to ");
        io::err(path);
        io::err("\n");
    }
}

fn finish_redirs(rf: RedirFrame) {
    let (out, err) = io::pop();
    if let Some((path, append)) = rf.out_file {
        write_target(&path, &out, append);
    } else if rf.out_to_err {
        io::note(&out);
    }
    if let Some((path, append)) = rf.err_file {
        write_target(&path, &err, append);
    }
}

// ─── Simple commands ────────────────────────────────────────────────────────

fn is_plain(word: &str) -> bool {
    !word.bytes().any(|c| matches!(c, b'\'' | b'"' | b'\\' | b'$' | b'`'))
}

/// `NAME=value` (NAME must be unquoted)
fn split_assignment(word: &str) -> Option<(&str, &str)> {
    let eq = word.find('=')?;
    let name = &word[..eq];
    let b = name.as_bytes();
    if b.is_empty() || !(b[0].is_ascii_alphabetic() || b[0] == b'_') { return None; }
    if !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_') { return None; }
    Some((name, &word[eq + 1..]))
}

fn redir_text(r: &Redir) -> String {
    let op = match r.kind {
        RedirKind::Out => ">",
        RedirKind::Append => ">>",
        RedirKind::In => "<",
        RedirKind::ErrOut => "2>",
        RedirKind::ErrAppend => "2>>",
        RedirKind::ErrToOut => "2>&1",
        RedirKind::OutToErr => ">&2",
        RedirKind::BothOut => "&>",
    };
    let mut s = String::from(op);
    if !r.target.is_empty() {
        s.push(' ');
        s.push_str(&r.target);
    }
    s
}

fn run_simple(words: &[String], redirs: &[Redir]) -> i32 {
    // Alias expansion on the first word
    if let Some(first) = words.first() {
        if is_plain(first) {
            let sh = shell();
            if let Some(val) = sh.aliases.get(first.as_str()).cloned() {
                if !sh.expanding_aliases.iter().any(|a| a == first) && sh.expanding_aliases.len() < 8 {
                    let mut text = val;
                    for w in &words[1..] {
                        text.push(' ');
                        text.push_str(w);
                    }
                    for r in redirs {
                        text.push(' ');
                        text.push_str(&redir_text(r));
                    }
                    shell().expanding_aliases.push(first.clone());
                    let st = match parse::parse(&text) {
                        Ok(node) => run_node(&node),
                        Err(e) => expand_error(&e),
                    };
                    shell().expanding_aliases.pop();
                    return st;
                }
            }
        }
    }

    // Expand words: leading NAME=value words are assignments
    let mut assigns: Vec<(String, String)> = Vec::new();
    let mut argv: Vec<String> = Vec::new();
    let subst_status_before = shell().last_exit;
    let mut had_subst = false;
    for w in words {
        if argv.is_empty() {
            if let Some((name, value)) = split_assignment(w) {
                match expand_string(value) {
                    Ok(v) => {
                        if value.contains("$(") || value.contains('`') { had_subst = true; }
                        assigns.push((String::from(name), v));
                    }
                    Err(e) => return expand_error(&e),
                }
                continue;
            }
        }
        match expand_fields(w) {
            Ok(f) => argv.extend(f),
            Err(e) => return expand_error(&e),
        }
    }

    let rf = if redirs.is_empty() {
        None
    } else {
        match setup_redirs(redirs) {
            Ok(r) => Some(r),
            Err(()) => return 1,
        }
    };

    let st = if argv.is_empty() {
        for (k, v) in &assigns {
            super::setenv(k, v);
        }
        // status of an assignment-only line is that of its last $(...)
        if had_subst { shell().last_exit } else { let _ = subst_status_before; 0 }
    } else {
        // temporary assignments for this command only
        let mut saved: Vec<(String, Option<String>)> = Vec::new();
        for (k, v) in &assigns {
            saved.push((k.clone(), shell().env.get(k).cloned()));
            super::setenv(k, v);
        }
        let st = run_argv(&argv);
        for (k, old) in saved {
            match old {
                Some(v) => super::setenv(&k, &v),
                None => super::unsetenv(&k),
            }
        }
        st
    };

    if let Some(rf) = rf {
        finish_redirs(rf);
    }
    st
}

/// Look up and run a command given as argv.
pub fn run_argv(argv: &[String]) -> i32 {
    if argv.is_empty() { return 0; }
    let name = argv[0].as_str();
    let args = &argv[1..];

    // 1. shell functions
    let func = shell().functions.get(name).cloned();
    if let Some(body) = func {
        return call_function(name, &body, args);
    }

    // 2. shell builtins
    io::begin_command();
    if let Some(st) = super::builtins::run(name, args) {
        return st;
    }

    // 3. axon coreutils
    io::begin_command();
    if crate::userspace::axon::run(name, args) {
        return io::end_command();
    }

    // 4. path to a script
    if name.contains('/') {
        let path = super::resolve_path(name);
        return match crate::fs::stat(&path) {
            None => {
                io::err("plum: ");
                io::err(name);
                io::err(": No such file or directory\n");
                127
            }
            Some(st) if st.node_type == crate::fs::NodeType::Directory => {
                io::err("plum: ");
                io::err(name);
                io::err(": Is a directory\n");
                126
            }
            Some(_) => exec_file(name, &path, args),
        };
    }

    // 5. console commands (help, date, ...)
    if super::CONSOLE_COMMANDS.contains(&name) {
        if let Some(handler) = super::external_handler() {
            let mut joined = String::new();
            for (i, a) in args.iter().enumerate() {
                if i > 0 { joined.push(' '); }
                joined.push_str(a);
            }
            if io::out_is_captured() {
                io::note("plum: note: output of console command '");
                io::note(name);
                io::note("' goes to the screen and cannot be piped or redirected\n");
            }
            if handler(name, &joined) {
                return 0;
            }
        }
        io::err("plum: ");
        io::err(name);
        io::err(": built into the console; it cannot be used inside pipelines, scripts or with redirections yet\n");
        return 126;
    }

    // 6. program on $PATH (ELF executables are run as ring-3 processes)
    if let Some(path) = find_in_path(name) {
        return exec_file(name, &path, args);
    }

    io::err("plum: ");
    io::err(name);
    io::err(": command not found\n");
    127
}

/// First regular file called `name` in $PATH (default `/usr/bin:/bin`).
fn find_in_path(name: &str) -> Option<String> {
    if name.is_empty() || name.contains('/') { return None; }
    let path = super::getenv("PATH").map(String::from).unwrap_or_else(|| String::from("/usr/bin:/bin"));
    for dir in path.split(':') {
        if dir.is_empty() { continue; }
        let cand = alloc::format!("{}/{}", dir.trim_end_matches('/'), name);
        if let Some(st) = crate::fs::stat(&cand) {
            if st.node_type != crate::fs::NodeType::Directory { return Some(cand); }
        }
    }
    None
}

/// Run a file given by absolute path: an ELF image becomes a ring-3 process,
/// anything else is run as a shell script.
fn exec_file(name: &str, path: &str, args: &[String]) -> i32 {
    let data = crate::fs::read_file(path).unwrap_or_default();
    if data.starts_with(b"\x7FELF") {
        run_elf(name, &data, args)
    } else {
        super::builtins::run_script(path, args)
    }
}

/// Spawn an ELF program, wait for it and return its exit code. Ctrl+C kills it.
/// Note: ring-3 stdout currently goes to the serial port (the write syscall), so the
/// program's output is neither shown on the framebuffer console nor capturable.
fn run_elf(name: &str, image: &[u8], args: &[String]) -> i32 {
    use crate::core::scheduler::{self, Capability};
    let mut argv: Vec<&str> = Vec::with_capacity(args.len() + 1);
    argv.push(name);
    for a in args { argv.push(a.as_str()); }
    let prog = name.rsplit('/').next().unwrap_or(name);
    let caps = alloc::vec![Capability::Serial, Capability::FsRead, Capability::FsWrite, Capability::Framebuf];
    let pid = match crate::core::elf::spawn(prog, image, &argv, caps) {
        Ok(pid) => pid,
        Err(e) => {
            io::err("plum: ");
            io::err(name);
            io::err(": cannot execute: ");
            io::err(e.as_str());
            io::err("\n");
            return 126;
        }
    };
    // Wait; Ctrl+C (flagged by the keyboard IRQ) kills the process.
    let mut killed = false;
    while scheduler::task_alive(pid) {
        if io::poll_interrupt() {
            scheduler::signal_pid(pid, 9);
            killed = true;
            break;
        }
        scheduler::sys_yield();
    }
    let code = scheduler::wait_pid(pid);
    if killed { return 130; }
    match code {
        Some(c) if c == scheduler::EXIT_KILLED => {
            io::err("plum: ");
            io::err(name);
            io::err(": terminated by the kernel (fault)\n");
            139
        }
        Some(c) => (c & 0xFF) as i32,
        None => 0,
    }
}

fn call_function(name: &str, body: &Rc<Node>, args: &[String]) -> i32 {
    let sh = shell();
    if sh.func_depth >= MAX_FUNC_DEPTH {
        io::err("plum: ");
        io::err(name);
        io::err(": maximum function nesting depth exceeded\n");
        return 1;
    }
    sh.func_depth += 1;
    let saved_pos = core::mem::replace(&mut sh.positional, args.to_vec());
    sh.locals.push(Vec::new());
    let st = run_node(body);
    let sh = shell();
    // restore locals
    if let Some(frame) = sh.locals.pop() {
        for (k, old) in frame.into_iter().rev() {
            match old {
                Some(v) => { sh.env.insert(k, v); }
                None => { sh.env.remove(&k); }
            }
        }
    }
    sh.positional = saved_pos;
    sh.func_depth -= 1;
    if sh.control == Control::Return {
        sh.control = Control::None;
        return sh.last_exit;
    }
    st
}

// ─── Command substitution ───────────────────────────────────────────────────

fn command_subst(code: &str) -> Result<String, String> {
    let sh = shell();
    if sh.subst_depth >= MAX_SUBST_DEPTH {
        return Err(String::from("command substitution nested too deeply"));
    }
    sh.subst_depth += 1;
    let node = parse::parse(code);
    let saved_control = shell().control;
    io::push(io::Sink::Capture, io::ErrSink::Inherit, io::Stdin::Inherit);
    let st = match node {
        Ok(n) => run_node(&n),
        Err(e) => {
            io::err("plum: ");
            io::err(&e);
            io::err("\n");
            2
        }
    };
    let (mut out, _) = io::pop();
    let sh = shell();
    sh.subst_depth -= 1;
    sh.control = saved_control;
    super::set_exit_code(st);
    while out.ends_with('\n') {
        out.pop();
    }
    Ok(out)
}

// ─── Word expansion ─────────────────────────────────────────────────────────

/// Builder for fields produced by expanding one word.
struct Fields {
    fields: Vec<(String, String, bool)>, // (value, glob pattern, has unquoted glob)
    cur: String,
    pat: String,
    glob: bool,
    started: bool,
}

impl Fields {
    fn new() -> Self {
        Fields { fields: Vec::new(), cur: String::new(), pat: String::new(), glob: false, started: false }
    }
    fn lit(&mut self, c: char) {
        self.cur.push(c);
        if c == '*' || c == '?' || c == '[' {
            self.glob = true;
            self.pat.push(c);
        } else {
            if c == ']' || c == '\\' { self.pat.push('\\'); }
            self.pat.push(c);
        }
        self.started = true;
    }
    fn quoted(&mut self, s: &str) {
        for c in s.chars() {
            self.cur.push(c);
            if matches!(c, '*' | '?' | '[' | ']' | '\\') { self.pat.push('\\'); }
            self.pat.push(c);
        }
        self.started = true;
    }
    /// Unquoted expansion result: subject to field splitting (not globbing).
    fn split(&mut self, s: &str) {
        for c in s.chars() {
            if c == ' ' || c == '\t' || c == '\n' {
                self.finish(false);
            } else {
                let mut b = [0u8; 4];
                self.quoted(c.encode_utf8(&mut b));
            }
        }
    }
    fn finish(&mut self, force: bool) {
        if self.started || force {
            let cur = core::mem::take(&mut self.cur);
            let pat = core::mem::take(&mut self.pat);
            self.fields.push((cur, pat, self.glob));
        }
        self.glob = false;
        self.started = false;
    }
}

fn find_close(chars: &[char], mut i: usize, open: char, close: char) -> Option<usize> {
    // i points just after the opening char; returns index of matching close
    let mut depth = 1;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' { i += 2; continue; }
        if c == '\'' {
            i += 1;
            while i < chars.len() && chars[i] != '\'' { i += 1; }
        } else if c == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' { i += 1; }
                i += 1;
            }
        } else if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 { return Some(i); }
        }
        i += 1;
    }
    None
}

fn positional(n: usize) -> String {
    let sh = shell();
    if n == 0 {
        return sh.script_name.clone();
    }
    sh.positional.get(n - 1).cloned().unwrap_or_default()
}

fn var_lookup(name: &str) -> Option<String> {
    if let Ok(n) = name.parse::<usize>() {
        let sh = shell();
        if n == 0 { return Some(sh.script_name.clone()); }
        return sh.positional.get(n - 1).cloned();
    }
    match name {
        "#" => Some(io::fmt_usize(shell().positional.len())),
        "?" => Some(io::fmt_i64(shell().last_exit as i64)),
        "@" | "*" => Some(shell().positional.join(" ")),
        _ => shell().env.get(name).cloned(),
    }
}

/// Expand `${...}` contents.
fn expand_brace(inner: &str) -> Result<String, String> {
    if let Some(name) = inner.strip_prefix('#') {
        if !name.is_empty() {
            return Ok(io::fmt_usize(var_lookup(name).unwrap_or_default().chars().count()));
        }
    }
    // find the operator position
    let b = inner.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') { i += 1; }
    if i == 0 && !b.is_empty() && matches!(b[0], b'?' | b'#' | b'@' | b'*') { i = 1; }
    let name = &inner[..i];
    if name.is_empty() {
        return Err(alloc::format!("${{{}}}: bad substitution", inner));
    }
    let rest = &inner[i..];
    let val = var_lookup(name);
    if rest.is_empty() {
        return Ok(val.unwrap_or_default());
    }
    let (op, word) = if rest.starts_with(":-") || rest.starts_with(":=") || rest.starts_with(":+") || rest.starts_with(":?")
        || rest.starts_with("##") || rest.starts_with("%%") {
        (&rest[..2], &rest[2..])
    } else {
        (&rest[..1], &rest[1..])
    };
    let set_nonempty = val.as_ref().map(|v| !v.is_empty()).unwrap_or(false);
    let is_set = val.is_some();
    match op {
        ":-" => if set_nonempty { Ok(val.unwrap()) } else { expand_string(word) },
        "-" => if is_set { Ok(val.unwrap()) } else { expand_string(word) },
        ":=" | "=" => {
            if (op == ":=" && set_nonempty) || (op == "=" && is_set) {
                Ok(val.unwrap())
            } else {
                let w = expand_string(word)?;
                super::setenv(name, &w);
                Ok(w)
            }
        }
        ":+" => if set_nonempty { expand_string(word) } else { Ok(String::new()) },
        "+" => if is_set { expand_string(word) } else { Ok(String::new()) },
        ":?" | "?" => {
            if set_nonempty || (op == "?" && is_set) {
                Ok(val.unwrap())
            } else {
                let msg = expand_string(word)?;
                Err(alloc::format!("{}: {}", name, if msg.is_empty() { String::from("parameter null or not set") } else { msg }))
            }
        }
        "#" | "##" | "%" | "%%" => {
            let v = val.unwrap_or_default();
            let pat = expand_pattern(word)?;
            let chars: Vec<(usize, char)> = v.char_indices().collect();
            let mut cuts: Vec<usize> = chars.iter().map(|(i, _)| *i).collect();
            cuts.push(v.len());
            Ok(match op {
                "#" => cuts.iter().find(|&&c| glob_match(&pat, &v[..c])).map(|&c| String::from(&v[c..])).unwrap_or(v.clone()),
                "##" => cuts.iter().rev().find(|&&c| glob_match(&pat, &v[..c])).map(|&c| String::from(&v[c..])).unwrap_or(v.clone()),
                "%" => cuts.iter().rev().find(|&&c| glob_match(&pat, &v[c..])).map(|&c| String::from(&v[..c])).unwrap_or(v.clone()),
                _ => cuts.iter().find(|&&c| glob_match(&pat, &v[c..])).map(|&c| String::from(&v[..c])).unwrap_or(v.clone()),
            })
        }
        _ => Err(alloc::format!("${{{}}}: bad substitution", inner)),
    }
}

/// Core expansion. `split`: perform field splitting/globbing (command
/// arguments); otherwise produce one string (assignments, targets).
fn expand_core(word: &str, split: bool) -> Result<Fields, String> {
    let chars: Vec<char> = word.chars().collect();
    let mut f = Fields::new();
    let mut i = 0usize;
    let mut in_dq = false;

    // tilde
    if !chars.is_empty() && chars[0] == '~' && (chars.len() == 1 || chars[1] == '/') {
        let home = super::getenv("HOME").unwrap_or("/");
        f.quoted(home);
        i = 1;
    }

    while i < chars.len() {
        let c = chars[i];
        if in_dq {
            match c {
                '"' => { in_dq = false; f.started = true; i += 1; }
                '\\' => {
                    if i + 1 < chars.len() && matches!(chars[i + 1], '$' | '`' | '"' | '\\' | '\n') {
                        let mut b = [0u8; 4];
                        f.quoted(chars[i + 1].encode_utf8(&mut b));
                        i += 2;
                    } else {
                        f.quoted("\\");
                        i += 1;
                    }
                }
                '$' | '`' => {
                    let (val, adv, is_at) = expand_dollar(&chars, i)?;
                    if is_at && split {
                        // "$@": one field per positional parameter
                        let params = shell().positional.clone();
                        for (k, p) in params.iter().enumerate() {
                            f.quoted(p);
                            if k + 1 < params.len() { f.finish(true); }
                        }
                        if params.is_empty() && !f.started { /* produce nothing */ }
                    } else {
                        f.quoted(&val);
                    }
                    i += adv;
                }
                _ => {
                    let mut b = [0u8; 4];
                    f.quoted(c.encode_utf8(&mut b));
                    i += 1;
                }
            }
            continue;
        }
        match c {
            '\'' => {
                let mut j = i + 1;
                let mut s = String::new();
                while j < chars.len() && chars[j] != '\'' {
                    s.push(chars[j]);
                    j += 1;
                }
                f.quoted(&s);
                i = j + 1;
            }
            '"' => {
                in_dq = true;
                f.started = true;
                i += 1;
            }
            '\\' => {
                if i + 1 < chars.len() {
                    let mut b = [0u8; 4];
                    f.quoted(chars[i + 1].encode_utf8(&mut b));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            '$' | '`' => {
                let (val, adv, _) = expand_dollar(&chars, i)?;
                if adv == 1 && c == '$' {
                    f.lit('$');
                } else if split {
                    f.split(&val);
                } else {
                    f.quoted(&val);
                }
                i += adv;
            }
            _ => {
                f.lit(c);
                i += 1;
            }
        }
    }
    Ok(f)
}

/// Expand a `$...` or backtick construct at chars[i].
/// Returns (value, chars consumed, is "$@").
fn expand_dollar(chars: &[char], i: usize) -> Result<(String, usize, bool), String> {
    if chars[i] == '`' {
        let mut j = i + 1;
        let mut code = String::new();
        while j < chars.len() && chars[j] != '`' {
            if chars[j] == '\\' && j + 1 < chars.len() && matches!(chars[j + 1], '`' | '\\' | '$') {
                code.push(chars[j + 1]);
                j += 2;
                continue;
            }
            code.push(chars[j]);
            j += 1;
        }
        let out = command_subst(&code)?;
        return Ok((out, j + 1 - i, false));
    }
    // chars[i] == '$'
    if i + 1 >= chars.len() {
        return Ok((String::from("$"), 1, false));
    }
    let n = chars[i + 1];
    if n == '(' {
        if i + 2 < chars.len() && chars[i + 2] == '(' {
            // $(( arithmetic ))
            if let Some(end) = find_close(chars, i + 3, '(', ')') {
                if end + 1 < chars.len() && chars[end + 1] == ')' {
                    let expr: String = chars[i + 3..end].iter().collect();
                    let expr = expand_string(&expr)?;
                    let v = super::arith::eval(&expr).map_err(|e| alloc::format!("$(({})): {}", expr.trim(), e))?;
                    return Ok((io::fmt_i64(v), end + 2 - i, false));
                }
            }
        }
        let end = find_close(chars, i + 2, '(', ')').ok_or_else(|| String::from("unterminated $("))?;
        let code: String = chars[i + 2..end].iter().collect();
        let out = command_subst(&code)?;
        return Ok((out, end + 1 - i, false));
    }
    if n == '{' {
        let mut j = i + 2;
        while j < chars.len() && chars[j] != '}' { j += 1; }
        if j >= chars.len() { return Err(String::from("unterminated ${")); }
        let inner: String = chars[i + 2..j].iter().collect();
        let v = expand_brace(&inner)?;
        return Ok((v, j + 1 - i, false));
    }
    if n == '@' {
        return Ok((shell().positional.join(" "), 2, true));
    }
    if matches!(n, '?' | '#' | '*') {
        let mut b = [0u8; 4];
        return Ok((var_lookup(n.encode_utf8(&mut b)).unwrap_or_default(), 2, false));
    }
    if n.is_ascii_digit() {
        return Ok((positional(n as usize - '0' as usize), 2, false));
    }
    if n.is_ascii_alphabetic() || n == '_' {
        let mut j = i + 1;
        while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') { j += 1; }
        let name: String = chars[i + 1..j].iter().collect();
        return Ok((shell().env.get(&name).cloned().unwrap_or_default(), j - i, false));
    }
    // lone '$'
    Ok((String::from("$"), 1, false))
}

/// Expand a word into fields (split + glob) — for command arguments.
pub fn expand_fields(word: &str) -> Result<Vec<String>, String> {
    let mut f = expand_core(word, true)?;
    f.finish(false);
    let mut out = Vec::new();
    for (val, pat, has_glob) in f.fields {
        if has_glob {
            let matches = glob_expand(&pat);
            if matches.is_empty() {
                out.push(val);
            } else {
                out.extend(matches);
            }
        } else {
            out.push(val);
        }
    }
    Ok(out)
}

/// Expand a word to a single string (no splitting, no globbing).
pub fn expand_string(word: &str) -> Result<String, String> {
    let f = expand_core(word, false)?;
    let mut s = String::new();
    for (v, _, _) in &f.fields {
        if !s.is_empty() { s.push(' '); }
        s.push_str(v);
    }
    if !f.cur.is_empty() {
        if !s.is_empty() && !f.fields.is_empty() { s.push(' '); }
        s.push_str(&f.cur);
    }
    Ok(s)
}

/// Expand a word to a glob pattern (quoted chars escaped) — for case.
fn expand_pattern(word: &str) -> Result<String, String> {
    let mut f = expand_core(word, false)?;
    f.finish(false);
    let mut s = String::new();
    for (_, p, _) in &f.fields {
        s.push_str(p);
    }
    Ok(s)
}

// ─── Globbing ───────────────────────────────────────────────────────────────

/// Match `name` against a shell pattern: * ? [abc] [a-z] [!x] and \x.
pub fn glob_match(pat: &str, name: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let n: Vec<char> = name.chars().collect();
    glob_rec(&p, &n)
}

fn glob_rec(p: &[char], n: &[char]) -> bool {
    let (mut pi, mut ni) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    star = Some((pi, ni));
                    pi += 1;
                    continue;
                }
                '?' => { pi += 1; ni += 1; continue; }
                '[' => {
                    if let Some((matched, len)) = class_match(&p[pi..], n[ni]) {
                        if matched { pi += len; ni += 1; continue; }
                    } else if n[ni] == '[' {
                        pi += 1; ni += 1; continue;
                    }
                }
                '\\' if pi + 1 < p.len() => {
                    if p[pi + 1] == n[ni] { pi += 2; ni += 1; continue; }
                }
                c => {
                    if c == n[ni] { pi += 1; ni += 1; continue; }
                }
            }
        }
        if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
            continue;
        }
        return false;
    }
    while pi < p.len() && p[pi] == '*' { pi += 1; }
    pi == p.len()
}

/// Match a bracket expression at p[0]=='['. Returns (matched, pattern length).
fn class_match(p: &[char], c: char) -> Option<(bool, usize)> {
    let mut i = 1;
    let negate = i < p.len() && (p[i] == '!' || p[i] == '^');
    if negate { i += 1; }
    let mut matched = false;
    let mut first = true;
    while i < p.len() {
        if p[i] == ']' && !first {
            return Some((matched != negate, i + 1));
        }
        first = false;
        let lo = if p[i] == '\\' && i + 1 < p.len() { i += 1; p[i] } else { p[i] };
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            let hi = p[i + 2];
            if lo <= c && c <= hi { matched = true; }
            i += 3;
        } else {
            if lo == c { matched = true; }
            i += 1;
        }
    }
    None
}

fn has_glob_chars(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => { i += 2; continue; }
            b'*' | b'?' | b'[' => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut esc = false;
    for c in s.chars() {
        if esc { out.push(c); esc = false; }
        else if c == '\\' { esc = true; }
        else { out.push(c); }
    }
    out
}

/// Expand a glob pattern against the VFS. Returns sorted matches (as the
/// user typed them: relative patterns give relative results).
fn glob_expand(pat: &str) -> Vec<String> {
    let absolute = pat.starts_with('/');
    let comps: Vec<&str> = pat.split('/').filter(|c| !c.is_empty()).collect();
    // (display path, absolute path)
    let mut cur: Vec<(String, String)> = if absolute {
        alloc::vec![(String::new(), String::new())]
    } else {
        let cwd = String::from(super::cwd());
        alloc::vec![(String::new(), if cwd == "/" { String::new() } else { cwd })]
    };
    for (ci, comp) in comps.iter().enumerate() {
        let last = ci + 1 == comps.len();
        let mut next = Vec::new();
        for (disp, abs) in &cur {
            let dir = if abs.is_empty() { String::from("/") } else { abs.clone() };
            if has_glob_chars(comp) {
                if let Some(entries) = crate::fs::readdir(&dir) {
                    let mut names: Vec<(String, bool)> = entries.iter()
                        .map(|e| (e.name.clone(), e.node_type == crate::fs::NodeType::Directory))
                        .collect();
                    names.sort();
                    for (name, is_dir) in names {
                        if name.starts_with('.') && !comp.starts_with('.') { continue; }
                        if !last && !is_dir { continue; }
                        if glob_match(comp, &name) {
                            let d = join_disp(disp, &name, absolute);
                            let a = alloc::format!("{}/{}", abs, name);
                            next.push((d, a));
                        }
                    }
                }
            } else {
                let name = unescape(comp);
                let a = alloc::format!("{}/{}", abs, name);
                if comp == &"." || comp == &".." || crate::fs::exists(&a) {
                    let d = join_disp(disp, &name, absolute);
                    let a = if comp == &".." || comp == &"." { super::resolve_path(&a) } else { a };
                    next.push((d, if a == "/" { String::new() } else { a }));
                }
            }
        }
        cur = next;
        if cur.is_empty() { break; }
    }
    cur.into_iter().map(|(d, _)| d).collect()
}

fn join_disp(disp: &str, name: &str, absolute: bool) -> String {
    if disp.is_empty() {
        if absolute { alloc::format!("/{}", name) } else { String::from(name) }
    } else {
        alloc::format!("{}/{}", disp, name)
    }
}
