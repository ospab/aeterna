/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

plum/builtins — commands implemented inside the shell itself.

  : true false echo cd pwd export unset set env printenv alias unalias
  source . bash sh type which command test [ [[ read exit return break
  continue local shift eval let plum save write grape tomato seed
*/

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::io;
use super::{shell, Control};

pub const BUILTINS: &[&str] = &[
    ":", "true", "false", "echo", "cd", "pwd", "export", "unset", "set", "env", "printenv",
    "alias", "unalias", "source", ".", "bash", "sh", "type", "which", "command", "test", "[", "[[",
    "read", "exit", "return", "break", "continue", "local", "shift", "eval", "let", "plum",
    "save", "write", "grape", "tomato", "seed",
];

/// Run a builtin. Returns None if `name` is not a builtin.
pub fn run(name: &str, args: &[String]) -> Option<i32> {
    let st = match name {
        ":" | "true" => 0,
        "false" => 1,
        "echo" => echo(args),
        "cd" => cd(args),
        "pwd" => { io::out(super::cwd()); io::out("\n"); 0 }
        "export" => export(args),
        "unset" => unset(args),
        "set" => set(args),
        "env" => env(args),
        "printenv" => printenv(args),
        "alias" => alias(args),
        "unalias" => unalias(args),
        "source" | "." => {
            if args.is_empty() {
                io::err("source: filename argument required\n");
                2
            } else {
                let path = super::resolve_path(&args[0]);
                source_file(&path, &args[1..])
            }
        }
        "bash" | "sh" => bash(args),
        "type" | "which" => type_cmd(name, args),
        "command" => {
            if args.is_empty() { 0 } else {
                // run without function lookup
                io::begin_command();
                if let Some(st) = run(&args[0], &args[1..]) { st } else { super::run_argv(args) }
            }
        }
        "test" => test_cmd(args, None),
        "[" => test_cmd(args, Some("]")),
        "[[" => test_cmd(args, Some("]]")),
        "read" => read(args),
        "exit" => {
            let code = args.first().and_then(|a| a.parse::<i32>().ok()).unwrap_or(shell().last_exit);
            shell().control = Control::Exit(code);
            code
        }
        "return" => {
            let sh = shell();
            if sh.func_depth == 0 && sh.script_depth == 0 {
                io::err("return: can only `return' from a function or sourced script\n");
                1
            } else {
                let code = args.first().and_then(|a| a.parse::<i32>().ok()).unwrap_or(sh.last_exit);
                super::set_exit_code(code);
                shell().control = Control::Return;
                code
            }
        }
        "break" | "continue" => {
            let n = args.first().and_then(|a| a.parse::<usize>().ok()).unwrap_or(1).max(1);
            let sh = shell();
            if sh.loop_depth == 0 {
                io::err(name);
                io::err(": only meaningful in a `for', `while', or `until' loop\n");
                1
            } else {
                sh.control = if name == "break" { Control::Break(n) } else { Control::Continue(n) };
                0
            }
        }
        "local" => local(args),
        "shift" => {
            let n = args.first().and_then(|a| a.parse::<usize>().ok()).unwrap_or(1);
            let sh = shell();
            if n > sh.positional.len() {
                1
            } else {
                sh.positional.drain(..n);
                0
            }
        }
        "eval" => {
            let text = args.join(" ");
            match super::parse::parse(&text) {
                Ok(node) => super::exec::run_node(&node),
                Err(e) => { io::err("eval: "); io::err(&e); io::err("\n"); 2 }
            }
        }
        "let" => {
            if args.is_empty() { io::err("let: expression expected\n"); return Some(1); }
            let mut last = 0i64;
            for a in args {
                match super::arith::eval(a) {
                    Ok(v) => last = v,
                    Err(e) => { io::err("let: "); io::err(&e); io::err("\n"); return Some(1); }
                }
            }
            if last != 0 { 0 } else { 1 }
        }
        "plum" => { plum_info(); 0 }
        "save" => save(),
        "write" => write(args),
        "grape" => {
            let path = args.first().map(|a| super::resolve_path(a)).unwrap_or_default();
            crate::userspace::grape::edit(&path);
            0
        }
        "tomato" => {
            io::begin_command();
            crate::userspace::tomato::run(&args.join(" "));
            io::end_command()
        }
        "seed" => {
            io::begin_command();
            crate::userspace::seed::run(&args.join(" "));
            io::end_command()
        }
        _ => return None,
    };
    Some(st)
}

// ─── echo ───────────────────────────────────────────────────────────────────

fn echo(args: &[String]) -> i32 {
    let mut newline = true;
    let mut escapes = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a.len() >= 2 && a.starts_with('-') && a[1..].chars().all(|c| c == 'n' || c == 'e' || c == 'E') {
            for c in a[1..].chars() {
                match c {
                    'n' => newline = false,
                    'e' => escapes = true,
                    _ => escapes = false,
                }
            }
            i += 1;
        } else {
            break;
        }
    }
    let mut out = String::new();
    for (k, a) in args[i..].iter().enumerate() {
        if k > 0 { out.push(' '); }
        if escapes {
            let (s, stop) = unescape_echo(a);
            out.push_str(&s);
            if stop { io::out(&out); return 0; }
        } else {
            out.push_str(a);
        }
    }
    if newline { out.push('\n'); }
    io::out(&out);
    0
}

/// Interpret backslash escapes. Returns (text, saw \c).
pub fn unescape_echo(s: &str) -> (String, bool) {
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            i += 1;
            match chars[i] {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                'a' => out.push('\x07'),
                'b' => out.push('\x08'),
                'e' => out.push('\x1b'),
                'f' => out.push('\x0c'),
                'v' => out.push('\x0b'),
                '\\' => out.push('\\'),
                'c' => return (out, true),
                '0' => {
                    let mut v = 0u32;
                    let mut n = 0;
                    while n < 3 && i + 1 < chars.len() && ('0'..='7').contains(&chars[i + 1]) {
                        i += 1;
                        v = v * 8 + (chars[i] as u32 - '0' as u32);
                        n += 1;
                    }
                    if let Some(c) = char::from_u32(v) { out.push(c); }
                }
                'x' => {
                    let mut v = 0u32;
                    let mut n = 0;
                    while n < 2 && i + 1 < chars.len() && chars[i + 1].is_ascii_hexdigit() {
                        i += 1;
                        v = v * 16 + chars[i].to_digit(16).unwrap_or(0);
                        n += 1;
                    }
                    if let Some(c) = char::from_u32(v) { out.push(c); }
                }
                c => { out.push('\\'); out.push(c); }
            }
            i += 1;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    (out, false)
}

// ─── cd ─────────────────────────────────────────────────────────────────────

fn cd(args: &[String]) -> i32 {
    let target = match args.first().map(|s| s.as_str()) {
        None | Some("~") => String::from(super::getenv("HOME").unwrap_or("/")),
        Some("-") => match super::getenv("OLDPWD") {
            Some(p) => { let p = String::from(p); io::out(&p); io::out("\n"); p }
            None => { io::err("cd: OLDPWD not set\n"); return 1; }
        },
        Some(p) => String::from(p),
    };
    let abs = super::resolve_path(&target);
    match crate::fs::stat(&abs) {
        Some(st) if st.node_type == crate::fs::NodeType::Directory => {
            let old = String::from(super::cwd());
            super::setenv("OLDPWD", &old);
            super::setenv("PWD", &abs);
            0
        }
        Some(_) if abs != "/" => {
            io::err("cd: ");
            io::err(&target);
            io::err(": Not a directory\n");
            1
        }
        _ => {
            if abs == "/" {
                let old = String::from(super::cwd());
                super::setenv("OLDPWD", &old);
                super::setenv("PWD", "/");
                return 0;
            }
            io::err("cd: ");
            io::err(&target);
            io::err(": No such file or directory\n");
            1
        }
    }
}

// ─── Variables ──────────────────────────────────────────────────────────────

fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && (b[0].is_ascii_alphabetic() || b[0] == b'_') && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn print_vars(prefix: &str, quote: bool) {
    let vars = super::get_env();
    for (k, v) in vars {
        io::out(prefix);
        io::out_c(&k, io::FG_WARN);
        io::out("=");
        if quote { io::out("\""); }
        io::out(&v);
        if quote { io::out("\""); }
        io::out("\n");
    }
}

fn export(args: &[String]) -> i32 {
    if args.is_empty() || (args.len() == 1 && args[0] == "-p") {
        print_vars("export ", true);
        return 0;
    }
    let mut st = 0;
    for a in args {
        if let Some(eq) = a.find('=') {
            let name = &a[..eq];
            if !valid_name(name) {
                io::err("export: `"); io::err(a); io::err("': not a valid identifier\n");
                st = 1;
                continue;
            }
            super::setenv(name, &a[eq + 1..]);
        } else if valid_name(a) {
            if super::getenv(a).is_none() { super::setenv(a, ""); }
        } else {
            io::err("export: `"); io::err(a); io::err("': not a valid identifier\n");
            st = 1;
        }
    }
    st
}

fn unset(args: &[String]) -> i32 {
    if args.is_empty() {
        io::err("unset: not enough arguments\n");
        return 1;
    }
    let (funcs, names) = if args[0] == "-f" { (true, &args[1..]) }
        else if args[0] == "-v" { (false, &args[1..]) }
        else { (false, args) };
    for n in names {
        if funcs {
            shell().functions.remove(n.as_str());
        } else if shell().env.remove(n.as_str()).is_none() {
            shell().functions.remove(n.as_str());
        }
    }
    0
}

fn set(args: &[String]) -> i32 {
    if args.is_empty() {
        print_vars("", false);
        return 0;
    }
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if a.starts_with('-') || a.starts_with('+') {
            io::note("set: shell options (");
            io::note(a);
            io::note(") are not supported; ignored\n");
            i += 1;
            continue;
        }
        break;
    }
    if i < args.len() || args.iter().any(|a| a == "--") {
        shell().positional = args[i..].to_vec();
    }
    0
}

fn env(args: &[String]) -> i32 {
    let mut i = 0;
    let mut assigns = Vec::new();
    while i < args.len() {
        if let Some(eq) = args[i].find('=') {
            if valid_name(&args[i][..eq]) {
                assigns.push((String::from(&args[i][..eq]), String::from(&args[i][eq + 1..])));
                i += 1;
                continue;
            }
        }
        break;
    }
    if i >= args.len() {
        let vars = super::get_env();
        for (k, v) in vars {
            if assigns.iter().any(|(a, _)| *a == k) { continue; }
            io::out(&k); io::out("="); io::out(&v); io::out("\n");
        }
        for (k, v) in &assigns {
            io::out(k); io::out("="); io::out(v); io::out("\n");
        }
        return 0;
    }
    let mut saved = Vec::new();
    for (k, v) in &assigns {
        saved.push((k.clone(), shell().env.get(k).cloned()));
        super::setenv(k, v);
    }
    let st = super::run_argv(&args[i..]);
    for (k, old) in saved {
        match old {
            Some(v) => super::setenv(&k, &v),
            None => super::unsetenv(&k),
        }
    }
    st
}

fn printenv(args: &[String]) -> i32 {
    if args.is_empty() {
        for (k, v) in super::get_env() {
            io::out(&k); io::out("="); io::out(&v); io::out("\n");
        }
        return 0;
    }
    let mut st = 0;
    for a in args {
        match super::getenv(a) {
            Some(v) => { io::out(v); io::out("\n"); }
            None => st = 1,
        }
    }
    st
}

fn local(args: &[String]) -> i32 {
    let sh = shell();
    if sh.func_depth == 0 || sh.locals.is_empty() {
        io::err("local: can only be used in a function\n");
        return 1;
    }
    for a in args {
        let (name, val) = match a.find('=') {
            Some(eq) => (&a[..eq], Some(&a[eq + 1..])),
            None => (a.as_str(), None),
        };
        if !valid_name(name) {
            io::err("local: `"); io::err(a); io::err("': not a valid identifier\n");
            return 1;
        }
        let sh = shell();
        let old = sh.env.get(name).cloned();
        if let Some(frame) = sh.locals.last_mut() {
            if !frame.iter().any(|(k, _)| k == name) {
                frame.push((String::from(name), old));
            }
        }
        super::setenv(name, val.unwrap_or(""));
    }
    0
}

// ─── Aliases ────────────────────────────────────────────────────────────────

fn alias(args: &[String]) -> i32 {
    if args.is_empty() {
        let list: Vec<(String, String)> = shell().aliases.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        for (k, v) in list {
            io::out("alias "); io::out(&k); io::out("='"); io::out(&v); io::out("'\n");
        }
        return 0;
    }
    let mut st = 0;
    for a in args {
        if let Some(eq) = a.find('=') {
            shell().aliases.insert(String::from(&a[..eq]), String::from(&a[eq + 1..]));
        } else {
            match shell().aliases.get(a.as_str()).cloned() {
                Some(v) => { io::out("alias "); io::out(a); io::out("='"); io::out(&v); io::out("'\n"); }
                None => { io::err("alias: "); io::err(a); io::err(": not found\n"); st = 1; }
            }
        }
    }
    st
}

fn unalias(args: &[String]) -> i32 {
    if args.is_empty() {
        io::err("unalias: usage: unalias [-a] name...\n");
        return 2;
    }
    if args[0] == "-a" {
        shell().aliases.clear();
        return 0;
    }
    let mut st = 0;
    for a in args {
        if shell().aliases.remove(a.as_str()).is_none() {
            io::err("unalias: "); io::err(a); io::err(": not found\n");
            st = 1;
        }
    }
    st
}

// ─── Scripts ────────────────────────────────────────────────────────────────

const MAX_SCRIPT_DEPTH: usize = 8;

fn run_text(text: &str, name: &str, args: Option<&[String]>) -> i32 {
    let sh = shell();
    if sh.script_depth >= MAX_SCRIPT_DEPTH {
        io::err("plum: scripts nested too deeply\n");
        return 1;
    }
    let node = match super::parse::parse(text) {
        Ok(n) => n,
        Err(e) => {
            io::err(name);
            io::err(": ");
            io::err(&e);
            io::err("\n");
            return 2;
        }
    };
    let sh = shell();
    sh.script_depth += 1;
    let saved_name = core::mem::replace(&mut sh.script_name, String::from(name));
    let saved_pos = match args {
        Some(a) => Some(core::mem::replace(&mut sh.positional, a.to_vec())),
        None => None,
    };
    let saved_loop = core::mem::replace(&mut sh.loop_depth, 0);
    let st = super::exec::run_node(&node);
    let sh = shell();
    sh.script_depth -= 1;
    sh.script_name = saved_name;
    if let Some(p) = saved_pos { sh.positional = p; }
    sh.loop_depth = saved_loop;
    let st = match sh.control {
        Control::Exit(code) => { sh.control = Control::None; code }
        Control::Return => { sh.control = Control::None; sh.last_exit }
        Control::Break(_) | Control::Continue(_) => { sh.control = Control::None; st }
        Control::None => st,
    };
    st
}

/// Run a script file in the current shell (`source`).
pub fn source_file(path: &str, args: &[String]) -> i32 {
    match crate::fs::read_file(path) {
        Some(data) => {
            let text = String::from_utf8_lossy(&data).into_owned();
            run_text(&text, path, if args.is_empty() { None } else { Some(args) })
        }
        None => {
            io::err("source: ");
            io::err(path);
            io::err(": No such file or directory\n");
            1
        }
    }
}

/// Run a script file with its own positional parameters (`bash file`, `./file`).
pub fn run_script(path: &str, args: &[String]) -> i32 {
    match crate::fs::read_file(path) {
        Some(data) => {
            let text = String::from_utf8_lossy(&data).into_owned();
            run_text(&text, path, Some(args))
        }
        None => {
            io::err("bash: ");
            io::err(path);
            io::err(": No such file or directory\n");
            127
        }
    }
}

fn bash(args: &[String]) -> i32 {
    if args.is_empty() {
        io::err("bash: usage: bash script.sh [args]  |  bash -c 'commands' [name [args]]\n");
        io::err("      (an interactive sub-shell is not available: the console already runs plum)\n");
        return 2;
    }
    if args[0] == "-c" {
        if args.len() < 2 {
            io::err("bash: -c: option requires an argument\n");
            return 2;
        }
        let name = args.get(2).cloned().unwrap_or_else(|| String::from("bash"));
        let rest: Vec<String> = if args.len() > 3 { args[3..].to_vec() } else { Vec::new() };
        return run_text(&args[1].clone(), &name, Some(&rest));
    }
    let path = super::resolve_path(&args[0]);
    run_script(&path, &args[1..])
}

// ─── type / which ───────────────────────────────────────────────────────────

fn type_cmd(which: &str, args: &[String]) -> i32 {
    if args.is_empty() {
        io::err(which);
        io::err(": missing argument\n");
        return 1;
    }
    let mut st = 0;
    for a in args {
        let n = a.as_str();
        let desc: Option<String> = if let Some(v) = shell().aliases.get(n) {
            Some(alloc::format!("{} is aliased to '{}'", n, v))
        } else if shell().functions.contains_key(n) {
            Some(alloc::format!("{} is a shell function", n))
        } else if BUILTINS.contains(&n) {
            Some(alloc::format!("{} is a shell builtin", n))
        } else if crate::userspace::axon::command_list().contains(&n) {
            Some(alloc::format!("{} is an axon coreutil (built into the kernel)", n))
        } else if super::CONSOLE_COMMANDS.contains(&n) {
            Some(alloc::format!("{} is a console command (only usable directly at the prompt)", n))
        } else {
            None
        };
        match desc {
            Some(d) => { io::out(&d); io::out("\n"); }
            None => {
                io::err(which); io::err(": "); io::err(n); io::err(": not found\n");
                st = 1;
            }
        }
    }
    st
}

// ─── test / [ / [[ ─────────────────────────────────────────────────────────

fn to_int(s: &str) -> Result<i64, String> {
    s.trim().parse::<i64>().map_err(|_| alloc::format!("{}: integer expression expected", s))
}

struct TestP<'a> {
    a: &'a [String],
    i: usize,
    ext: bool,
}

impl<'a> TestP<'a> {
    fn peek(&self) -> Option<&'a str> { let a: &'a [String] = self.a; a.get(self.i).map(|s| s.as_str()) }

    fn or(&mut self) -> Result<bool, String> {
        let mut v = self.and()?;
        while matches!(self.peek(), Some("-o") | Some("||")) {
            self.i += 1;
            let r = self.and()?;
            v = v || r;
        }
        Ok(v)
    }

    fn and(&mut self) -> Result<bool, String> {
        let mut v = self.not()?;
        while matches!(self.peek(), Some("-a") | Some("&&")) {
            self.i += 1;
            let r = self.not()?;
            v = v && r;
        }
        Ok(v)
    }

    fn not(&mut self) -> Result<bool, String> {
        if self.peek() == Some("!") && self.i + 1 < self.a.len() {
            self.i += 1;
            return Ok(!self.not()?);
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<bool, String> {
        let a = match self.peek() {
            Some(a) => a,
            None => return Err(String::from("argument expected")),
        };
        if a == "(" {
            self.i += 1;
            let v = self.or()?;
            if self.peek() != Some(")") { return Err(String::from("')' expected")); }
            self.i += 1;
            return Ok(v);
        }
        // binary?
        if let Some(op) = self.a.get(self.i + 1).map(|s| s.as_str()) {
            if is_binop(op) && self.i + 2 < self.a.len() {
                let l = self.a[self.i].clone();
                let r = self.a[self.i + 2].clone();
                self.i += 3;
                return binop(&l, op, &r, self.ext);
            }
        }
        // unary?
        if a.len() == 2 && a.starts_with('-') && self.i + 1 < self.a.len() {
            let op = a;
            let arg = self.a[self.i + 1].clone();
            if let Some(v) = unop(op, &arg)? {
                self.i += 2;
                return Ok(v);
            }
        }
        self.i += 1;
        Ok(!a.is_empty())
    }
}

fn is_binop(op: &str) -> bool {
    matches!(op, "=" | "==" | "!=" | "<" | ">" | "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge" | "=~" | "-nt" | "-ot" | "-ef")
}

fn binop(l: &str, op: &str, r: &str, ext: bool) -> Result<bool, String> {
    Ok(match op {
        "=" | "==" => if ext { super::glob_match(r, l) } else { l == r },
        "!=" => if ext { !super::glob_match(r, l) } else { l != r },
        "<" => l < r,
        ">" => l > r,
        "-eq" => to_int(l)? == to_int(r)?,
        "-ne" => to_int(l)? != to_int(r)?,
        "-lt" => to_int(l)? < to_int(r)?,
        "-le" => to_int(l)? <= to_int(r)?,
        "-gt" => to_int(l)? > to_int(r)?,
        "-ge" => to_int(l)? >= to_int(r)?,
        "=~" => match crate::userspace::axon::regex::Regex::new(r) {
            Ok(re) => re.is_match(l),
            Err(e) => return Err(alloc::format!("=~: {}", e)),
        },
        _ => return Err(alloc::format!("{}: not supported (the VFS has no timestamps or inodes)", op)),
    })
}

fn unop(op: &str, arg: &str) -> Result<Option<bool>, String> {
    let path = || super::resolve_path(arg);
    Ok(Some(match op {
        "-z" => arg.is_empty(),
        "-n" => !arg.is_empty(),
        "-e" | "-r" | "-w" | "-x" => crate::fs::exists(&path()) || path() == "/",
        "-f" => matches!(crate::fs::stat(&path()), Some(s) if s.node_type == crate::fs::NodeType::File),
        "-d" => path() == "/" || matches!(crate::fs::stat(&path()), Some(s) if s.node_type == crate::fs::NodeType::Directory),
        "-c" => matches!(crate::fs::stat(&path()), Some(s) if s.node_type == crate::fs::NodeType::CharDevice),
        "-s" => matches!(crate::fs::stat(&path()), Some(s) if s.size > 0),
        "-L" | "-h" | "-p" | "-S" | "-b" => false,
        _ => return Ok(None),
    }))
}

fn test_cmd(args: &[String], close: Option<&str>) -> i32 {
    let args: &[String] = match close {
        Some(c) => {
            if args.last().map(|s| s.as_str()) != Some(c) {
                io::err(if c == "]" { "[: missing `]'\n" } else { "[[: missing `]]'\n" });
                return 2;
            }
            &args[..args.len() - 1]
        }
        None => args,
    };
    if args.is_empty() { return 1; }
    let mut p = TestP { a: args, i: 0, ext: close == Some("]]") };
    match p.or() {
        Ok(v) => {
            if p.i < args.len() {
                io::err("test: too many arguments\n");
                return 2;
            }
            if v { 0 } else { 1 }
        }
        Err(e) => {
            io::err("test: ");
            io::err(&e);
            io::err("\n");
            2
        }
    }
}

// ─── read ───────────────────────────────────────────────────────────────────

fn read(args: &[String]) -> i32 {
    let mut i = 0;
    let mut prompt: Option<String> = None;
    while i < args.len() && args[i].starts_with('-') {
        match args[i].as_str() {
            "-r" => {}
            "-p" => {
                if i + 1 < args.len() { prompt = Some(args[i + 1].clone()); i += 1; }
            }
            o => {
                io::err("read: unsupported option "); io::err(o); io::err("\n");
                return 2;
            }
        }
        i += 1;
    }
    let names: Vec<String> = if i < args.len() { args[i..].to_vec() } else { alloc::vec![String::from("REPLY")] };
    let line = match io::read_stdin_line() {
        Some(Some(l)) => l,
        Some(None) => return 1, // EOF
        None => {
            if let Some(p) = &prompt { crate::arch::x86_64::framebuffer::draw_string(p, io::FG, io::BG); }
            match io::read_console_line() {
                Some(l) => l,
                None => return 130,
            }
        }
    };
    if names.len() == 1 {
        super::setenv(&names[0], line.trim());
        return 0;
    }
    let mut rest = line.trim_start();
    for (k, n) in names.iter().enumerate() {
        if k + 1 == names.len() {
            super::setenv(n, rest.trim_end());
        } else {
            let (w, r) = match rest.find(|c: char| c == ' ' || c == '\t') {
                Some(p) => (&rest[..p], rest[p..].trim_start()),
                None => (rest, ""),
            };
            super::setenv(n, w);
            rest = r;
        }
    }
    0
}

// ─── misc ───────────────────────────────────────────────────────────────────

fn save() -> i32 {
    if !crate::fs::disk_sync::is_dirty() {
        io::out("Filesystem is already clean - nothing to save.\n");
        return 0;
    }
    io::out("Syncing filesystem to disk...\n");
    if crate::fs::disk_sync::sync_filesystem() {
        io::out_c("[OK] ", io::FG_OK);
        io::out("Filesystem saved to disk.\n");
        0
    } else {
        io::err("save: failed to write the filesystem to disk (no storage device, or write error)\n");
        1
    }
}

fn write(args: &[String]) -> i32 {
    if args.len() < 2 {
        io::err("write: usage: write <file> <text...>\n");
        return 2;
    }
    let path = super::resolve_path(&args[0]);
    let mut text = args[1..].join(" ");
    text.push('\n');
    if crate::fs::write_file(&path, text.as_bytes()) {
        0
    } else {
        io::err("write: cannot write to '"); io::err(&args[0]); io::err("'\n");
        1
    }
}

fn plum_info() {
    io::out_c("plum", io::FG_OK);
    io::out(" - command shell for ospab.os\n\n");
    io::out("Language: a POSIX sh subset\n");
    io::out("  variables, $(...), `...`, $((...)), ((...)), let\n");
    io::out("  pipes |, && || ; !, redirections > >> < 2> 2>&1 &>\n");
    io::out("  if/elif/else, for, while/until, case, functions, local, return\n");
    io::out("  globbing * ? [..], ~, aliases, scripts (bash file.sh, ./file.sh, source)\n\n");
    io::out("Not supported: background jobs (&), here-documents (<<), arrays,\n");
    io::out("keyboard stdin for commands other than `read`.\n");
    io::out("Pipelines run one stage after another (there are no processes yet).\n\n");
    io::out("Startup file: /etc/plum/plumrc\n");
}
