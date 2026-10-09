/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

plum — command shell for ospab.os (AETERNA)

A POSIX-sh-like shell interpreter (see parse.rs for the grammar):
  - variables ($VAR, ${VAR:-x}, ${#VAR}, $1..$9, $#, $@, $?), export/unset
  - command substitution $(...) and `...`, arithmetic $((...)), ((...)), let
  - pipes, && || ; &, ! negation, redirections > >> < 2> 2>&1 &>
  - if/elif/else, for, while/until, case, functions, local, return,
    break/continue, { } groups, ( ) subshells (variables restored)
  - globbing (* ? [..]) against the VFS, ~ expansion, aliases
  - scripts: `bash file.sh`, `sh file.sh`, `./file.sh`, `source file`

Limitations (honest list):
  - everything runs inside the kernel; there are no processes, so `&` runs
    in the foreground and pipelines run stage by stage;
  - pipe data is text; keyboard stdin is only available to `read`;
  - commands built into the console (help, date, uname, ...) are not
    visible here unless the console registers a handler via
    `set_external_handler`.

Startup script: /etc/plum/plumrc
*/

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

pub mod arith;
pub mod bash;
pub mod builtins;
pub mod exec;
pub mod io;
pub mod parse;

pub use exec::glob_match;

// ─── Shell state ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Control {
    None,
    Break(usize),
    Continue(usize),
    Return,
    Exit(i32),
}

pub struct PlumShell {
    pub env: BTreeMap<String, String>,
    pub aliases: BTreeMap<String, String>,
    pub functions: BTreeMap<String, Rc<parse::Node>>,
    pub positional: Vec<String>,
    pub script_name: String,
    pub last_exit: i32,
    pub initialized: bool,
    pub control: Control,
    pub loop_depth: usize,
    pub func_depth: usize,
    pub nest: usize,
    pub subst_depth: usize,
    pub script_depth: usize,
    /// Saved values for `local` (one frame per active function call)
    pub locals: Vec<Vec<(String, Option<String>)>>,
    pub expanding_aliases: Vec<String>,
}

static mut SHELL: Option<PlumShell> = None;

/// Get the global shell instance, initializing defaults if needed.
pub fn shell() -> &'static mut PlumShell {
    unsafe {
        if SHELL.is_none() {
            let mut sh = PlumShell {
                env: BTreeMap::new(),
                aliases: BTreeMap::new(),
                functions: BTreeMap::new(),
                positional: Vec::new(),
                script_name: String::from("plum"),
                last_exit: 0,
                initialized: false,
                control: Control::None,
                loop_depth: 0,
                func_depth: 0,
                nest: 0,
                subst_depth: 0,
                script_depth: 0,
                locals: Vec::new(),
                expanding_aliases: Vec::new(),
            };
            for (k, v) in [
                ("HOME", "/home/root"),
                ("USER", "root"),
                ("SHELL", "/bin/plum"),
                ("PATH", "/bin:/sbin:/usr/bin"),
                ("PS1", "\\u@\\h:\\w# "),
                ("TERM", "aeterna-fb"),
                ("EDITOR", "grape"),
                ("HOSTNAME", "ospab"),
                ("OSTYPE", "ospab-os"),
                ("LANG", "en_US.UTF-8"),
                ("PWD", "/"),
            ] {
                sh.env.insert(String::from(k), String::from(v));
            }
            for (k, v) in [("ll", "ls -l"), ("la", "ls -a"), ("edit", "grape")] {
                sh.aliases.insert(String::from(k), String::from(v));
            }
            SHELL = Some(sh);
        }
        SHELL.as_mut().unwrap()
    }
}

// ─── Initialization ─────────────────────────────────────────────────────────

/// Initialize plum. Called once at boot. Runs /etc/plum/plumrc.
pub fn init() {
    let sh = shell();
    if sh.initialized { return; }
    sh.initialized = true;

    if !crate::fs::exists("/etc/plum") {
        crate::fs::mkdir("/etc/plum");
    }
    if !crate::fs::exists("/etc/plum/plumrc") {
        let default_rc = concat!(
            "# plum shell configuration (sourced at boot)\n",
            "alias ll='ls -l'\n",
            "alias la='ls -a'\n",
            "alias edit='grape'\n",
            "export EDITOR=grape\n",
            "export PAGER=cat\n",
        );
        crate::fs::write_file("/etc/plum/plumrc", default_rc.as_bytes());
    }
    let d = io::depth();
    io::push(io::Sink::Null, io::ErrSink::Inherit, io::Stdin::Console);
    builtins::source_file("/etc/plum/plumrc", &[]);
    io::pop();
    io::truncate(d);
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Run one line typed at the console (or any shell text).
/// Returns the exit status.
pub fn run_line(input: &str) -> i32 {
    let input = input.trim();
    if input.is_empty() { return shell().last_exit; }
    io::clear_interrupt();
    let depth = io::depth();
    let sh = shell();
    sh.control = Control::None;
    sh.nest = 0;
    let status = match parse::parse(input) {
        Ok(node) => exec::run_node(&node),
        Err(e) => {
            io::err("plum: ");
            io::err(&e);
            io::err("\n");
            2
        }
    };
    io::truncate(depth);
    let sh = shell();
    if let Control::Exit(_) = sh.control {
        io::note("plum: exit: this is the system console; there is no parent shell to return to\n");
    }
    sh.control = Control::None;
    if io::interrupted() {
        io::out_c("^C\n", io::FG_DIM);
        io::clear_interrupt();
    }
    set_exit_code(status);
    status
}

/// Compatibility entry used by the console: runs the line through plum.
/// Always returns None (plum prints its own "command not found").
pub fn preprocess(input: &str) -> Option<String> {
    run_line(input);
    None
}

/// Run an already-split command (used by xargs, env, etc.).
pub fn run_argv(argv: &[String]) -> i32 {
    exec::run_argv(argv)
}

/// The console can register a handler for commands it implements itself
/// (help, date, uname, ...).  The handler gets (command, args) and returns
/// true if it handled the command.  Output of such commands goes straight
/// to the screen and cannot be piped.
static mut EXTERNAL: Option<fn(&str, &str) -> bool> = None;

pub fn set_external_handler(f: fn(&str, &str) -> bool) {
    unsafe { EXTERNAL = Some(f); }
}

pub(crate) fn external_handler() -> Option<fn(&str, &str) -> bool> {
    unsafe { EXTERNAL }
}

/// Commands implemented inside the console (src/terminal.rs), not in plum.
pub const CONSOLE_COMMANDS: &[&str] = &[
    "help", "clear", "ver", "version", "uname", "whoami", "hostname", "date", "about",
    "meminfo", "free", "uptime", "dmesg", "lsmem", "ifconfig", "netdiag", "soundtest",
    "vol", "mute", "ntpdate", "sync", "dump_disk", "changelog", "reboot", "shutdown",
    "poweroff", "halt", "install", "history", "tutor", "doom", "bench", "ring3test", "testmode",
];

/// Get the value of an environment variable
pub fn getenv(name: &str) -> Option<&'static str> {
    let sh = shell();
    sh.env.get(name).map(|s| unsafe { &*(s.as_str() as *const str) })
}

pub fn setenv(name: &str, value: &str) {
    shell().env.insert(String::from(name), String::from(value));
}

pub fn unsetenv(name: &str) {
    shell().env.remove(name);
}

/// All environment variables as (name, value) pairs
pub fn get_env() -> Vec<(String, String)> {
    shell().env.iter().filter(|(k, _)| k.as_str() != "?").map(|(k, v)| (k.clone(), v.clone())).collect()
}

pub fn set_exit_code(code: i32) {
    let sh = shell();
    sh.last_exit = code;
    sh.env.insert(String::from("?"), io::fmt_i64(code as i64));
}

pub fn last_exit() -> i32 {
    shell().last_exit
}

/// Current working directory
pub fn cwd() -> &'static str {
    getenv("PWD").unwrap_or("/")
}

/// Resolve a user-supplied path to a normalized absolute path
/// (handles ~, ., .. and duplicate slashes).
pub fn resolve_path(path: &str) -> String {
    let path = path.trim();
    let mut full = String::new();
    if path == "~" || path.starts_with("~/") {
        full.push_str(getenv("HOME").unwrap_or("/"));
        full.push('/');
        full.push_str(&path[1..]);
    } else if path.starts_with('/') {
        full.push_str(path);
    } else {
        full.push_str(cwd());
        full.push('/');
        full.push_str(path);
    }
    let mut parts: Vec<&str> = Vec::new();
    for comp in full.split('/') {
        match comp {
            "" | "." => {}
            ".." => { parts.pop(); }
            c => parts.push(c),
        }
    }
    let mut out = String::new();
    for p in &parts {
        out.push('/');
        out.push_str(p);
    }
    if out.is_empty() { out.push('/'); }
    out
}
