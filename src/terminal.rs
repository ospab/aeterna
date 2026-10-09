/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Interactive console for ospab.os (AETERNA kernel), drawn on the framebuffer.

It runs in ring 0 as part of the kernel, like every other tool here for now.
  - prompt root@<hostname>:<path>#
  - line editor: cursor keys, Home/End, Delete, Ctrl+A/E/U/K/W, Tab completion
  - command history (Up/Down), `history`
  - "--More--" pager for long output
Lines are run by the plum shell (pipes, ;, &&, variables, aliases, scripts).
Commands implemented here (help, date, free, ...) are registered with plum
as console commands; a plain line like `free` is run directly.
*/
use core::arch::asm;
use alloc::string::String;
use alloc::vec::Vec;
use ospab_os::arch::x86_64::framebuffer;
use ospab_os::arch::x86_64::keyboard;
use ospab_os::klog;
use ospab_os::{fs, acpi, axon};

extern crate alloc;

#[path = "testmode.rs"]
mod testmode;

/// Commands implemented in this file.
const TERMINAL_COMMANDS: &[&str] = &[
    "help", "clear", "version", "ver", "uname", "whoami", "hostname",
    "date", "about", "free", "meminfo", "lsmem", "uptime", "dmesg",
    "ifconfig", "ntpdate", "netdiag",
    "soundtest", "vol", "mute", "sync", "dump_disk", "changelog",
    "reboot", "shutdown", "poweroff", "halt", "install", "history", "tutor",
    "grape", "tomato", "seed", "doom", "bench", "ring3test", "testmode",
];

/// Shell builtins and file commands, for Tab completion only.
const SHELL_COMMANDS: &[&str] = &[
    "ls", "cd", "pwd", "cat", "mkdir", "touch", "rm", "echo", "write", "save",
    "export", "set", "unset", "env", "alias", "unalias", "source", "bash", "sh",
    "type", "which", "test", "read", "exit", "plum", "ip",
];

/// Commands that draw full-screen UIs, wait for keys or run until stopped:
/// the pager is not used for them.
const NO_PAGER: &[&str] = &[
    "grape", "doom", "top", "ping", "install", "tomato", "yes", "clear",
    "bench", "reboot", "shutdown", "poweroff", "halt", "traceroute", "seed",
    "curl", "soundtest", "ntpdate", "netdiag", "verify_audio", "verify_net", "read",
    "testmode",
];

/// PIT rate behind `idt::timer_ticks()`.
const TIMER_HZ: u64 = 100;

// ─── Colors (0x00RRGGBB; the framebuffer converts to its native layout) ───
const FG: u32         = 0x00FFFFFF;   // Default text
const FG_DIM: u32     = 0x00A0A0A0;   // Secondary info
const FG_ERR: u32     = 0x00FF5555;   // Errors
const FG_WARN: u32    = 0x00FFCC44;   // Warnings, section headings
const FG_OK: u32      = 0x0055DD55;   // Success
const FG_PROMPT: u32  = 0x0055DD55;   // Prompt user@host
const FG_PATH: u32    = 0x005599FF;   // Prompt path
const FG_HL: u32      = 0x0055CCFF;   // Highlighted names (commands, keys)
const BG: u32         = 0x00000000;

// ─── Input buffer ───
const INPUT_BUFFER_SIZE: usize = 256;
static mut INPUT_BUFFER: [u8; INPUT_BUFFER_SIZE] = [0; INPUT_BUFFER_SIZE];
static mut INPUT_LEN: usize = 0;
static mut INPUT_CURSOR: usize = 0;

// ─── Command history ───
const HISTORY_SIZE: usize = 64;
static mut HISTORY: [[u8; INPUT_BUFFER_SIZE]; HISTORY_SIZE] = [[0; INPUT_BUFFER_SIZE]; HISTORY_SIZE];
static mut HISTORY_LENS: [usize; HISTORY_SIZE] = [0; HISTORY_SIZE];
static mut HISTORY_COUNT: usize = 0;
static mut HISTORY_POS: usize = 0;
static mut HISTORY_BROWSING: bool = false;

// ─── Prompt position tracking ───
static mut PROMPT_END_X: u64 = 0;
static mut PROMPT_END_Y: u64 = 0;
/// framebuffer::scroll_count() when PROMPT_END_Y was last valid.
static mut PROMPT_SCROLLS: u64 = 0;

fn cwd_str() -> &'static str {
    ospab_os::plum::cwd()
}

/// Resolve a user-supplied path to an absolute path (plum's PWD rules).
fn resolve_path(path: &str) -> String {
    ospab_os::plum::resolve_path(path)
}

/// Hostname from /etc/hostname, or "ospab".
fn hostname() -> String {
    if let Some(data) = fs::read_file("/etc/hostname") {
        if let Ok(text) = core::str::from_utf8(&data) {
            let t = text.trim();
            if !t.is_empty() {
                return String::from(t);
            }
        }
    }
    String::from("ospab")
}

// ══════════════════════════════════════════════════════════════
// Main loop
// ══════════════════════════════════════════════════════════════

/// Main terminal loop — never returns
pub fn run() -> ! {
    keyboard::init();
    ospab_os::plum::set_external_handler(console_handler);

    framebuffer::clear(BG);
    framebuffer::set_cursor_pos(0, 0);
    print_banner();

    klog::record(klog::EventSource::Terminal, "Terminal started");

    loop {
        draw_prompt();
        let cmd = read_line();
        if !cmd.is_empty() {
            history_push(cmd);
            // Copy out of the static input buffer: commands may re-enter the line editor.
            let owned = String::from(cmd);
            execute_command(&owned);
        }
    }
}

fn print_banner() {
    framebuffer::draw_string(crate::version::OS_VERSION, FG_OK, BG);
    dim_print("  AETERNA kernel ");
    dim_print(crate::version::VERSION_STR);
    dim_print(" (");
    dim_print(crate::version::ARCH);
    dim_print(")\n");
    dim_print("Development build: the shell and all tools run inside the kernel (ring 0).\n");
    puts("Type ");
    hl_print("help");
    puts(" for commands, ");
    hl_print("tutor");
    puts(" for a short tour.\n\n");
}

// ══════════════════════════════════════════════════════════════
// Prompt
// ══════════════════════════════════════════════════════════════

fn draw_prompt() {
    // Start the prompt on a fresh line if a command left the cursor mid-line.
    let (x, _) = framebuffer::cursor_pos();
    if x != 0 {
        puts("\n");
    }
    let host = hostname();
    framebuffer::draw_string("root@", FG_PROMPT, BG);
    framebuffer::draw_string(&host, FG_PROMPT, BG);
    framebuffer::draw_string(":", FG, BG);
    let pwd = cwd_str();
    let home = ospab_os::plum::getenv("HOME").unwrap_or("");
    if !home.is_empty() && home != "/" && pwd == home {
        framebuffer::draw_string("~", FG_PATH, BG);
    } else if !home.is_empty() && home != "/" && pwd.starts_with(home)
        && pwd.as_bytes().get(home.len()) == Some(&b'/')
    {
        framebuffer::draw_string("~", FG_PATH, BG);
        framebuffer::draw_string(&pwd[home.len()..], FG_PATH, BG);
    } else {
        framebuffer::draw_string(pwd, FG_PATH, BG);
    }
    framebuffer::draw_string("# ", FG, BG);
    unsafe {
        let (x, y) = framebuffer::cursor_pos();
        PROMPT_END_X = x;
        PROMPT_END_Y = y;
        PROMPT_SCROLLS = framebuffer::scroll_count();
    }
}

/// If the screen scrolled since the prompt was drawn, move the remembered
/// prompt position up by the same number of text rows.
fn track_scroll() {
    unsafe {
        let now = framebuffer::scroll_count();
        let delta = now.wrapping_sub(PROMPT_SCROLLS);
        if delta > 0 {
            PROMPT_END_Y = PROMPT_END_Y.saturating_sub(delta * framebuffer::CHAR_HEIGHT);
            PROMPT_SCROLLS = now;
        }
    }
}

// ══════════════════════════════════════════════════════════════
// Command history
// ══════════════════════════════════════════════════════════════

fn history_push(cmd: &str) {
    let bytes = cmd.as_bytes();
    if bytes.is_empty() { return; }
    unsafe {
        // Skip an exact repeat of the previous command.
        if HISTORY_COUNT > 0 {
            let prev = (HISTORY_COUNT - 1) % HISTORY_SIZE;
            if &HISTORY[prev][..HISTORY_LENS[prev]] == bytes {
                HISTORY_POS = HISTORY_COUNT;
                HISTORY_BROWSING = false;
                return;
            }
        }
        let slot = HISTORY_COUNT % HISTORY_SIZE;
        let len = bytes.len().min(INPUT_BUFFER_SIZE);
        HISTORY[slot][..len].copy_from_slice(&bytes[..len]);
        HISTORY_LENS[slot] = len;
        HISTORY_COUNT += 1;
        HISTORY_POS = HISTORY_COUNT;
        HISTORY_BROWSING = false;
    }
}

fn history_up() -> Option<&'static str> {
    unsafe {
        if HISTORY_COUNT == 0 { return None; }
        if !HISTORY_BROWSING {
            HISTORY_POS = HISTORY_COUNT;
            HISTORY_BROWSING = true;
        }
        if HISTORY_POS == 0 { return None; }
        let oldest = if HISTORY_COUNT > HISTORY_SIZE { HISTORY_COUNT - HISTORY_SIZE } else { 0 };
        if HISTORY_POS <= oldest { return None; }
        HISTORY_POS -= 1;
        let slot = HISTORY_POS % HISTORY_SIZE;
        let len = HISTORY_LENS[slot];
        Some(core::str::from_utf8_unchecked(&HISTORY[slot][..len]))
    }
}

fn history_down() -> Option<&'static str> {
    unsafe {
        if !HISTORY_BROWSING { return None; }
        if HISTORY_POS >= HISTORY_COUNT { return None; }
        HISTORY_POS += 1;
        if HISTORY_POS >= HISTORY_COUNT {
            HISTORY_BROWSING = false;
            return Some("");
        }
        let slot = HISTORY_POS % HISTORY_SIZE;
        let len = HISTORY_LENS[slot];
        Some(core::str::from_utf8_unchecked(&HISTORY[slot][..len]))
    }
}

fn replace_input_line(new_text: &str) {
    unsafe {
        let old_len = INPUT_LEN;
        let bytes = new_text.as_bytes();
        let len = bytes.len().min(INPUT_BUFFER_SIZE - 1);
        INPUT_BUFFER[..len].copy_from_slice(&bytes[..len]);
        INPUT_LEN = len;
        INPUT_CURSOR = len;
        redraw_input_from(0, old_len);
    }
}

// ══════════════════════════════════════════════════════════════
// Line editor helpers
// ══════════════════════════════════════════════════════════════

/// Screen pixel position for a given input buffer index.
fn input_screen_pos(idx: usize) -> (u64, u64) {
    unsafe {
        let cw = framebuffer::CHAR_WIDTH;
        let ch = framebuffer::CHAR_HEIGHT;
        let cols = framebuffer::screen_cols().max(1);
        let prompt_col = PROMPT_END_X / cw;
        let total_col = prompt_col + idx as u64;
        let row_offset = total_col / cols;
        let col = total_col % cols;
        (col * cw, PROMPT_END_Y + row_offset * ch)
    }
}

/// Redraw the input from `from` to the end, blank out what is left of an
/// older, longer line (`old_len`), then put the cursor at INPUT_CURSOR.
fn redraw_input_from(from: usize, old_len: usize) {
    unsafe {
        let (x, y) = input_screen_pos(from);
        framebuffer::set_cursor_pos(x, y);
        for i in from..INPUT_LEN {
            framebuffer::draw_char(INPUT_BUFFER[i] as char, FG, BG);
            track_scroll();
        }
        let tail = old_len.max(INPUT_LEN + 1) - INPUT_LEN;
        for _ in 0..tail {
            framebuffer::draw_char(' ', FG, BG);
            track_scroll();
        }
        let (cx, cy) = input_screen_pos(INPUT_CURSOR);
        framebuffer::set_cursor_pos(cx, cy);
    }
}

/// Redraw prompt and the whole input line on a new line (after completion lists).
fn redraw_line() {
    draw_prompt();
    unsafe {
        for i in 0..INPUT_LEN {
            framebuffer::draw_char(INPUT_BUFFER[i] as char, FG, BG);
            track_scroll();
        }
        let (cx, cy) = input_screen_pos(INPUT_CURSOR);
        framebuffer::set_cursor_pos(cx, cy);
    }
}

/// Draw a block cursor (inverted colors) at INPUT_CURSOR.
fn draw_input_cursor() {
    unsafe {
        let (x, y) = input_screen_pos(INPUT_CURSOR);
        let c = if INPUT_CURSOR < INPUT_LEN { INPUT_BUFFER[INPUT_CURSOR] as char } else { ' ' };
        framebuffer::draw_char_at(x, y, c, BG, FG);
    }
}

/// Erase the block cursor (restore normal rendering).
fn erase_input_cursor() {
    unsafe {
        let (x, y) = input_screen_pos(INPUT_CURSOR);
        let c = if INPUT_CURSOR < INPUT_LEN { INPUT_BUFFER[INPUT_CURSOR] as char } else { ' ' };
        framebuffer::draw_char_at(x, y, c, FG, BG);
    }
}

/// Delete `count` bytes starting at `at` from the input buffer.
unsafe fn input_delete(at: usize, count: usize) {
    if count == 0 || at >= INPUT_LEN { return; }
    let count = count.min(INPUT_LEN - at);
    for i in at..INPUT_LEN - count {
        INPUT_BUFFER[i] = INPUT_BUFFER[i + count];
    }
    INPUT_LEN -= count;
}

/// Insert bytes at the cursor. Returns how many were inserted.
unsafe fn input_insert(bytes: &[u8]) -> usize {
    let need = bytes.len();
    if need == 0 || INPUT_LEN + need >= INPUT_BUFFER_SIZE { return 0; }
    for i in (INPUT_CURSOR..INPUT_LEN).rev() {
        INPUT_BUFFER[i + need] = INPUT_BUFFER[i];
    }
    INPUT_BUFFER[INPUT_CURSOR..INPUT_CURSOR + need].copy_from_slice(bytes);
    INPUT_CURSOR += need;
    INPUT_LEN += need;
    need
}

// ══════════════════════════════════════════════════════════════
// Tab completion
// ══════════════════════════════════════════════════════════════

fn current_input_prefix() -> &'static str {
    unsafe { core::str::from_utf8_unchecked(&INPUT_BUFFER[..INPUT_CURSOR]) }
}

/// Complete the token before the cursor. Returns number of bytes inserted.
fn try_complete() -> usize {
    let prefix = current_input_prefix();
    let token_start = prefix.rfind(' ').map(|p| p + 1).unwrap_or(0);
    let token = &prefix[token_start..];
    let is_first_token = prefix[..token_start].trim().is_empty();

    let (dir, base) = if let Some(pos) = token.rfind('/') {
        let dir_part = &token[..pos];
        let abs = if dir_part.is_empty() { String::from("/") } else { resolve_path(dir_part) };
        (abs, &token[pos + 1..])
    } else {
        (String::from(cwd_str()), token)
    };

    let mut matches: Vec<String> = Vec::new();
    if is_first_token && !token.contains('/') {
        for &b in TERMINAL_COMMANDS.iter().chain(SHELL_COMMANDS.iter()).chain(axon::command_list().iter()) {
            if b.starts_with(token) { matches.push(String::from(b)); }
        }
    } else if let Some(entries) = fs::readdir(&dir) {
        for e in entries {
            if e.name.starts_with(base) {
                let mut name = e.name.clone();
                if e.node_type == fs::NodeType::Directory { name.push('/'); }
                matches.push(name);
            }
        }
    }
    matches.sort();
    matches.dedup();

    if matches.is_empty() {
        return 0;
    }

    // Longest common prefix of all matches.
    let first = matches[0].as_bytes();
    let mut common = first.len();
    for m in &matches[1..] {
        let mb = m.as_bytes();
        let mut n = 0;
        while n < common && n < mb.len() && mb[n] == first[n] { n += 1; }
        common = n;
    }

    if common > base.len() {
        let suffix = &matches[0][base.len()..common];
        let mut ins = String::from(suffix);
        if matches.len() == 1 && !suffix.ends_with('/') {
            ins.push(' ');
        }
        return unsafe { input_insert(ins.as_bytes()) };
    }

    if matches.len() > 1 {
        // Show candidates in columns, then redraw the line below them.
        unsafe {
            let (ex, ey) = input_screen_pos(INPUT_LEN);
            framebuffer::set_cursor_pos(ex, ey);
        }
        puts("\n");
        let width = matches.iter().map(|m| m.len()).max().unwrap_or(1) + 2;
        let cols = (framebuffer::screen_cols() as usize / width).max(1);
        for (i, m) in matches.iter().enumerate() {
            if m.ends_with('/') {
                framebuffer::draw_string(m, FG_PATH, BG);
            } else {
                puts(m);
            }
            if (i + 1) % cols == 0 || i + 1 == matches.len() {
                puts("\n");
            } else {
                pad(m.len(), width);
            }
        }
        redraw_line();
    }
    0
}

// ══════════════════════════════════════════════════════════════
// Input line editor
// ══════════════════════════════════════════════════════════════

fn read_line() -> &'static str {
    unsafe {
        INPUT_LEN = 0;
        INPUT_CURSOR = 0;
        HISTORY_BROWSING = false;

        draw_input_cursor();

        loop {
            let ch = match keyboard::try_read_key() {
                Some(c) => c,
                None => {
                    // No key — sleep until the next interrupt, then let a
                    // deferred disk write-back run if one is due.
                    asm!("hlt");
                    if ospab_os::drivers::disk_count() > 0 {
                        fs::disk_sync::deferred_tick();
                    }
                    continue;
                }
            };

            erase_input_cursor();

            match ch {
                '\n' => {
                    let (ex, ey) = input_screen_pos(INPUT_LEN);
                    framebuffer::set_cursor_pos(ex, ey);
                    framebuffer::draw_char('\n', FG, BG);
                    INPUT_BUFFER[INPUT_LEN] = 0;
                    return core::str::from_utf8_unchecked(&INPUT_BUFFER[..INPUT_LEN]);
                }

                '\x08' => {
                    // Backspace: delete char before cursor
                    if INPUT_CURSOR > 0 {
                        let old = INPUT_LEN;
                        INPUT_CURSOR -= 1;
                        input_delete(INPUT_CURSOR, 1);
                        redraw_input_from(INPUT_CURSOR, old);
                    }
                }

                k if k == keyboard::KEY_DELETE || k == '\x04' => {
                    // Delete / Ctrl+D: remove char at cursor
                    if INPUT_CURSOR < INPUT_LEN {
                        let old = INPUT_LEN;
                        input_delete(INPUT_CURSOR, 1);
                        redraw_input_from(INPUT_CURSOR, old);
                    }
                }

                k if k == keyboard::KEY_LEFT || k == '\x02' => {
                    if INPUT_CURSOR > 0 { INPUT_CURSOR -= 1; }
                }

                k if k == keyboard::KEY_RIGHT || k == '\x06' => {
                    if INPUT_CURSOR < INPUT_LEN { INPUT_CURSOR += 1; }
                }

                k if k == keyboard::KEY_HOME || k == '\x01' => {
                    INPUT_CURSOR = 0;
                }

                k if k == keyboard::KEY_END || k == '\x05' => {
                    INPUT_CURSOR = INPUT_LEN;
                }

                k if k == keyboard::KEY_UP || k == '\x10' => {
                    if let Some(text) = history_up() {
                        replace_input_line(text);
                    }
                }

                k if k == keyboard::KEY_DOWN || k == '\x0E' => {
                    if let Some(text) = history_down() {
                        replace_input_line(text);
                    }
                }

                '\x15' => {
                    // Ctrl+U: delete from line start to cursor
                    let old = INPUT_LEN;
                    let n = INPUT_CURSOR;
                    INPUT_CURSOR = 0;
                    input_delete(0, n);
                    redraw_input_from(0, old);
                }

                '\x0B' => {
                    // Ctrl+K: delete from cursor to end of line
                    let old = INPUT_LEN;
                    INPUT_LEN = INPUT_CURSOR;
                    redraw_input_from(INPUT_CURSOR, old);
                }

                '\x17' => {
                    // Ctrl+W: delete the word before the cursor
                    let old = INPUT_LEN;
                    let mut start = INPUT_CURSOR;
                    while start > 0 && INPUT_BUFFER[start - 1] == b' ' { start -= 1; }
                    while start > 0 && INPUT_BUFFER[start - 1] != b' ' { start -= 1; }
                    let n = INPUT_CURSOR - start;
                    INPUT_CURSOR = start;
                    input_delete(start, n);
                    redraw_input_from(start, old);
                }

                '\x03' => {
                    // Ctrl+C: cancel input
                    let (ex, ey) = input_screen_pos(INPUT_LEN);
                    framebuffer::set_cursor_pos(ex, ey);
                    framebuffer::draw_string("^C", FG_DIM, BG);
                    framebuffer::draw_char('\n', FG, BG);
                    INPUT_LEN = 0;
                    INPUT_CURSOR = 0;
                    return core::str::from_utf8_unchecked(&INPUT_BUFFER[..0]);
                }

                '\x0C' => {
                    // Ctrl+L: clear screen, keep what was typed
                    framebuffer::clear(BG);
                    framebuffer::set_cursor_pos(0, 0);
                    redraw_line();
                }

                '\t' => {
                    let start = INPUT_CURSOR;
                    let inserted = try_complete();
                    if inserted > 0 {
                        redraw_input_from(start, INPUT_LEN);
                    }
                }

                c if c.is_ascii() && (c as u8) >= 0x20 && (c as u8) < 0x7F => {
                    let at_end = INPUT_CURSOR == INPUT_LEN;
                    if input_insert(&[c as u8]) == 1 {
                        if at_end {
                            let (x, y) = input_screen_pos(INPUT_CURSOR - 1);
                            framebuffer::set_cursor_pos(x, y);
                            framebuffer::draw_char(c, FG, BG);
                        } else {
                            redraw_input_from(INPUT_CURSOR - 1, INPUT_LEN);
                        }
                    }
                }

                _ => {}
            }

            track_scroll();
            let (cx, cy) = input_screen_pos(INPUT_CURSOR);
            framebuffer::set_cursor_pos(cx, cy);
            draw_input_cursor();
        }
    }
}

// ══════════════════════════════════════════════════════════════
// Pager
// ══════════════════════════════════════════════════════════════

/// Wait for one key, sleeping between interrupts.
fn wait_key() -> char {
    loop {
        if let Some(k) = keyboard::try_read_key() {
            return k;
        }
        unsafe { asm!("hlt"); }
    }
}

/// Called by the framebuffer after each screenful of output.
fn pager_hook() -> bool {
    let (_, y) = framebuffer::cursor_pos();
    framebuffer::set_cursor_pos(0, y);
    framebuffer::draw_string(" --More-- ", BG, FG_DIM);
    framebuffer::draw_string("  Space/Enter: next page   q: stop", FG_DIM, BG);
    let k = wait_key();
    framebuffer::set_cursor_pos(0, y);
    framebuffer::clear_to_eol(BG);
    match k {
        'q' | 'Q' | '\x1B' | '\x03' => false,
        _ => true,
    }
}

// ══════════════════════════════════════════════════════════════
// Command parsing and dispatch
// ══════════════════════════════════════════════════════════════

/// Characters that need the plum parser (pipes, chaining, redirection,
/// variables, quoting, globs, substitution).
fn needs_shell(line: &str) -> bool {
    line.bytes().any(|b| matches!(b, b'|' | b';' | b'&' | b'<' | b'>' | b'$' | b'`'
        | b'(' | b')' | b'\'' | b'"' | b'*' | b'?' | b'[' | b'~' | b'='))
}

fn split_first_word(s: &str) -> (&str, &str) {
    let s = s.trim();
    match s.find(|c: char| c == ' ' || c == '\t') {
        Some(pos) => (&s[..pos], s[pos + 1..].trim()),
        None => (s, ""),
    }
}

/// Run one input line. Simple console commands run directly; everything else
/// (and every line with shell syntax) goes to the plum shell, which calls
/// back into `console_handler` for console commands it meets.
fn execute_command(line: &str) {
    let line = line.trim();
    if line.is_empty() { return; }

    let (command, args) = split_first_word(line);
    let paged = !NO_PAGER.contains(&command);
    if paged {
        framebuffer::pager_begin(pager_hook);
    }

    let direct = !needs_shell(line) && is_console_command(command);
    if direct {
        dispatch_console(command, args);
    } else {
        ospab_os::plum::run_line(line);
    }

    if paged {
        framebuffer::pager_end();
    }
}

/// Handler registered with plum for console commands used inside shell lines.
fn console_handler(command: &str, args: &str) -> bool {
    dispatch_console(command, args)
}

fn is_console_command(command: &str) -> bool {
    TERMINAL_COMMANDS.contains(&command)
}

/// Run a command implemented in this file. Returns false if `command` is not one.
fn dispatch_console(command: &str, args: &str) -> bool {
    match command {
        "help"    => cmd_help(args),
        "clear"   => cmd_clear(),
        "ver" | "version" => cmd_version(),
        "uname"   => cmd_uname(args),
        "whoami"  => puts("root\n"),
        "hostname"=> cmd_hostname(args),
        "date"    => cmd_date(args),
        "about"   => cmd_about(),
        "free"    => cmd_free(),
        "meminfo" => cmd_cat_proc("/proc/meminfo"),
        "uptime"  => cmd_uptime(),
        "dmesg"   => cmd_dmesg(),
        "lsmem"   => cmd_lsmem(),
        "ifconfig"=> cmd_ifconfig(),
        "netdiag" => {
            puts("Running network diagnostics (full report on serial COM1)...\n");
            ospab_os::net::diag::run_full_diagnostic();
            ospab_os::net::diag::run_screen_summary();
        }
        "soundtest" => cmd_soundtest(),
        "vol"     => cmd_vol(args),
        "mute"    => cmd_mute(),
        "ntpdate" => cmd_ntpdate(args),
        "sync"    => cmd_sync(),
        "dump_disk" => cmd_dump_disk(args),
        "changelog" => cmd_changelog(),
        "reboot"  => cmd_reboot(),
        "shutdown" | "poweroff" | "halt" => cmd_shutdown(),
        "install" => crate::installer::run(),
        "history" => cmd_history(),
        "tutor"   => cmd_tutor(args),
        "grape"   => cmd_grape(args),
        "tomato"  => cmd_tomato(args),
        "seed"    => ospab_os::userspace::seed::run(args),
        "doom"    => cmd_doom(),
        "bench"   => ospab_os::bench::run(args),
        "ring3test" => cmd_ring3test(),
        "testmode" => testmode::run(args),
        _ => return false,
    }
    true
}

// ══════════════════════════════════════════════════════════════
// help
// ══════════════════════════════════════════════════════════════

struct HelpSection {
    title: &'static str,
    cmds: &'static [(&'static str, &'static str)],
}

const HELP: &[HelpSection] = &[
    HelpSection { title: "Shell", cmds: &[
        ("help [cmd]",       "this list, or details for one command"),
        ("tutor [topic]",    "short guided tour"),
        ("clear",            "clear the screen (Ctrl+L)"),
        ("history",          "previous commands (Up/Down)"),
        ("echo [text]",      "print text; > file, >> file"),
        ("a | b, a; b",      "pipes, sequences, && and ||"),
        ("export / unset",   "set / remove a variable"),
        ("env / set",        "show variables"),
        ("alias / unalias",  "command aliases"),
        ("type <cmd>",       "what kind of command it is"),
        ("bash <file.sh>",   "run a script (also: source)"),
        ("plum",             "shell info"),
    ]},
    HelpSection { title: "Files", cmds: &[
        ("ls [-l] [path]",   "list a directory"),
        ("cd / pwd",         "change / print directory"),
        ("cat <file>",       "print a file"),
        ("mkdir / touch",    "create directory / file"),
        ("rm <path>",        "remove file or empty dir"),
        ("cp / mv",          "copy / move"),
        ("write <f> <text>", "write text to a file"),
        ("find / tree",      "find DIR -name X; directory tree"),
        ("stat / du / df",   "file info, usage"),
        ("sync (save)",      "write RAM filesystem to disk now"),
    ]},
    HelpSection { title: "Text", cmds: &[
        ("grep <pat> <f>",   "search lines"),
        ("head / tail",      "first / last lines"),
        ("wc / nl",          "count / number lines"),
        ("sort / uniq",      "sort, drop duplicates"),
        ("cut / awk",        "fields"),
        ("diff <a> <b>",     "compare files"),
        ("xxd <file>",       "hex dump"),
        ("seq / printf",     "numbers, formatted output"),
        ("rev / tee / yes",  "misc text tools"),
    ]},
    HelpSection { title: "System", cmds: &[
        ("version / uname",  "kernel version"),
        ("about",            "what this system is"),
        ("uptime / date",    "time since boot, clock"),
        ("hostname [name]",  "show or set host name"),
        ("free / meminfo",   "memory usage"),
        ("lsmem",            "physical memory regions"),
        ("ps / top / kill",  "scheduler tasks"),
        ("dmesg",            "kernel event log"),
        ("lspci",            "PCI devices"),
        ("changelog",        "release notes"),
    ]},
    HelpSection { title: "Storage", cmds: &[
        ("lsblk",            "disks"),
        ("fdisk -l",         "partition tables"),
        ("mkfs / mount",     "AeternaFS format / mount"),
        ("dump_disk",        "hex dump of the persistence sector"),
        ("install",          "install to disk (GPT + FAT32)"),
    ]},
    HelpSection { title: "Network", cmds: &[
        ("ifconfig / ip",    "interface, address, routes"),
        ("ping <host>",      "ICMP echo (-c -i -s -W)"),
        ("nslookup <name>",  "DNS lookup"),
        ("curl <url>",       "HTTP/HTTPS GET"),
        ("traceroute <h>",   "route to a host"),
        ("netstat",          "sockets"),
        ("ntpdate [srv]",    "set clock via SNTP"),
        ("netdiag",          "NIC diagnostics"),
    ]},
    HelpSection { title: "Apps", cmds: &[
        ("grape [file]",     "text editor"),
        ("tomato",           "package manager"),
        ("seed",             "service list"),
        ("doom",             "DOOM (if the WAD was bundled)"),
    ]},
    HelpSection { title: "Hardware & tests", cmds: &[
        ("soundtest",        "audio driver check + 440 Hz tone"),
        ("vol [n] / mute",   "volume"),
        ("bench [n]",        "TSC timing/jitter benchmark"),
        ("verify_mem",       "heap allocation test"),
        ("verify_sched",     "timer/scheduler test"),
        ("verify_net",       "network self-test"),
        ("verify_audio",     "audio self-test"),
        ("ring3test",        "start one ring-3 test task"),
        ("testmode [item]",  "preview panic/fault screens, self-tests"),
        ("reboot / shutdown","power"),
    ]},
];

const HELP_NAME_W: usize = 19;

fn cmd_help(args: &str) {
    let topic = args.trim();
    if !topic.is_empty() {
        help_detail(topic);
        return;
    }

    let cols = framebuffer::screen_cols() as usize;
    let two_col = cols >= 116;
    let col_w = if two_col { cols / 2 } else { cols };
    let desc_w = col_w.saturating_sub(HELP_NAME_W + 3).max(10);

    framebuffer::draw_string("Commands", FG_OK, BG);
    dim_print("  (help <cmd> for details; long output pauses at --More--)\n");

    let mut i = 0;
    while i < HELP.len() {
        if two_col && i + 1 < HELP.len() {
            let (a, b) = (&HELP[i], &HELP[i + 1]);
            help_heading(a.title, col_w);
            help_heading(b.title, col_w);
            puts("\n");
            let rows = a.cmds.len().max(b.cmds.len());
            for r in 0..rows {
                let used = match a.cmds.get(r) {
                    Some(&(n, d)) => help_cell(n, d, desc_w),
                    None => 0,
                };
                pad(used, col_w);
                if let Some(&(n, d)) = b.cmds.get(r) {
                    help_cell(n, d, desc_w);
                }
                puts("\n");
            }
            i += 2;
        } else {
            help_heading(HELP[i].title, 0);
            puts("\n");
            for &(n, d) in HELP[i].cmds {
                help_cell(n, d, desc_w);
                puts("\n");
            }
            i += 1;
        }
    }
    dim_print("Keys: Tab completes, Up/Down history, Ctrl+A/E start/end, Ctrl+U/K/W delete, Ctrl+C cancel.\n");
}

/// Section heading, padded to `width` (0 = no padding).
fn help_heading(title: &str, width: usize) {
    framebuffer::draw_string("\u{2500}\u{2500} ", FG_DIM, BG);
    framebuffer::draw_string(title, FG_WARN, BG);
    puts(" ");
    let used = 4 + title.chars().count();
    let line = if width > 0 { width.saturating_sub(used + 2) } else { 20usize.saturating_sub(title.len()) };
    for _ in 0..line {
        framebuffer::draw_string("\u{2500}", FG_DIM, BG);
    }
    if width > 0 {
        puts("  ");
    }
}

/// One "  name   description" cell. Returns the number of columns used.
fn help_cell(name: &str, desc: &str, desc_w: usize) -> usize {
    puts("  ");
    hl_print(name);
    pad(name.len(), HELP_NAME_W);
    let d: &str = if desc.len() > desc_w { &desc[..desc_w] } else { desc };
    dim_print(d);
    2 + name.len().max(HELP_NAME_W) + d.len()
}

fn help_line(usage: &str, lines: &[&str]) {
    hl_print(usage);
    puts("\n");
    for l in lines {
        dim_print("  ");
        dim_print(l);
        puts("\n");
    }
}

fn help_detail(topic: &str) {
    match topic {
        "ping" => help_line("ping [-c count] [-i sec] [-s bytes] [-W sec] <host>", &[
            "Send ICMP echo requests. Runs until Ctrl+C unless -c is given.",
            "Works with any supported NIC: RTL8139, RTL8169, e1000, virtio-net.",
            "Example: ping -c 4 10.0.2.2",
        ]),
        "ntpdate" => help_line("ntpdate [server]", &[
            "Set the clock via SNTP. Without an argument tries the QEMU gateway",
            "and then public NTP servers. 'date' shows the result.",
        ]),
        "ifconfig" | "ip" => help_line("ifconfig | ip [addr|link|route]", &[
            "Interface address, MAC, link state, gateway and packet counters.",
        ]),
        "tutor" => help_line("tutor [topic]", &[
            "Topics: intro fs disk persistence net mem kernel shell axon commands",
        ]),
        "grape" => help_line("grape [file]", &[
            "Text editor. Ctrl+O save, Ctrl+X exit, Ctrl+K cut line,",
            "Ctrl+W search, Ctrl+G help.",
        ]),
        "tomato" => help_line("tomato <op> [pkg]", &[
            "Package manager: -S install, -R remove, -Q list, -Ss search, -Syu update.",
            "tomato --tmt <cmd> works with .tmt binary packages.",
        ]),
        "seed" => help_line("seed [status|start|stop|restart|log] [service]", &[
            "Service manager. Note: the listed services are table entries; the",
            "kernel does not run them as separate processes yet.",
        ]),
        "doom" => help_line("doom", &[
            "Runs DOOM if doom1.wad was present at build time.",
            "Arrows/WASD move, Ctrl fire, Space use, Esc menu.",
        ]),
        "soundtest" => help_line("soundtest", &[
            "Shows the active audio driver (AC97 / HDA / ES1371), IRQ, rate and",
            "volume, dumps registers to serial COM1 and plays 0.5 s of 440 Hz.",
        ]),
        "vol" => help_line("vol [N | +N | -N]", &[
            "Show or set master volume in percent.",
        ]),
        "sync" | "save" => help_line("sync", &[
            "Write the in-memory filesystem changes to the persistence area",
            "(LBA 2048) of the first disk. Changes are also written automatically",
            "about 10 s after the last change while the shell is idle.",
        ]),
        "cat" => help_line("cat <file>", &[
            "Print a file. Live kernel data: /proc/cpuinfo meminfo uptime",
            "version tasks mounts cmdline.",
        ]),
        "uname" => help_line("uname [-a|-s|-n|-r|-m]", &[
            "-a all, -s kernel name, -n host name, -r release, -m machine.",
        ]),
        "free" | "meminfo" => help_line("free | meminfo", &[
            "free: physical frames and kernel heap. meminfo: /proc/meminfo.",
        ]),
        "date" => help_line("date [-e | -n | --unix]", &[
            "Local date/time. The clock starts from the CMOS RTC at boot and",
            "'ntpdate' corrects it. System time counts from the ospab epoch,",
            "2012-08-09 00:00:00 UTC: -e seconds, -n nanoseconds, --unix Unix seconds.",
        ]),
        "dmesg" => help_line("dmesg", &[
            "The last 32 kernel events (boot, faults, commands). Full boot",
            "log is on serial COM1.",
        ]),
        "ring3test" => help_line("ring3test", &[
            "Spawns a CPL3 task that calls getpid and exit; the result is",
            "printed on serial COM1.",
        ]),
        "bench" => help_line("bench [iterations]", &[
            "Times a fixed FMA workload with the TSC and reports jitter.",
        ]),
        _ => {
            for sec in HELP {
                for &(n, d) in sec.cmds {
                    let names = n.split(|c| c == ' ' || c == '/' || c == '(' || c == ')');
                    if names.into_iter().any(|w| w == topic) {
                        help_line(n, &[d]);
                        return;
                    }
                }
            }
            err_print("help: no such command: ");
            err_print(topic);
            puts("\n");
        }
    }
}

// ══════════════════════════════════════════════════════════════
// Basic commands
// ══════════════════════════════════════════════════════════════

fn cmd_clear() {
    framebuffer::clear(BG);
    framebuffer::set_cursor_pos(0, 0);
}

fn cmd_version() {
    framebuffer::draw_string(crate::version::OS_VERSION, FG_OK, BG);
    puts("  (kernel ");
    puts(crate::version::KERNEL_VERSION);
    puts(", ");
    puts(crate::version::ARCH);
    puts(")\n");
    dim_print("License: ");
    dim_print(crate::version::LICENSE);
    puts("\n");
}

fn cmd_uname(args: &str) {
    let a = args.trim();
    let all = a.contains('a') && a.starts_with('-') || a == "--all";
    let host = hostname();
    if a.is_empty() || a == "-s" {
        puts("AETERNA\n");
    } else if all {
        puts("AETERNA ");
        puts(&host);
        puts(" ");
        puts(crate::version::VERSION_STR);
        puts(" ");
        puts(crate::version::ARCH);
        puts(" ospab.os\n");
    } else if a == "-n" {
        puts(&host);
        puts("\n");
    } else if a == "-r" {
        puts(crate::version::VERSION_STR);
        puts("\n");
    } else if a == "-m" || a == "-p" {
        puts(crate::version::ARCH);
        puts("\n");
    } else {
        err_print("uname: unknown option ");
        err_print(a);
        puts("\n");
        dim_print("Usage: uname [-a|-s|-n|-r|-m]\n");
    }
}

fn cmd_hostname(args: &str) {
    let trimmed = args.trim();
    if trimmed.is_empty() {
        puts(&hostname());
        puts("\n");
        return;
    }
    if trimmed == "-h" || trimmed == "--help" {
        puts("Usage: hostname [NEW_NAME]\n");
        return;
    }
    if trimmed.len() > 63 {
        err_print("hostname: name too long (max 63)\n");
        return;
    }
    for &b in trimmed.as_bytes() {
        let valid = (b as char).is_ascii_alphanumeric() || b == b'-' || b == b'.';
        if !valid {
            err_print("hostname: invalid character (allowed: a-z A-Z 0-9 . -)\n");
            return;
        }
    }
    let mut data = Vec::from(trimmed.as_bytes());
    data.push(b'\n');
    if !fs::write_file("/etc/hostname", &data) {
        err_print("hostname: failed to write /etc/hostname\n");
        return;
    }
    puts("hostname set to ");
    puts(trimmed);
    puts("\n");

    if ospab_os::net::is_up() {
        dim_print("renewing DHCP lease with the new name...\n");
        if ospab_os::net::dhcp_renew() {
            dim_print("done\n");
        } else {
            framebuffer::draw_string("warning: DHCP renew failed (name saved locally)\n", FG_WARN, BG);
        }
    }
}

fn print_signed(v: i64) {
    if v < 0 { puts("-"); }
    print_dec(v.unsigned_abs());
}

/// `date`            — local date/time and the clock source
/// `date -e | +%s`   — seconds since the ospab epoch (2012-08-09 00:00:00 UTC)
/// `date -n`         — nanoseconds since the ospab epoch
/// `date -x | --unix`— Unix seconds
fn cmd_date(args: &str) {
    use ospab_os::time;
    let now = time::now();
    match args.trim() {
        "-e" | "+%s" => { print_signed(now.div_euclid(time::NS_PER_SEC)); puts("\n"); }
        "-n"         => { print_signed(now); puts("\n"); }
        "-x" | "--unix" => { print_signed(time::to_unix_secs(now)); puts("\n"); }
        "" | "-l" => {
            let tz = ospab_os::net::sntp::read_timezone_offset();
            let mut buf = [0u8; 40];
            let len = time::format(now, tz, &mut buf);
            puts(core::str::from_utf8(&buf[..len]).unwrap_or("?"));
            match time::source() {
                time::Source::Ntp  => dim_print("  (NTP)\n"),
                time::Source::Rtc  => dim_print("  (CMOS RTC; run 'ntpdate' to sync)\n"),
                time::Source::None => dim_print("  (clock not set)\n"),
            }
        }
        _ => puts("usage: date [-e | -n | --unix]\n"),
    }
}

fn cmd_about() {
    puts("\n");
    framebuffer::draw_string("  AETERNA", FG_OK, BG);
    dim_print("  - the kernel of ospab.os\n\n");
    puts("  ");
    puts(crate::version::OS_VERSION);
    puts(" with the AETERNA kernel, written from scratch in Rust (no_std).\n\n");
    puts("  Goal: a capability-based microkernel, with drivers, network and\n");
    puts("  filesystems as isolated user-space servers.\n\n");
    framebuffer::draw_string("  Today:", FG_WARN, BG);
    puts(" the kernel, drivers, network stack, this shell and every tool\n");
    puts("  run together in ring 0 in one address space. Ring 3 works for test\n");
    puts("  tasks only (see 'ring3test'). Capabilities are not enforced yet.\n");
    puts("  One CPU is used (no SMP).\n\n");
    dim_print("  License: ");
    dim_print(crate::version::LICENSE);
    dim_print("   Details: README.md, AUDIT.md, ROADMAP.md in the source tree.\n\n");
}

fn cmd_free() {
    let used_f = ospab_os::mm::physical::frames_allocated();
    let free_f = ospab_os::mm::physical::frames_free();
    let total = (used_f + free_f) * 4096;

    dim_print("             total        used        free\n");
    puts("Mem:   ");
    print_size_padded(total, 12, true);
    print_size_padded(used_f * 4096, 12, true);
    print_size_padded(free_f * 4096, 12, true);
    puts("\n");

    if ospab_os::mm::heap::is_initialized() {
        let (used, free) = ospab_os::mm::heap::stats();
        let heap_total = ospab_os::mm::heap::heap_size() as u64;
        puts("Heap:  ");
        print_size_padded(heap_total, 12, true);
        print_size_padded(used as u64, 12, true);
        print_size_padded(free as u64, 12, true);
        puts("\n");
    }
    dim_print("Mem = 4 KiB frames managed by the physical allocator; the kernel heap\n");
    dim_print("is carved out of those frames at boot, so it counts as used in Mem.\n");
}

fn cmd_cat_proc(path: &str) {
    match fs::read_file(path) {
        Some(data) => puts(core::str::from_utf8(&data).unwrap_or("(not UTF-8)\n")),
        None => {
            err_print(path);
            err_print(": not available\n");
        }
    }
}

fn cmd_uptime() {
    let ticks = ospab_os::arch::x86_64::idt::timer_ticks();
    let seconds = ticks / TIMER_HZ;
    let days = seconds / 86400;
    let hours = (seconds / 3600) % 24;
    let minutes = (seconds / 60) % 60;

    puts("up ");
    if days > 0 {
        print_dec(days);
        puts("d ");
    }
    if days > 0 || hours > 0 {
        print_dec(hours);
        puts("h ");
    }
    print_dec(minutes);
    puts("m ");
    print_dec(seconds % 60);
    puts("s");
    dim_print("  (");
    print_dec(ticks);
    dim_print(" ticks at 100 Hz, ");
    let tasks = count_tasks();
    print_dec(tasks as u64);
    dim_print(if tasks == 1 { " scheduler task)\n" } else { " scheduler tasks)\n" });
}

fn count_tasks() -> usize {
    use ospab_os::core::scheduler::TaskSnapshot;
    // SAFETY: plain data; get_tasks fills the prefix it reports.
    let mut snaps: [TaskSnapshot; 64] = unsafe { core::mem::zeroed() };
    ospab_os::core::scheduler::get_tasks(&mut snaps)
}

fn cmd_dmesg() {
    let mut buf = [klog::Event::empty_pub(); 32];
    let count = klog::last_events(&mut buf, 32);
    if count == 0 {
        dim_print("(no events recorded)\n");
        return;
    }
    let total = klog::total_count();
    if total > count {
        dim_print("(last ");
        print_dec(count as u64);
        dim_print(" of ");
        print_dec(total as u64);
        dim_print(" events; full boot log is on serial COM1)\n");
    }
    for ev in &buf[..count] {
        let label = ev.source.label().trim_end();
        let color = match ev.source {
            klog::EventSource::Boot => FG_OK,
            klog::EventSource::Fault | klog::EventSource::Panic => FG_ERR,
            klog::EventSource::Terminal => FG_HL,
            _ => FG_DIM,
        };
        framebuffer::draw_string("[", FG_DIM, BG);
        framebuffer::draw_string(label, color, BG);
        framebuffer::draw_string("]", FG_DIM, BG);
        pad(label.len() + 2, 8);
        puts(ev.message());
        puts("\n");
    }
}

fn cmd_lsmem() {
    let stats = ospab_os::mm::physical::stats();
    let regions = ospab_os::mm::physical::get_usable_regions();
    dim_print("Usable RAM regions (from the bootloader memory map):\n");
    dim_print("  START               END                 SIZE\n");
    for r in regions {
        puts("  ");
        print_hex_u64(r.base);
        puts("  ");
        print_hex_u64(r.base + r.length - 1);
        puts("  ");
        print_size(r.length);
        puts("\n");
    }
    puts("Usable:     ");
    print_size(stats.usable_bytes);
    puts(" in ");
    print_dec(stats.region_count as u64);
    puts(" regions\n");
    puts("Map total:  ");
    print_size(stats.total_bytes);
    dim_print("  (all memory-map entries, incl. reserved and device windows)\n");
}

// ══════════════════════════════════════════════════════════════
// Files and disks
// ══════════════════════════════════════════════════════════════

fn cmd_changelog() {
    match fs::read_file("/CHANGELOG.md") {
        Some(data) => {
            if let Ok(text) = core::str::from_utf8(&data) {
                puts(text);
                if !text.ends_with('\n') { puts("\n"); }
            } else {
                err_print("changelog: /CHANGELOG.md is not UTF-8\n");
            }
        }
        None => {
            dim_print("No /CHANGELOG.md in this image.\n");
            cmd_version();
        }
    }
}

fn cmd_sync() {
    if ospab_os::drivers::disk_count() == 0 {
        framebuffer::draw_string("sync: no disk attached; files live in RAM only.\n", FG_WARN, BG);
        return;
    }
    if !fs::disk_sync::is_dirty() {
        dim_print("Nothing to write: no changes since the last sync.\n");
        return;
    }
    puts("Writing filesystem to disk...\n");
    klog::record(klog::EventSource::Boot, "Sync requested");
    if fs::disk_sync::sync_filesystem() {
        framebuffer::draw_string("Done.\n", FG_OK, BG);
    } else {
        err_print("sync failed (see serial log).\n");
    }
}

fn cmd_dump_disk(_args: &str) {
    let disk = match fs::disk_sync::primary_disk_index() {
        Some(d) => d,
        None => {
            if ospab_os::drivers::disk_count() == 0 {
                err_print("dump_disk: no disk attached\n");
                return;
            }
            0
        }
    };
    puts("Disk ");
    print_dec(disk as u64);
    puts(", sector 2048 (start of the persistence area), first 64 bytes:\n");
    let mut buf = [0u8; 512];
    if !ospab_os::drivers::read(disk, 2048, 1, &mut buf) {
        err_print("dump_disk: read failed\n");
        return;
    }
    for row in 0..4 {
        let off = row * 16;
        dim_print("  ");
        print_hex_byte(off as u8);
        dim_print(":  ");
        for i in 0..16 {
            print_hex_byte(buf[off + i]);
            puts(if i == 7 { "  " } else { " " });
        }
        puts(" ");
        let mut ascii = String::with_capacity(16);
        for i in 0..16 {
            let c = buf[off + i];
            ascii.push(if (0x20..0x7f).contains(&c) { c as char } else { '.' });
        }
        dim_print(&ascii);
        puts("\n");
    }
    let magic = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
    if magic == fs::disk_sync::SUPER_MAGIC {
        framebuffer::draw_string("Persistence superblock present.\n", FG_OK, BG);
    } else {
        dim_print("No persistence superblock (disk never synced or not ours).\n");
    }
}

// ─── vol — volume control ────────────────────────────────────────────────────

fn simple_parse_u8(s: &str) -> Option<u8> {
    let mut val: u16 = 0;
    let mut any = false;
    for &b in s.as_bytes() {
        if b.is_ascii_digit() {
            val = val * 10 + (b - b'0') as u16;
            any = true;
            if val > 255 { return Some(255); }
        } else {
            return None;
        }
    }
    if any { Some(val as u8) } else { None }
}

/// Saved volume before mute (for toggle restore).
static mut PRE_MUTE_VOL: u8 = 80;

fn cmd_vol(args: &str) {
    use ospab_os::drivers::audio;

    if !audio::is_ready() {
        err_print("vol: no audio driver active\n");
        return;
    }

    let arg = args.trim();
    if arg.is_empty() {
        puts("Volume: ");
        print_dec(audio::volume() as u64);
        puts("%\n");
        return;
    }

    let new_vol = if let Some(rest) = arg.strip_prefix('+') {
        simple_parse_u8(rest).map(|d| audio::volume().saturating_add(d).min(100))
    } else if let Some(rest) = arg.strip_prefix('-') {
        simple_parse_u8(rest).map(|d| audio::volume().saturating_sub(d))
    } else {
        simple_parse_u8(arg).map(|v| v.min(100))
    };
    let new_vol = match new_vol {
        Some(v) => v,
        None => {
            err_print("vol: expected N, +N or -N (0-100)\n");
            return;
        }
    };

    audio::set_volume(new_vol);
    puts("Volume: ");
    print_dec(new_vol as u64);
    puts("%\n");
}

fn cmd_mute() {
    use ospab_os::drivers::audio;

    if !audio::is_ready() {
        err_print("mute: no audio driver active\n");
        return;
    }

    let cur = audio::volume();
    if cur == 0 {
        let restore = unsafe { PRE_MUTE_VOL };
        let restore = if restore == 0 { 80 } else { restore };
        audio::set_volume(restore);
        puts("Unmuted (");
        print_dec(restore as u64);
        puts("%)\n");
    } else {
        unsafe { PRE_MUTE_VOL = cur; }
        audio::set_volume(0);
        puts("Muted\n");
    }
}

// ─── soundtest — audio subsystem diagnostics + 440 Hz test tone ──────────────

fn cmd_soundtest() {
    use ospab_os::arch::x86_64::serial;
    use ospab_os::drivers::audio;

    serial::write_str("[SOUND] === Audio Subsystem Diagnostics ===\r\n");

    let driver = audio::active_driver_name();
    let ready  = audio::is_ready();
    let mut nbuf = [0u8; 8];

    serial::write_str("[SOUND] Active driver : "); serial::write_str(driver); serial::write_str("\r\n");
    serial::write_str("[SOUND] Ready         : ");
    serial::write_str(if ready { "yes" } else { "no" }); serial::write_str("\r\n");

    puts("Driver       : "); puts(driver); puts("\n");
    puts("Status       : ");
    if ready {
        framebuffer::draw_string("ready\n", FG_OK, BG);
    } else {
        err_print("not ready\n");
    }

    let irq = audio::irq_line();
    serial::write_str("[SOUND] IRQ           : ");
    serial::write_str(ospab_os::format_u64(&mut nbuf, irq as u64));
    serial::write_str("\r\n");
    puts("IRQ line     : "); print_dec(irq as u64); puts("\n");

    let rate = audio::sample_rate();
    puts("Sample rate  : "); print_dec(rate as u64); puts(" Hz\n");

    let vol = audio::volume();
    puts("Volume       : "); print_dec(vol as u64); puts("%\n");

    if driver == "HDA" && ready {
        let lpib = audio::hda::dma_position();
        puts("DMA position : "); print_dec(lpib as u64); puts(" / "); print_dec(audio::hda::ring_bytes() as u64); puts("\n");
    }

    if driver == "AC97" && ready {
        let (civ, fill, in_flight) = audio::ac97::dma_status();
        serial::write_str("[SOUND] CIV=");
        serial::write_str(ospab_os::format_u64(&mut nbuf, civ as u64));
        serial::write_str("  FILL_IDX=");
        serial::write_str(ospab_os::format_u64(&mut nbuf, fill as u64));
        serial::write_str("  in_flight=");
        serial::write_str(ospab_os::format_u64(&mut nbuf, in_flight as u64));
        serial::write_str("\r\n");
        puts("DMA          : CIV="); print_dec(civ as u64);
        puts(" FILL="); print_dec(fill as u64);
        puts(" in_flight="); print_dec(in_flight as u64); puts("\n");
    }

    dim_print("Register dump written to serial COM1.\n");
    audio::dump_status();
    audio::dump_mem_map();

    if !ready {
        puts("No audio driver ready; test tone skipped.\n");
        serial::write_str("[SOUND] No driver — test tone SKIPPED\r\n");
        serial::write_str("[SOUND] === End Diagnostics ===\r\n");
        return;
    }

    // 16-sample sine table: sin(i·2π/16) × 16384 (50 % amplitude, integer-only)
    let sample_rate = audio::sample_rate();
    if sample_rate == 0 {
        err_print("soundtest: driver reports a sample rate of 0; tone skipped\n");
        return;
    }

    puts("Playing 440 Hz for 0.5 s (");
    print_dec(sample_rate as u64);
    puts(" Hz, 16-bit stereo)...\n");
    serial::write_str("[SOUND] Generating 440 Hz test tone @ ");
    serial::write_str(ospab_os::format_u64(&mut nbuf, sample_rate as u64));
    serial::write_str(" Hz...\r\n");

    const SIN16: [i16; 16] = [
        0, 6270, 11585, 15137, 16384, 15137, 11585, 6270,
        0, -6270, -11585, -15137, -16384, -15137, -11585, -6270,
    ];

    // Phase increment Q16.16 = 440 × 16 × 65536 / sample_rate
    let phase_inc: u32 = ((440u64 * 16u64 * 65536u64) / sample_rate as u64) as u32;
    let total_frames: usize = (sample_rate / 2) as usize;
    const CHUNK_FRAMES: usize = 1024;
    const CHUNK_BYTES:  usize = CHUNK_FRAMES * 4;

    let mut phase: u32 = 0;
    let mut total_bytes: usize = 0;
    let mut remaining: usize = total_frames;
    let mut pcm: Vec<u8> = alloc::vec![0u8; CHUNK_BYTES];

    while remaining > 0 {
        let n = remaining.min(CHUNK_FRAMES);
        for i in 0..n {
            let s = SIN16[((phase >> 16) as usize) & 0xF];
            let lo = (s as u16 & 0xFF) as u8;
            let hi = ((s as u16) >> 8) as u8;
            pcm[i * 4] = lo;
            pcm[i * 4 + 1] = hi;
            pcm[i * 4 + 2] = lo;
            pcm[i * 4 + 3] = hi;
            phase = phase.wrapping_add(phase_inc);
        }
        let bytes = n * 4;
        audio::write_pcm(&pcm[..bytes]);
        total_bytes += bytes;
        remaining -= n;
    }

    serial::write_str("[SOUND] Bytes submitted : ");
    serial::write_str(ospab_os::format_u64(&mut nbuf, total_bytes as u64));
    serial::write_str("\r\n[SOUND] === End Diagnostics ===\r\n");

    // Fill the hardware ring with silence so the tone does not loop.
    let silence = alloc::vec![0u8; 32768];
    audio::write_pcm(&silence);

    puts("Submitted ");
    print_dec(total_bytes as u64);
    puts(" bytes. ");
    framebuffer::draw_string("Done.\n", FG_OK, BG);
}

// ─── power ───────────────────────────────────────────────────────────────────

fn cmd_reboot() {
    if fs::disk_sync::is_dirty() {
        puts("Writing pending filesystem changes...\n");
        fs::disk_sync::sync_filesystem();
    }
    puts("Rebooting...\n");
    klog::record(klog::EventSource::Boot, "Reboot requested");
    ospab_os::arch::x86_64::serial::write_str("[POWER] Rebooting...\r\n");
    // ACPI reset; falls back internally to 0xCF9 / 0x64 / triple fault
    acpi::reboot();
}

fn cmd_shutdown() {
    if fs::disk_sync::is_dirty() {
        puts("Writing pending filesystem changes...\n");
        fs::disk_sync::sync_filesystem();
    }
    puts("Shutting down...\n");
    klog::record(klog::EventSource::Boot, "Shutdown requested");
    ospab_os::arch::x86_64::serial::write_str("[POWER] Shutting down...\r\n");
    // ACPI S5 via PM1a_CNT, with emulator port fallbacks
    acpi::shutdown();
    dim_print("\nACPI power-off did not take effect. It is now safe to turn off the machine.\n");
    loop { unsafe { asm!("cli; hlt"); } }
}

fn cmd_history() {
    unsafe {
        if HISTORY_COUNT == 0 {
            dim_print("(no history)\n");
            return;
        }
        let start = if HISTORY_COUNT > HISTORY_SIZE { HISTORY_COUNT - HISTORY_SIZE } else { 0 };
        for i in start..HISTORY_COUNT {
            let slot = i % HISTORY_SIZE;
            let len = HISTORY_LENS[slot];
            let n = i + 1;
            pad(dec_len(n as u64), 5);
            print_dec_color(n as u64, FG_DIM);
            puts("  ");
            puts(core::str::from_utf8_unchecked(&HISTORY[slot][..len]));
            puts("\n");
        }
    }
}

// ══════════════════════════════════════════════════════════════
// Network commands
// ══════════════════════════════════════════════════════════════

fn net_down_message() {
    err_print("Network is not up.\n");
    dim_print("Supported NICs: RTL8139, RTL8169/8111, Intel e1000, virtio-net.\n");
    dim_print("QEMU example: -netdev user,id=n0 -device e1000,netdev=n0\n");
}

fn cmd_ifconfig() {
    if !ospab_os::net::is_up() {
        net_down_message();
        return;
    }
    let ip = unsafe { ospab_os::net::OUR_IP };
    let gw = unsafe { ospab_os::net::GATEWAY_IP };
    let mask = unsafe { ospab_os::net::SUBNET_MASK };
    let mac = unsafe { ospab_os::net::OUR_MAC };
    let gw_mac = unsafe { ospab_os::net::GATEWAY_MAC };
    let driver = ospab_os::net::nic_name();
    let hw_link = ospab_os::net::link_up();

    hl_print("eth0");
    puts(": ");
    if hw_link {
        framebuffer::draw_string("UP", FG_OK, BG);
    } else {
        err_print("NO-CARRIER");
    }
    dim_print("  driver ");
    dim_print(driver);
    puts("\n");
    puts("      inet ");
    print_ip(ip);
    puts("  netmask ");
    print_ip(mask);
    puts("  broadcast ");
    print_ip(ip_broadcast(ip, mask));
    puts("\n");
    puts("      ether ");
    print_mac(mac);
    puts("\n");
    puts("      gateway ");
    print_ip(gw);
    puts("  (");
    print_mac(gw_mac);
    if gw_mac == [0xFF; 6] {
        dim_print(", ARP not resolved, using broadcast");
    }
    puts(")\n");
    puts("      RX packets ");
    print_dec(ospab_os::net::rx_packets());
    puts("  bytes ");
    print_dec(ospab_os::net::rx_bytes());
    puts("\n");
    puts("      TX packets ");
    print_dec(ospab_os::net::tx_packets());
    puts("  bytes ");
    print_dec(ospab_os::net::tx_bytes());
    puts("\n");
}

fn ip_broadcast(ip: [u8; 4], mask: [u8; 4]) -> [u8; 4] {
    [ip[0] | !mask[0], ip[1] | !mask[1], ip[2] | !mask[2], ip[3] | !mask[3]]
}

fn cmd_ntpdate(args: &str) {
    if !ospab_os::net::is_up() {
        net_down_message();
        return;
    }

    let server = args.trim();
    let result = if server.is_empty() {
        puts("Querying NTP servers...\n");
        ospab_os::net::sntp::sync_system_time()
    } else {
        let server_ip = match parse_ip(server) {
            Some(ip) => ip,
            None => match ospab_os::net::resolver::resolve_host(server) {
                Ok(ip) => ip,
                Err(_) => {
                    err_print("ntpdate: cannot resolve ");
                    err_print(server);
                    puts("\n");
                    return;
                }
            },
        };
        puts("Querying ");
        puts(server);
        puts(" (");
        print_ip(server_ip);
        puts(")...\n");
        ospab_os::net::sntp::sync_time(server_ip)
    };

    match result {
        Ok(unix_ts) => {
            framebuffer::draw_string("Clock set: ", FG_OK, BG);
            let mut buf = [0u8; 32];
            let len = ospab_os::net::sntp::format_datetime_with_tz(
                unix_ts,
                ospab_os::net::sntp::read_timezone_offset(),
                &mut buf,
            );
            puts(core::str::from_utf8(&buf[..len]).unwrap_or("?"));
            puts("\n");
        }
        Err(e) => {
            err_print("ntpdate: ");
            err_print(e.as_str());
            puts("\n");
        }
    }
}

// ─── IP parsing helpers ───

fn parse_ip(s: &str) -> Option<[u8; 4]> {
    let mut ip = [0u8; 4];
    let mut octet = 0u32;
    let mut octet_idx = 0usize;
    let mut has_digit = false;

    for &b in s.as_bytes() {
        if b == b'.' {
            if !has_digit || octet > 255 || octet_idx >= 3 { return None; }
            ip[octet_idx] = octet as u8;
            octet_idx += 1;
            octet = 0;
            has_digit = false;
        } else if b.is_ascii_digit() {
            octet = octet * 10 + (b - b'0') as u32;
            if octet > 255 { return None; }
            has_digit = true;
        } else {
            return None;
        }
    }
    if !has_digit || octet_idx != 3 { return None; }
    ip[3] = octet as u8;
    Some(ip)
}

fn print_ip(ip: [u8; 4]) {
    for i in 0..4 {
        print_dec(ip[i] as u64);
        if i < 3 { puts("."); }
    }
}

fn print_mac(mac: [u8; 6]) {
    for i in 0..6 {
        print_hex_byte(mac[i]);
        if i < 5 { puts(":"); }
    }
}

// ══════════════════════════════════════════════════════════════
// Applications
// ══════════════════════════════════════════════════════════════

fn cmd_grape(args: &str) {
    let path = args.trim();
    if path.is_empty() {
        ospab_os::userspace::grape::edit("");
    } else {
        ospab_os::userspace::grape::edit(&resolve_path(path));
    }
    // The editor owns the whole screen; start clean when it returns.
    cmd_clear();
}

fn cmd_tomato(args: &str) {
    // `tomato --tmt <subcmd>` routes to the binary package (.tmt) subsystem
    if let Some(tmt_args) = args.strip_prefix("--tmt") {
        ospab_os::userspace::tomato::tmt_dispatch(tmt_args.trim());
    } else {
        ospab_os::userspace::tomato::run(args);
    }
}

fn cmd_doom() {
    dim_print("Starting DOOM...\n");
    ospab_os::doom::run();
    // DOOM draws over the whole framebuffer; clear it on return.
    cmd_clear();
}

fn cmd_ring3test() {
    puts("Starting a ring-3 test task (getpid, then exit)...\n");
    match ospab_os::arch::x86_64::ring::launch_ring3_smoke_test() {
        Some(pid) => {
            puts("Spawned pid ");
            print_dec(pid as u64);
            puts(". It runs on the next scheduler tick; the result appears on\n");
            puts("serial COM1 as [SYSCALL] exit(");
            print_dec(pid as u64);
            puts(").\n");
        }
        None => err_print("ring3test: could not prepare the ring-3 task\n"),
    }
}

// ══════════════════════════════════════════════════════════════
// tutor
// ══════════════════════════════════════════════════════════════

fn cmd_tutor(args: &str) {
    let topic = if args.trim().is_empty() { "intro" } else { args.trim() };

    match topic {
        "intro"       => tutor_intro(),
        "fs"          => tutor_fs(),
        "disk"        => tutor_disk(),
        "persistence" => tutor_persistence(),
        "net"         => tutor_net(),
        "mem"         => tutor_mem(),
        "kernel"      => tutor_kernel(),
        "shell"       => tutor_shell(),
        "axon"        => tutor_axon(),
        "commands" | "cmd" => cmd_help(""),
        "topics" | "help" | "?" => tutor_topics(),
        _ => {
            err_print("tutor: unknown topic '");
            err_print(topic);
            err_print("'\n");
            tutor_topics();
        }
    }
}

fn tutor_title(t: &str) {
    puts("\n");
    framebuffer::draw_string(t, FG_OK, BG);
    puts("\n");
    let n = t.chars().count();
    for _ in 0..n {
        framebuffer::draw_string("\u{2500}", FG_DIM, BG);
    }
    puts("\n");
}

fn tutor_head(t: &str) {
    puts("\n");
    framebuffer::draw_string(t, FG_WARN, BG);
    puts("\n");
}

/// "  command      explanation"
fn tutor_try(cmd: &str, what: &str) {
    puts("  ");
    hl_print(cmd);
    pad(cmd.len(), 34);
    dim_print(what);
    puts("\n");
}

fn tutor_topics() {
    tutor_title("tutor topics");
    tutor_try("tutor intro", "what this system is and is not");
    tutor_try("tutor fs", "the in-memory filesystem and /proc");
    tutor_try("tutor disk", "storage drivers and disk tools");
    tutor_try("tutor persistence", "how files survive a reboot");
    tutor_try("tutor net", "network stack and tools");
    tutor_try("tutor mem", "physical memory and the kernel heap");
    tutor_try("tutor kernel", "kernel structure and boot");
    tutor_try("tutor shell", "line editing, variables, aliases");
    tutor_try("tutor axon", "the AXON file and text tools");
    tutor_try("tutor commands", "same as 'help'");
    puts("\n");
}

fn tutor_intro() {
    tutor_title("Welcome to ospab.os");
    puts("ospab.os is a hobby operating system written from scratch in Rust. Its\n");
    puts("kernel, AETERNA, is meant to become a capability-based microkernel.\n");
    puts("Right now it is one big kernel: drivers, the network stack, this shell\n");
    puts("and all tools run in ring 0 and share one address space.\n");

    tutor_head("Things to try");
    tutor_try("ls /  ;  cat /etc/os-release", "look around the filesystem");
    tutor_try("cat /proc/cpuinfo", "live data from the kernel");
    tutor_try("free  ;  lsmem", "memory");
    tutor_try("lspci  ;  lsblk", "hardware the kernel found");
    tutor_try("ifconfig  ;  ping -c 3 10.0.2.2", "network (needs a NIC)");
    tutor_try("ntpdate  ;  date", "set the clock from the internet");
    tutor_try("grape /tmp/notes.txt", "text editor");
    tutor_try("dmesg", "kernel event log");

    tutor_head("More");
    puts("'help' lists every command, 'tutor topics' lists the other lessons.\n");
    puts("Tab completes commands and paths; Up/Down recall history.\n\n");
}

fn tutor_fs() {
    tutor_title("Filesystem");
    puts("Files live in RAM. The root '/' is a copy-on-write overlay: a read-only\n");
    puts("RamFS with the default files, plus a writable RamFS for your changes.\n");
    puts("Only the writable layer is saved to disk (see 'tutor persistence').\n");
    puts("/proc is generated by the kernel on every read.\n");
    puts("There are no users or permissions yet; everything runs as root.\n");

    tutor_head("Try");
    tutor_try("ls /", "top-level directories");
    tutor_try("ls /proc", "live kernel files");
    tutor_try("cat /proc/meminfo", "memory counters");
    tutor_try("cat /proc/tasks", "scheduler task list");
    tutor_try("echo hi > /tmp/a.txt", "write a file");
    tutor_try("cat /tmp/a.txt", "read it back");
    tutor_try("tree /etc", "directory tree");
    puts("\n");
}

fn tutor_disk() {
    tutor_title("Disks");
    puts("Storage drivers: ATA PIO (IDE), AHCI (SATA) and NVMe. GPT partition\n");
    puts("tables can be read and written by the installer.\n");

    tutor_head("Try");
    tutor_try("lsblk", "list disks");
    tutor_try("fdisk -l", "partition tables");
    tutor_try("dump_disk", "raw view of the persistence sector");
    tutor_try("install", "install to a disk (GPT + FAT32)");

    tutor_head("QEMU: attach a disk");
    dim_print("  qemu-img create -f raw disk.img 1G\n");
    dim_print("  ... -drive file=disk.img,format=raw,if=none,id=d0 \\\n");
    dim_print("      -device ahci,id=ahci -device ide-hd,drive=d0,bus=ahci.0\n\n");
}

fn tutor_persistence() {
    tutor_title("Persistence");
    puts("Without a disk, everything you change is lost at reboot.\n");
    puts("With a disk, the writable filesystem layer is serialised into one flat\n");
    puts("image starting at sector (LBA) 2048 of the disk:\n");
    dim_print("  superblock: magic \"AETERNA\\0\", sector count, \"AETERNA_FS\", version, entries\n");
    dim_print("  entries:    path, type (file/dir), file data\n");
    puts("The image is written about 10 seconds after the last change, while the\n");
    puts("shell waits for input, or at once with 'sync'. reboot and shutdown also\n");
    puts("write pending changes. At boot the image is read back into RAM.\n");

    tutor_head("Try (with a disk attached)");
    tutor_try("echo hello > /home/root/note.txt", "change something");
    tutor_try("sync", "write it now");
    tutor_try("dump_disk", "see the superblock");
    tutor_try("reboot", "then: cat /home/root/note.txt");
    puts("\n");
}

fn tutor_net() {
    tutor_title("Networking");
    puts("The kernel has its own IPv4 stack: Ethernet, ARP, IPv4, ICMP, UDP, TCP,\n");
    puts("DHCP, DNS, SNTP and a TLS client. NIC drivers: RTL8139, RTL8169/8111,\n");
    puts("Intel e1000 and virtio-net. There is no IPv6 and no loopback device.\n");

    tutor_head("QEMU");
    dim_print("  -netdev user,id=n0 -device e1000,netdev=n0\n");
    puts("QEMU's user network gives the guest 10.0.2.15, gateway 10.0.2.2 and\n");
    puts("DNS 10.0.2.3. It forwards TCP/UDP to the internet; ping beyond the\n");
    puts("gateway depends on the host.\n");

    tutor_head("Try");
    tutor_try("ifconfig", "address and counters");
    tutor_try("ping -c 3 10.0.2.2", "reach the gateway");
    tutor_try("nslookup example.com", "DNS");
    tutor_try("curl http://example.com", "HTTP");
    tutor_try("ntpdate", "set the clock");
    puts("\n");
}

fn tutor_mem() {
    tutor_title("Memory");
    puts("Physical memory is managed in 4 KiB frames by a bitmap allocator,\n");
    puts("built from the bootloader's memory map. The kernel heap (");
    print_size(ospab_os::mm::heap::heap_size() as u64);
    puts(") is a\nlinked-list allocator on frames taken at boot.\n");
    puts("All physical memory is also mapped at a fixed offset (the HHDM), here ");
    match ospab_os::arch::x86_64::boot::hhdm_offset() {
        Some(off) => print_hex_u64(off),
        None => puts("unknown"),
    }
    puts(".\n");
    puts("Each task has its own page tables; the upper half (kernel) is shared.\n");

    tutor_head("Try");
    tutor_try("free", "frames and heap in use");
    tutor_try("lsmem", "usable RAM regions");
    tutor_try("cat /proc/meminfo", "all counters");
    tutor_try("verify_mem", "heap allocation test");
    puts("\n");
}

fn tutor_kernel() {
    tutor_title("Kernel");
    puts("AETERNA is written in Rust (no_std) for x86-64 and boots with Limine.\n");

    tutor_head("What exists");
    puts("  GDT/TSS, IDT, APIC timer, preemptive scheduler, SYSCALL/SYSRET,\n");
    puts("  per-task page tables, bitmap frame allocator, kernel heap, ACPI\n");
    puts("  power off/reset, PCI, storage, network and audio drivers.\n");

    tutor_head("What does not exist yet");
    puts("  Ring-3 programs loaded from files (ELF loader), process isolation,\n");
    puts("  enforced capabilities, drivers as user-space servers, SMP.\n");
    puts("  The shell and tools are kernel code. See ROADMAP.md.\n");

    tutor_head("Source layout");
    tutor_try("arch/x86_64/", "CPU setup, interrupts, framebuffer, keyboard");
    tutor_try("core/", "scheduler, syscalls, IPC, capabilities");
    tutor_try("mm/", "frames, page tables, heap");
    tutor_try("drivers/  net/  vfs/", "drivers, network stack, filesystems");
    tutor_try("src/", "kernel entry, this terminal, installer");
    tutor_try("userland/", "grape, tomato, seed (still built into the kernel)");
    puts("\n");
}

fn tutor_shell() {
    tutor_title("Shell");
    puts("This terminal runs your line; file commands and variables come from the\n");
    puts("plum shell module.\n");

    tutor_head("Keys");
    tutor_try("Up / Down", "history");
    tutor_try("Tab", "complete command or path");
    tutor_try("Left/Right Home/End", "move (also Ctrl+B/F/A/E)");
    tutor_try("Ctrl+U / Ctrl+K / Ctrl+W", "delete to start / to end / word");
    tutor_try("Ctrl+C", "cancel the line or stop ping");
    tutor_try("Ctrl+L", "clear the screen");

    tutor_head("Variables, aliases, chaining");
    tutor_try("export NAME=world", "set a variable");
    tutor_try("echo hello $NAME", "use it");
    tutor_try("alias ll='ls -l'", "define an alias");
    tutor_try("cd /tmp ; ls", "run two commands");
    tutor_try("echo text >> file", "append to a file");
    puts("Pipes (|) are not supported.\n");
    puts("/etc/plum/plumrc is run when the shell starts.\n\n");
}

fn tutor_axon() {
    tutor_title("AXON tools");
    puts("AXON is the set of file and text tools built into the kernel. They\n");
    puts("read and write files directly; there are no pipes.\n");

    tutor_head("Try");
    tutor_try("wc /etc/os-release", "lines, words, bytes");
    tutor_try("grep NAME /etc/os-release", "matching lines");
    tutor_try("head -n 3 /etc/hosts", "first lines");
    tutor_try("sort /etc/hosts", "sorted");
    tutor_try("cut -d= -f1 /etc/os-release", "first field");
    tutor_try("xxd /etc/hostname", "hex dump");
    tutor_try("cp /etc/hosts /tmp/h", "copy");
    tutor_try("find / -name hosts", "find by name");
    puts("\n");
}

// ══════════════════════════════════════════════════════════════
// Output helpers
// ══════════════════════════════════════════════════════════════

fn puts(s: &str) {
    framebuffer::draw_string(s, FG, BG);
}

fn dim_print(s: &str) {
    framebuffer::draw_string(s, FG_DIM, BG);
}

fn err_print(s: &str) {
    framebuffer::draw_string(s, FG_ERR, BG);
}

fn hl_print(s: &str) {
    framebuffer::draw_string(s, FG_HL, BG);
}

/// Print spaces so that a field of `len` columns fills `target` columns.
fn pad(len: usize, target: usize) {
    for _ in 0..target.saturating_sub(len) {
        framebuffer::draw_char(' ', FG, BG);
    }
}

fn dec_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 10 { v /= 10; n += 1; }
    n
}

fn print_dec(val: u64) {
    print_dec_color(val, FG);
}

fn print_dec_color(mut val: u64, color: u32) {
    if val == 0 {
        framebuffer::draw_char('0', color, BG);
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    for j in (0..i).rev() {
        framebuffer::draw_char(buf[j] as char, color, BG);
    }
}

fn print_hex_byte(val: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    framebuffer::draw_char(HEX[(val >> 4) as usize] as char, FG, BG);
    framebuffer::draw_char(HEX[(val & 0xF) as usize] as char, FG, BG);
}

fn print_hex_u64(val: u64) {
    puts("0x");
    for i in (0..8).rev() {
        print_hex_byte((val >> (i * 8)) as u8);
    }
}

fn print_size(bytes: u64) {
    let s = format_size(bytes);
    puts(&s);
}

/// Print a size in a field of `width` columns (right-aligned if `right`).
fn print_size_padded(bytes: u64, width: usize, right: bool) {
    let s = format_size(bytes);
    if right { pad(s.len(), width); }
    puts(&s);
    if !right { pad(s.len(), width); }
}

/// Human-readable size with one decimal for MiB and GiB ("1.5 GiB").
fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        let tenths = bytes * 10 / GIB;
        alloc::format!("{}.{} GiB", tenths / 10, tenths % 10)
    } else if bytes >= MIB {
        let tenths = bytes * 10 / MIB;
        alloc::format!("{}.{} MiB", tenths / 10, tenths % 10)
    } else if bytes >= KIB {
        alloc::format!("{} KiB", bytes / KIB)
    } else {
        alloc::format!("{} B", bytes)
    }
}
