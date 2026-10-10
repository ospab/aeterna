/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

plum/io — standard streams for in-kernel commands.

Everything still runs in ring 0, so there are no per-process file
descriptors.  Instead plum keeps a stack of "stream frames".  A command
writes through `out()` / `err()` and reads through `take_stdin()` /
`read_stdin_line()`; the frames decide where the bytes go:

  stdout: the framebuffer console, a capture buffer (pipes, `$(...)`,
          `> file`), or nowhere (`> /dev/null`);
  stderr: the console, a capture buffer, stdout (`2>&1`) or nowhere;
  stdin:  text from the previous pipeline stage or a `< file`
          redirection, or the console (only the `read` builtin can read
          the keyboard).

A frame field set to `Inherit` defers to the frame below it.  Pipelines
are run stage by stage (no concurrency) and pipe data is text (UTF-8,
invalid bytes replaced).
*/

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::arch::x86_64::framebuffer;

pub const FG: u32 = 0x00FFFFFF;
pub const FG_OK: u32 = 0x0000FF00;
pub const FG_ERR: u32 = 0x00FF4444;
pub const FG_WARN: u32 = 0x00FFFF00;
pub const FG_DIM: u32 = 0x00AAAAAA;
pub const FG_DIR: u32 = 0x005555FF;
pub const FG_HL: u32 = 0x00FFCC00;
pub const BG: u32 = 0x00000000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Sink {
    Inherit,
    Screen,
    Capture,
    Null,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ErrSink {
    Inherit,
    Screen,
    Capture,
    /// 2>&1 — stderr goes wherever stdout of the same frame goes
    ToOut,
    Null,
}

pub enum Stdin {
    Inherit,
    Console,
    Data(String, usize),
}

struct Frame {
    out: Sink,
    err: ErrSink,
    out_buf: String,
    err_buf: String,
    stdin: Stdin,
}

static mut STACK: Vec<Frame> = Vec::new();
/// Set when a command wrote to stderr (used as a default non-zero status).
static mut ERR_WRITTEN: bool = false;
/// Explicit status set by the running command.
static mut EXPLICIT_STATUS: Option<i32> = None;

/// Push a new stream frame.
pub fn push(out: Sink, err: ErrSink, stdin: Stdin) {
    unsafe {
        STACK.push(Frame { out, err, out_buf: String::new(), err_buf: String::new(), stdin });
    }
}

/// Pop the current frame; returns (captured stdout, captured stderr).
pub fn pop() -> (String, String) {
    unsafe {
        match STACK.pop() {
            Some(f) => (f.out_buf, f.err_buf),
            None => (String::new(), String::new()),
        }
    }
}

pub fn depth() -> usize {
    unsafe { STACK.len() }
}

/// Drop frames above `n` (error recovery).
pub fn truncate(n: usize) {
    unsafe {
        while STACK.len() > n {
            STACK.pop();
        }
    }
}

/// Index of the frame that owns stdout, starting the search at `from`.
fn out_owner(from: usize) -> Option<usize> {
    unsafe {
        let mut i = from;
        loop {
            if i == 0 { return None; }
            i -= 1;
            if STACK[i].out != Sink::Inherit { return Some(i); }
        }
    }
}

fn err_owner() -> Option<usize> {
    unsafe {
        let mut i = STACK.len();
        loop {
            if i == 0 { return None; }
            i -= 1;
            if STACK[i].err != ErrSink::Inherit { return Some(i); }
        }
    }
}

/// True when stdout is not the console (pipe / capture / redirect).
pub fn out_is_captured() -> bool {
    unsafe {
        match out_owner(STACK.len()) {
            Some(i) => STACK[i].out != Sink::Screen,
            None => false,
        }
    }
}

fn screen_write(s: &str, color: u32) {
    // Large outputs: draw line by line and stop as soon as Ctrl+C is pressed.
    if s.len() > 256 {
        for line in s.split_inclusive('\n') {
            if interrupted() { return; }
            screen_write_raw(line, color);
        }
        return;
    }
    screen_write_raw(s, color);
}

fn screen_write_raw(s: &str, color: u32) {
    // Expand tabs to the next multiple of 8 columns; the font has no tab glyph.
    if !s.contains('\t') {
        framebuffer::draw_string(s, color, BG);
        return;
    }
    for ch in s.chars() {
        if ch == '\t' {
            let (x, _) = framebuffer::cursor_pos();
            let col = (x / framebuffer::CHAR_WIDTH) as usize;
            let n = 8 - (col % 8);
            for _ in 0..n {
                framebuffer::draw_char(' ', color, BG);
            }
        } else {
            framebuffer::draw_char(ch, color, BG);
        }
    }
}

fn write_out_from(from: usize, s: &str, color: u32) {
    unsafe {
        match out_owner(from) {
            None => screen_write(s, color),
            Some(i) => match STACK[i].out {
                Sink::Screen | Sink::Inherit => screen_write(s, color),
                Sink::Capture => STACK[i].out_buf.push_str(s),
                Sink::Null => {}
            },
        }
    }
}

/// Write to stdout with a colour (colour is dropped when captured).
pub fn out_c(s: &str, color: u32) {
    // After Ctrl+C, drop further output so a command that prints a lot
    // stops scrolling the screen immediately (loops also check the flag).
    if interrupted() { return; }
    unsafe { write_out_from(STACK.len(), s, color); }
}

pub fn out(s: &str) { out_c(s, FG); }

/// Write to stderr and mark the running command as failed (unless it sets
/// an explicit status).
pub fn err(s: &str) {
    unsafe { ERR_WRITTEN = true; }
    err_color(s, FG_ERR);
}

/// Write a diagnostic to stderr without marking failure.
pub fn note(s: &str) {
    err_color(s, FG_WARN);
}

fn err_color(s: &str, color: u32) {
    unsafe {
        match err_owner() {
            None => screen_write(s, color),
            Some(i) => match STACK[i].err {
                ErrSink::Screen | ErrSink::Inherit => screen_write(s, color),
                ErrSink::Capture => STACK[i].err_buf.push_str(s),
                ErrSink::Null => {}
                ErrSink::ToOut => write_out_from(i + 1, s, color),
            },
        }
    }
}

// ─── stdin ──────────────────────────────────────────────────────────────────

fn stdin_owner() -> Option<usize> {
    unsafe {
        let mut i = STACK.len();
        loop {
            if i == 0 { return None; }
            i -= 1;
            match STACK[i].stdin {
                Stdin::Inherit => continue,
                _ => return Some(i),
            }
        }
    }
}

/// True if stdin is connected to a pipe or file (not the console).
pub fn has_stdin() -> bool {
    unsafe {
        match stdin_owner() {
            Some(i) => matches!(STACK[i].stdin, Stdin::Data(_, _)),
            None => false,
        }
    }
}

/// Take all remaining stdin text.  Returns None when stdin is the console.
pub fn take_stdin() -> Option<String> {
    unsafe {
        let i = stdin_owner()?;
        match &mut STACK[i].stdin {
            Stdin::Data(s, pos) => {
                let rest = String::from(&s[*pos..]);
                *pos = s.len();
                Some(rest)
            }
            _ => None,
        }
    }
}

/// Read up to `max` bytes of piped / redirected stdin for a ring-3 program.
/// None = stdin is the console; Some(empty) = end of input.
pub fn read_stdin_bytes(max: usize) -> Option<Vec<u8>> {
    unsafe {
        let i = stdin_owner()?;
        match &mut STACK[i].stdin {
            Stdin::Data(s, pos) => {
                let mut end = (*pos + max).min(s.len());
                while end > *pos && !s.is_char_boundary(end) {
                    end -= 1;
                }
                let chunk = Vec::from(s[*pos..end].as_bytes());
                *pos = end;
                Some(chunk)
            }
            _ => None,
        }
    }
}

/// Read one line from stdin (without the newline).
/// Outer None = stdin is the console; inner None = end of input.
pub fn read_stdin_line() -> Option<Option<String>> {
    unsafe {
        let i = stdin_owner()?;
        match &mut STACK[i].stdin {
            Stdin::Data(s, pos) => {
                if *pos >= s.len() {
                    return Some(None);
                }
                let rest = &s[*pos..];
                let (line, adv) = match rest.find('\n') {
                    Some(n) => (&rest[..n], n + 1),
                    None => (rest, rest.len()),
                };
                let line = String::from(line);
                *pos += adv;
                Some(Some(line))
            }
            _ => None,
        }
    }
}

/// Error message used by commands that need stdin when none is connected.
pub fn no_stdin(cmd: &str) {
    err(cmd);
    err(": no input: give a file argument or pipe data in (keyboard stdin is not supported)\n");
}

// ─── Status tracking ────────────────────────────────────────────────────────

pub fn begin_command() {
    unsafe {
        ERR_WRITTEN = false;
        EXPLICIT_STATUS = None;
    }
}

pub fn set_status(code: i32) {
    unsafe { EXPLICIT_STATUS = Some(code); }
}

pub fn end_command() -> i32 {
    unsafe {
        match EXPLICIT_STATUS {
            Some(c) => c,
            None => if ERR_WRITTEN { 1 } else { 0 },
        }
    }
}

// ─── Interrupt (Ctrl+C) ─────────────────────────────────────────────────────

/// Ctrl+C is detected at IRQ time by the keyboard driver
/// (keyboard::interrupt_pending); these are thin wrappers around it.
/// Polling no longer consumes keystrokes.
pub fn poll_interrupt() -> bool {
    crate::arch::x86_64::keyboard::interrupt_pending()
}

pub fn interrupted() -> bool {
    crate::arch::x86_64::keyboard::interrupt_pending()
}

pub fn clear_interrupt() {
    crate::arch::x86_64::keyboard::clear_interrupt();
}

// ─── Console line input (read builtin) ──────────────────────────────────────

/// Read a line from the keyboard with echo.  Returns None on Ctrl+C.
pub fn read_console_line() -> Option<String> {
    let mut line = String::new();
    loop {
        let ch = loop {
            if let Some(c) = crate::arch::x86_64::keyboard::try_read_key() {
                break c;
            }
            unsafe { core::arch::asm!("hlt"); }
        };
        match ch {
            '\n' | '\r' => {
                framebuffer::draw_char('\n', FG, BG);
                return Some(line);
            }
            '\x03' => {
                framebuffer::draw_string("^C\n", FG_DIM, BG);
                return None;
            }
            '\x08' => {
                if line.pop().is_some() {
                    let (x, y) = framebuffer::cursor_pos();
                    if x >= framebuffer::CHAR_WIDTH {
                        let nx = x - framebuffer::CHAR_WIDTH;
                        framebuffer::set_cursor_pos(nx, y);
                        framebuffer::draw_char(' ', FG, BG);
                        framebuffer::set_cursor_pos(nx, y);
                    }
                }
            }
            c if (c as u32) >= 0x20 && (c as u32) < 0x7F => {
                line.push(c);
                framebuffer::draw_char(c, FG, BG);
            }
            _ => {}
        }
    }
}

// ─── Number formatting ──────────────────────────────────────────────────────

pub fn fmt_usize(mut n: usize) -> String {
    if n == 0 { return String::from("0"); }
    let mut buf = [0u8; 20];
    let mut pos = 20;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    String::from(core::str::from_utf8(&buf[pos..]).unwrap_or("0"))
}

pub fn fmt_i64(n: i64) -> String {
    if n < 0 {
        let mut s = String::from("-");
        s.push_str(&fmt_usize(n.unsigned_abs() as usize));
        s
    } else {
        fmt_usize(n as usize)
    }
}
