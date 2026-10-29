/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Console stdin for ring-3 programs: a line discipline over the keyboard.

read(0) from a program run by the shell blocks until a whole line is typed. Keys are echoed
as they are typed; Backspace and Ctrl+U edit the line; Enter ends it (the newline is part
of the data); Ctrl+D on an empty line is end of input, on a non-empty line it ends the line
without a newline. Ctrl+C echoes "^C" and drops the line: the shell sees the interrupt flag
set by the keyboard IRQ and kills the program (see plum/exec.rs), so the blocked read never
returns to it. Piped or redirected stdin is served by plum::io before this code runs.

Only one program owns the keyboard at a time (the shell waits for it). The state is tagged
with the owner pid and starts empty for a new owner.
*/

use alloc::vec::Vec;
use crate::core::sync::{rank, IrqSpinLock};

struct State {
    owner: u32,
    /// Typed characters of the line being edited.
    edit: Vec<u8>,
    /// Finished line waiting to be read.
    ready: Vec<u8>,
    pos: usize,
    /// Ctrl+D on an empty line: the next read returns 0.
    eof: bool,
}

static STATE: IrqSpinLock<State> = IrqSpinLock::new(
    "STDIN",
    rank::DEV,
    State { owner: 0, edit: Vec::new(), ready: Vec::new(), pos: 0, eof: false },
);

/// Fill `out` (at most `max` bytes) from the console. Blocks until data or end of input.
/// Returns an empty vector at end of input.
pub fn read_console(max: usize) -> Vec<u8> {
    let me = crate::core::scheduler::current_task_id() as u32;
    {
        let mut s = STATE.lock();
        if s.owner != me {
            s.owner = me;
            s.edit.clear();
            s.ready.clear();
            s.pos = 0;
            s.eof = false;
        }
    }
    loop {
        {
            let mut s = STATE.lock();
            if s.pos < s.ready.len() {
                let end = (s.pos + max).min(s.ready.len());
                let chunk = s.ready[s.pos..end].to_vec();
                s.pos = end;
                if s.pos == s.ready.len() {
                    s.ready.clear();
                    s.pos = 0;
                }
                return chunk;
            }
            if s.eof {
                s.eof = false;
                return Vec::new();
            }
        }
        match crate::arch::x86_64::keyboard::try_read_key() {
            Some(ch) => feed(ch),
            None => crate::core::scheduler::sys_yield(),
        }
    }
}

/// Apply one typed key to the line being edited.
fn feed(ch: char) {
    use crate::userspace::plum::io;
    match ch {
        '\n' | '\r' => {
            io::echo("\n");
            let mut s = STATE.lock();
            let mut line = core::mem::take(&mut s.edit);
            line.push(b'\n');
            s.ready = line;
            s.pos = 0;
        }
        '\x04' => {
            let mut s = STATE.lock();
            if s.edit.is_empty() {
                s.eof = true;
            } else {
                let line = core::mem::take(&mut s.edit);
                s.ready = line;
                s.pos = 0;
            }
        }
        '\x03' => {
            STATE.lock().edit.clear();
            io::echo_interrupt();
        }
        '\x08' | '\x7f' => {
            let popped = STATE.lock().edit.pop().is_some();
            if popped {
                io::echo_erase();
            }
        }
        '\x15' => {
            let n = core::mem::take(&mut STATE.lock().edit).len();
            for _ in 0..n {
                io::echo_erase();
            }
        }
        c if (c as u32) >= 0x20 && (c as u32) < 0x7F => {
            let full = {
                let mut s = STATE.lock();
                if s.edit.len() < 1024 {
                    s.edit.push(c as u8);
                    false
                } else {
                    true
                }
            };
            if !full {
                let mut tmp = [0u8; 4];
                io::echo(c.encode_utf8(&mut tmp));
            }
        }
        _ => {}
    }
}
