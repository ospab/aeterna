/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
PS/2 keyboard driver: interrupt-driven via IRQ1 buffer + scancode decoding.
US QWERTY layout. Supports Shift, CapsLock, Ctrl+C, Backspace, Tab, Escape.
Extended scancodes: arrow keys (Up/Down/Left/Right), Home, End, Delete.
Full scancode set 1 translation.
*/

use core::arch::asm;

// Special key codes (non-ASCII, above 0x7F)
pub const KEY_UP: char    = '\u{0080}';
pub const KEY_DOWN: char  = '\u{0081}';
pub const KEY_LEFT: char  = '\u{0082}';
pub const KEY_RIGHT: char = '\u{0083}';
pub const KEY_HOME: char  = '\u{0084}';
pub const KEY_END: char   = '\u{0085}';
pub const KEY_DELETE: char = '\u{007F}';
pub const KEY_PGUP: char  = '\u{0086}';
pub const KEY_PGDN: char  = '\u{0087}';
pub const KEY_F1: char    = '\u{0088}';
pub const KEY_F2: char    = '\u{0089}';
pub const KEY_F3: char    = '\u{008A}';
pub const KEY_F4: char    = '\u{008B}';
pub const KEY_F5: char    = '\u{008C}';
pub const KEY_F6: char    = '\u{008D}';
pub const KEY_F7: char    = '\u{008E}';
pub const KEY_F8: char    = '\u{008F}';
pub const KEY_F9: char    = '\u{0090}';
pub const KEY_F10: char   = '\u{0091}';

// Modifier key state
static LEFT_SHIFT: AtomicBool = AtomicBool::new(false);
static RIGHT_SHIFT: AtomicBool = AtomicBool::new(false);
static CTRL_PRESSED: AtomicBool = AtomicBool::new(false);
static CAPS_LOCK: AtomicBool = AtomicBool::new(false);
static EXTENDED: AtomicBool = AtomicBool::new(false); // 0xE0 prefix seen

// ─── Ctrl+C as an interrupt (seen at IRQ time) ──────────────────────────────
//
// The IRQ1 handler passes every raw scancode to `irq_scancode()`.  When it
// sees Ctrl+C it sets INTERRUPT_PENDING, so long-running commands notice it
// even though they never read the keyboard queue.  The '\x03' character is
// still queued as before, so line editing at the prompt keeps working.

use core::sync::atomic::{AtomicBool, Ordering};

static INTERRUPT_PENDING: AtomicBool = AtomicBool::new(false);
static IRQ_CTRL_DOWN: AtomicBool = AtomicBool::new(false);

/// Called from the keyboard IRQ handler (and USB HID injection) with each raw
/// set-1 scancode. Must stay tiny: it runs in interrupt context.
#[inline]
pub fn irq_scancode(sc: u8) {
    match sc {
        0x1D => IRQ_CTRL_DOWN.store(true, Ordering::Relaxed),  // (left or E0-prefixed right) Ctrl down
        0x9D => IRQ_CTRL_DOWN.store(false, Ordering::Relaxed), // Ctrl up
        0x2E if IRQ_CTRL_DOWN.load(Ordering::Relaxed) => INTERRUPT_PENDING.store(true, Ordering::Relaxed),
        _ => {}
    }
}

/// Has Ctrl+C been pressed since the flag was last cleared?
#[inline]
pub fn interrupt_pending() -> bool {
    crate::xhci::poll(false); // USB keyboards have no IRQ: service them here too
    INTERRUPT_PENDING.load(Ordering::Relaxed)
}

/// Return and clear the Ctrl+C flag.
#[inline]
pub fn take_interrupt() -> bool {
    INTERRUPT_PENDING.swap(false, Ordering::Relaxed)
}

/// Clear the Ctrl+C flag (the shell does this before each new command).
#[inline]
pub fn clear_interrupt() {
    INTERRUPT_PENDING.store(false, Ordering::Relaxed);
}

/// Initialize keyboard: drain pending scancodes from IRQ buffer
pub fn init() {
    while crate::arch::x86_64::idt::kb_irq_read().is_some() {}
}

/// Poll for key press (blocking). Returns decoded char.
pub fn poll_key() -> Option<char> {
    loop {
        if let Some(c) = try_read_key() {
            return Some(c);
        }
        unsafe { asm!("hlt"); }
    }
}

/// Try to read a key (non-blocking). Returns None if no key available.
// ─── Pasted text and serial input ───────────────────────────────────────────
//
// Ctrl+V pastes the host clipboard (VMware backdoor, drivers/gpu/vmclip.rs) by
// queueing its text here; bytes arriving on COM1 are typed too, so a terminal on the
// serial line (PuTTY on a VMware named pipe, QEMU -serial stdio) can paste anywhere.

const PASTE_CAP: usize = 4096;

/// Ring of pasted bytes, lock class DEV.
struct Paste {
    buf: [u8; PASTE_CAP],
    head: usize,
    len: usize,
}

static PASTE: crate::core::sync::IrqSpinLock<Paste> = crate::core::sync::IrqSpinLock::new(
    "PASTE",
    crate::core::sync::rank::DEV,
    Paste { buf: [0; PASTE_CAP], head: 0, len: 0 },
);

/// Queue text to be read as if typed. Line breaks become spaces and trailing
/// whitespace is dropped, so a pasted link never runs a command by itself.
pub fn inject_text(text: &str) {
    // Line breaks become Enter, as in other terminals; the trailing one is dropped so the
    // last pasted line stays in the editor instead of running at once.
    let text = text.trim_end();
    let mut p = PASTE.lock();
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if p.len >= PASTE_CAP { break; }
        let b = match b {
            b'\r' if bytes.get(i + 1) == Some(&b'\n') => continue,
            b'\r' | b'\n' => b'\n',
            b'\t' => b' ',
            b => b,
        };
        let at = (p.head + p.len) % PASTE_CAP;
        p.buf[at] = b;
        p.len += 1;
    }
}

fn pop_pasted() -> Option<char> {
    loop {
        let b = {
            let mut p = PASTE.lock();
            if p.len == 0 { return None; }
            let b = p.buf[p.head];
            p.head = (p.head + 1) % PASTE_CAP;
            p.len -= 1;
            b
        };
        // Non-ASCII bytes of UTF-8 text are dropped: the console line editor is ASCII.
        if b.is_ascii() { return Some(b as char); }
    }
}

fn serial_key() -> Option<char> {
    match crate::arch::x86_64::serial::try_read_byte()? {
        b'\r' => Some('\n'),
        0x7F => Some('\x08'),
        0x03 => { INTERRUPT_PENDING.store(true, Ordering::Relaxed); Some('\x03') }
        b if b.is_ascii() => Some(b as char),
        _ => None,
    }
}

pub fn try_read_key() -> Option<char> {
    if let Some(c) = pop_pasted() { return Some(c); }
    if let Some(c) = serial_key() { return Some(c); }
    crate::xhci::poll(true); // USB HID keyboards inject set-1 scancodes into the same buffer
    let scancode = crate::arch::x86_64::idt::kb_irq_read()?;

    // Extended scancode prefix
    if scancode == 0xE0 {
        unsafe { EXTENDED.store(true, Ordering::Relaxed); }
        return None;
    }

    let is_extended = EXTENDED.load(Ordering::Relaxed);
    unsafe { EXTENDED.store(false, Ordering::Relaxed); }

    // Right Ctrl (E0 1D / E0 9D) acts like Left Ctrl
    if is_extended && (scancode == 0x1D || scancode == 0x9D) {
        unsafe { CTRL_PRESSED.store(scancode == 0x1D, Ordering::Relaxed); }
        return None;
    }

    // Handle extended key releases (ignore)
    if is_extended && scancode & 0x80 != 0 {
        return None;
    }

    // Handle extended key presses
    if is_extended {
        return match scancode {
            0x48 => Some(KEY_UP),
            0x50 => Some(KEY_DOWN),
            0x4B => Some(KEY_LEFT),
            0x4D => Some(KEY_RIGHT),
            0x47 => Some(KEY_HOME),
            0x4F => Some(KEY_END),
            0x53 => Some(KEY_DELETE),
            0x1C => Some('\n'), // keypad Enter
            0x35 => Some('/'),   // keypad /
            0x49 => Some(KEY_PGUP),
            0x51 => Some(KEY_PGDN),
            _ => None,
        };
    }

    // Standard modifier handling
    unsafe {
        match scancode {
            0x2A => { LEFT_SHIFT.store(true, Ordering::Relaxed); return None; }
            0xAA => { LEFT_SHIFT.store(false, Ordering::Relaxed); return None; }
            0x36 => { RIGHT_SHIFT.store(true, Ordering::Relaxed); return None; }
            0xB6 => { RIGHT_SHIFT.store(false, Ordering::Relaxed); return None; }
            0x1D => { CTRL_PRESSED.store(true, Ordering::Relaxed); return None; }
            0x9D => { CTRL_PRESSED.store(false, Ordering::Relaxed); return None; }
            0x3A => { CAPS_LOCK.fetch_xor(true, Ordering::Relaxed); return None; }
            _ => {}
        }
    }

    // Ignore releases
    if scancode & 0x80 != 0 {
        return None;
    }

    // Ctrl combos
    unsafe {
        if CTRL_PRESSED.load(Ordering::Relaxed) {
            return match scancode {
                0x1E => Some('\x01'), // Ctrl+A
                0x30 => Some('\x02'), // Ctrl+B
                0x2E => Some('\x03'), // Ctrl+C
                0x20 => Some('\x04'), // Ctrl+D (EOF)
                0x12 => Some('\x05'), // Ctrl+E
                0x21 => Some('\x06'), // Ctrl+F
                0x22 => Some('\x07'), // Ctrl+G
                0x23 => Some('\x08'), // Ctrl+H (same as Backspace)
                0x25 => Some('\x0B'), // Ctrl+K
                0x26 => Some('\x0C'), // Ctrl+L
                0x31 => Some('\x0E'), // Ctrl+N
                0x18 => Some('\x0F'), // Ctrl+O
                0x19 => Some('\x10'), // Ctrl+P
                0x13 => Some('\x12'), // Ctrl+R
                0x1F => Some('\x13'), // Ctrl+S
                0x14 => Some('\x14'), // Ctrl+T
                0x16 => Some('\x15'), // Ctrl+U
                // Ctrl+V: paste the host clipboard when there is one (VMware), else the raw key
                0x2F => match crate::drivers::gpu::vmclip::host_text() {
                    Some(text) => { inject_text(&text); pop_pasted().or(Some('\x16')) }
                    None => Some('\x16'),
                },
                0x11 => Some('\x17'), // Ctrl+W
                0x2D => Some('\x18'), // Ctrl+X
                0x15 => Some('\x19'), // Ctrl+Y
                0x2C => Some('\x1A'), // Ctrl+Z
                _ => None,
            };
        }
    }

    let shift_active = (LEFT_SHIFT.load(Ordering::Relaxed) || RIGHT_SHIFT.load(Ordering::Relaxed));
    let caps_active = CAPS_LOCK.load(Ordering::Relaxed);

    let base = match scancode {
        0x01 => Some('\x1B'), // Escape
        0x02 => Some('1'),
        0x03 => Some('2'),
        0x04 => Some('3'),
        0x05 => Some('4'),
        0x06 => Some('5'),
        0x07 => Some('6'),
        0x08 => Some('7'),
        0x09 => Some('8'),
        0x0A => Some('9'),
        0x0B => Some('0'),
        0x0C => Some('-'),
        0x0D => Some('='),
        0x0E => Some('\x08'), // Backspace
        0x0F => Some('\t'),   // Tab
        0x10 => Some('q'),
        0x11 => Some('w'),
        0x12 => Some('e'),
        0x13 => Some('r'),
        0x14 => Some('t'),
        0x15 => Some('y'),
        0x16 => Some('u'),
        0x17 => Some('i'),
        0x18 => Some('o'),
        0x19 => Some('p'),
        0x1A => Some('['),
        0x1B => Some(']'),
        0x1C => Some('\n'),
        0x1E => Some('a'),
        0x1F => Some('s'),
        0x20 => Some('d'),
        0x21 => Some('f'),
        0x22 => Some('g'),
        0x23 => Some('h'),
        0x24 => Some('j'),
        0x25 => Some('k'),
        0x26 => Some('l'),
        0x27 => Some(';'),
        0x28 => Some('\''),
        0x29 => Some('`'),
        0x2B => Some('\\'),
        0x2C => Some('z'),
        0x2D => Some('x'),
        0x2E => Some('c'),
        0x2F => Some('v'),
        0x30 => Some('b'),
        0x31 => Some('n'),
        0x32 => Some('m'),
        0x33 => Some(','),
        0x34 => Some('.'),
        0x35 => Some('/'),
        0x37 => Some('*'),
        0x39 => Some(' '),
        0x3B => Some(KEY_F1),  // F1
        0x3C => Some(KEY_F2),  // F2
        0x3D => Some(KEY_F3),  // F3
        0x3E => Some(KEY_F4),  // F4
        0x3F => Some(KEY_F5),  // F5
        0x40 => Some(KEY_F6),  // F6
        0x41 => Some(KEY_F7),  // F7
        0x42 => Some(KEY_F8),  // F8
        0x43 => Some(KEY_F9),  // F9
        0x44 => Some(KEY_F10), // F10
        _ => None,
    };

    base.map(|c| {
        if c.is_ascii_alphabetic() {
            let upper = caps_active ^ shift_active;
            if upper { c.to_ascii_uppercase() } else { c }
        } else if shift_active {
            shift_symbol(c)
        } else {
            c
        }
    })
}

fn shift_symbol(c: char) -> char {
    match c {
        '1' => '!', '2' => '@', '3' => '#', '4' => '$', '5' => '%',
        '6' => '^', '7' => '&', '8' => '*', '9' => '(', '0' => ')',
        '-' => '_', '=' => '+', '[' => '{', ']' => '}', '\\' => '|',
        ';' => ':', '\'' => '"', '`' => '~', ',' => '<', '.' => '>',
        '/' => '?',
        _ => c,
    }
}

// ─── Raw key events for ring-3 programs (syscalls 263/264) ──────────────────
//
// A program that switches to raw mode gets the set-1 scancodes as press/release events
// instead of the console line discipline. Ctrl+C still sets the interrupt flag at IRQ time
// (`irq_scancode`), so the shell kills the program as usual. Only one raw owner at a time;
// the kernel drops the mode when the owner exits.

static RAW_OWNER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static RAW_EXT: AtomicBool = AtomicBool::new(false);

/// Pid in raw keyboard mode, or 0.
pub fn raw_owner() -> u32 {
    RAW_OWNER.load(Ordering::Relaxed)
}

/// Enter raw mode as `pid`. False if another process holds it.
pub fn raw_acquire(pid: u32) -> bool {
    if RAW_OWNER.compare_exchange(0, pid, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        return RAW_OWNER.load(Ordering::Relaxed) == pid;
    }
    RAW_EXT.store(false, Ordering::Relaxed);
    while crate::arch::x86_64::idt::kb_irq_read().is_some() {}
    true
}

/// Leave raw mode if `pid` owns it; the queue is flushed so stale keys do not reach the shell.
pub fn raw_release(pid: u32) -> bool {
    if RAW_OWNER.compare_exchange(pid, 0, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
        RAW_EXT.store(false, Ordering::Relaxed);
        while crate::arch::x86_64::idt::kb_irq_read().is_some() {}
        true
    } else {
        false
    }
}

/// Next raw event: scancode (bits 0..7, never 0), bit 8 = E0-extended, bit 9 = release.
/// 0 when the queue is empty.
pub fn raw_event() -> i64 {
    crate::xhci::poll(true);
    while let Some(sc) = crate::arch::x86_64::idt::kb_irq_read() {
        if sc == 0xE0 {
            RAW_EXT.store(true, Ordering::Relaxed);
            continue;
        }
        let ext = RAW_EXT.swap(false, Ordering::Relaxed);
        let code = (sc & 0x7F) as i64;
        if code == 0 {
            continue;
        }
        return code | ((ext as i64) << 8) | (((sc & 0x80 != 0) as i64) << 9);
    }
    0
}
