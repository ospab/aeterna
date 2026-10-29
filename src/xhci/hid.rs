/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
USB HID boot-protocol report decoding.

Keyboard reports are translated into PS/2 scancode set 1 and injected into the
same ring buffer the IRQ1 handler fills (idt::kb_buffer_write), so every
consumer of arch::x86_64::keyboard (shell, editor, installer, DOOM) works
unchanged. Mouse reports go to arch::x86_64::mouse::inject.
*/

use crate::arch::x86_64::{idt, mouse};

/// Delay before auto-repeat starts and the repeat period (PS/2 typematic defaults).
const REPEAT_DELAY_US: u64 = 500_000;
const REPEAT_PERIOD_US: u64 = 33_000;

/// Per-keyboard decoder state.
#[derive(Clone, Copy)]
pub struct KbdState {
    prev: [u8; 8],
    /// Key being auto-repeated: (extended, set-1 make code), 0 = none.
    rep_ext: bool,
    rep_code: u8,
    rep_usage: u8,
    rep_at: u64,
}

impl KbdState {
    pub const fn new() -> Self {
        KbdState { prev: [0; 8], rep_ext: false, rep_code: 0, rep_usage: 0, rep_at: 0 }
    }
}

/// Modifier bit (report byte 0) to set-1 (extended, make code).
const MODS: [(bool, u8); 8] = [
    (false, 0x1D), // LCtrl
    (false, 0x2A), // LShift
    (false, 0x38), // LAlt
    (true, 0x5B),  // LGui
    (true, 0x1D),  // RCtrl
    (false, 0x36), // RShift
    (true, 0x38),  // RAlt
    (true, 0x5C),  // RGui
];

/// HID keyboard usage (page 0x07) to PS/2 set-1 (extended, make code).
fn usage_to_set1(u: u8) -> Option<(bool, u8)> {
    const LETTERS: [u8; 26] = [
        0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32,
        0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
    ];
    const KP: [u8; 10] = [0x52, 0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49];
    let r = match u {
        0x04..=0x1D => (false, LETTERS[(u - 0x04) as usize]),
        0x1E..=0x27 => (false, 0x02 + (u - 0x1E)), // 1..9, 0
        0x28 => (false, 0x1C), // Enter
        0x29 => (false, 0x01), // Esc
        0x2A => (false, 0x0E), // Backspace
        0x2B => (false, 0x0F), // Tab
        0x2C => (false, 0x39), // Space
        0x2D => (false, 0x0C), // -
        0x2E => (false, 0x0D), // =
        0x2F => (false, 0x1A), // [
        0x30 => (false, 0x1B), // ]
        0x31 | 0x32 => (false, 0x2B), // \ and non-US #
        0x33 => (false, 0x27), // ;
        0x34 => (false, 0x28), // '
        0x35 => (false, 0x29), // `
        0x36 => (false, 0x33), // ,
        0x37 => (false, 0x34), // .
        0x38 => (false, 0x35), // /
        0x39 => (false, 0x3A), // Caps Lock
        0x3A..=0x43 => (false, 0x3B + (u - 0x3A)), // F1..F10
        0x44 => (false, 0x57), // F11
        0x45 => (false, 0x58), // F12
        0x46 => (true, 0x37),  // Print Screen
        0x47 => (false, 0x46), // Scroll Lock
        0x49 => (true, 0x52),  // Insert
        0x4A => (true, 0x47),  // Home
        0x4B => (true, 0x49),  // Page Up
        0x4C => (true, 0x53),  // Delete
        0x4D => (true, 0x4F),  // End
        0x4E => (true, 0x51),  // Page Down
        0x4F => (true, 0x4D),  // Right
        0x50 => (true, 0x4B),  // Left
        0x51 => (true, 0x50),  // Down
        0x52 => (true, 0x48),  // Up
        0x53 => (false, 0x45), // Num Lock
        0x54 => (true, 0x35),  // KP /
        0x55 => (false, 0x37), // KP *
        0x56 => (false, 0x4A), // KP -
        0x57 => (false, 0x4E), // KP +
        0x58 => (true, 0x1C),  // KP Enter
        0x59..=0x61 => (false, KP[(u - 0x59 + 1) as usize]), // KP 1..9
        0x62 => (false, KP[0]),
        0x63 => (false, 0x53), // KP .
        0x64 => (false, 0x56), // non-US \
        _ => return None,
    };
    Some(r)
}

/// Write one key event (make or break) into the keyboard buffer atomically
/// with respect to the PS/2 IRQ handler (E0 prefix + code must stay adjacent).
fn emit(ext: bool, code: u8, release: bool) {
    let code = if release { code | 0x80 } else { code };
    let flags: u64;
    // SAFETY: save RFLAGS and disable interrupts for the two buffer writes.
    unsafe { core::arch::asm!("pushfq; pop {}; cli", out(reg) flags, options()); }
    if ext {
        idt::kb_buffer_write(0xE0);
    }
    idt::kb_buffer_write(code);
    if flags & (1 << 9) != 0 {
        // SAFETY: interrupts were enabled on entry.
        unsafe { core::arch::asm!("sti", options(nostack)); }
    }
}

fn is_modifier_usage(u: u8) -> bool {
    (0xE0..=0xE7).contains(&u)
}

/// Decode a boot-protocol keyboard report (8 bytes: mods, reserved, 6 keys).
pub fn kbd_report(st: &mut KbdState, rep: &[u8], now_us: u64) {
    if rep.len() < 3 {
        return;
    }
    let mut cur = [0u8; 8];
    let n = rep.len().min(8);
    cur[..n].copy_from_slice(&rep[..n]);

    // Phantom state / rollover error: every key reads 0x01. Keep the old state.
    if cur[2] == 0x01 {
        return;
    }

    let old_mods = st.prev[0];
    let new_mods = cur[0];

    // Releases first: ordinary keys, then modifiers.
    for i in 2..8 {
        let k = st.prev[i];
        if k > 3 && !cur[2..8].contains(&k) {
            if let Some((ext, code)) = usage_to_set1(k) {
                emit(ext, code, true);
            }
            if st.rep_usage == k {
                st.rep_code = 0;
                st.rep_usage = 0;
            }
        }
    }
    for b in 0..8 {
        let bit = 1u8 << b;
        if old_mods & bit != 0 && new_mods & bit == 0 {
            emit(MODS[b].0, MODS[b].1, true);
        }
    }

    // Presses: modifiers first so Shift+key arrives in the right order.
    for b in 0..8 {
        let bit = 1u8 << b;
        if old_mods & bit == 0 && new_mods & bit != 0 {
            emit(MODS[b].0, MODS[b].1, false);
        }
    }
    for i in 2..8 {
        let k = cur[i];
        if k > 3 && !st.prev[2..8].contains(&k) && !is_modifier_usage(k) {
            if let Some((ext, code)) = usage_to_set1(k) {
                emit(ext, code, false);
                // The newest key is the one that repeats (as with PS/2 typematic).
                st.rep_ext = ext;
                st.rep_code = code;
                st.rep_usage = k;
                st.rep_at = now_us + REPEAT_DELAY_US;
            }
        }
    }
    st.prev = cur;
}

/// USB keyboards report only on change; typematic repeat is up to the host.
pub fn kbd_repeat(st: &mut KbdState, now_us: u64) {
    if st.rep_code == 0 || now_us < st.rep_at {
        return;
    }
    emit(st.rep_ext, st.rep_code, false);
    // At most one repeat per poll; never try to catch up on missed periods.
    st.rep_at = now_us + REPEAT_PERIOD_US;
}

/// True while a key is waiting to auto-repeat.
pub fn kbd_repeating(st: &KbdState) -> bool {
    st.rep_code != 0
}

/// Forget held keys (device removed or recovered).
pub fn kbd_reset(st: &mut KbdState) {
    let prev = st.prev;
    for i in 2..8 {
        let k = prev[i];
        if k > 3 {
            if let Some((ext, code)) = usage_to_set1(k) {
                emit(ext, code, true);
            }
        }
    }
    for b in 0..8 {
        if prev[0] & (1 << b) != 0 {
            emit(MODS[b].0, MODS[b].1, true);
        }
    }
    *st = KbdState::new();
}

/// Decode a boot-protocol mouse report: buttons, dX, dY, [wheel].
pub fn mouse_report(rep: &[u8]) {
    if rep.len() < 3 {
        return;
    }
    let btns = rep[0] & 0x07;
    let dx = rep[1] as i8 as i32;
    // USB: +Y is down. mouse.rs follows the PS/2 convention (+Y is up).
    let dy = -(rep[2] as i8 as i32);
    mouse::inject(dx, dy, btns);
}
