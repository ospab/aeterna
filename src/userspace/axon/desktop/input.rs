/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Keyboard decoder for the desktop: raw PS/2 set-1 scancodes (USB HID
keyboards inject the same codes) -> key down/up events with modifiers and
US-layout text.  The console's keyboard::try_read_key() only reports key
presses as characters; the desktop needs releases, Alt and Super.
*/

use oos_ui::event::{Event, Key, Modifiers};

static mut EXT: bool = false;
static mut LSHIFT: bool = false;
static mut RSHIFT: bool = false;
static mut CTRL: bool = false;
static mut ALT: bool = false;
static mut META: bool = false;
static mut CAPS: bool = false;

pub fn reset() {
    unsafe {
        EXT = false;
        LSHIFT = false;
        RSHIFT = false;
        CTRL = false;
        ALT = false;
        META = false;
    }
}

fn mods() -> Modifiers {
    unsafe { Modifiers { shift: LSHIFT || RSHIFT, ctrl: CTRL, alt: ALT, meta: META } }
}

const NORMAL: &[u8; 0x3A] = b"\x00\x001234567890-=\x08\tqwertyuiop[]\n\x00asdfghjkl;'`\x00\\zxcvbnm,./\x00*\x00 ";
const SHIFTED: &[u8; 0x3A] = b"\x00\x00!@#$%^&*()_+\x08\tQWERTYUIOP{}\n\x00ASDFGHJKL:\"~\x00|ZXCVBNM<>?\x00*\x00 ";

/// Next keyboard event, if any.
pub fn poll_key() -> Option<Event> {
    crate::xhci::poll(true);
    loop {
        let sc = crate::arch::x86_64::idt::kb_irq_read()?;
        if sc == 0xE0 {
            unsafe { EXT = true; }
            continue;
        }
        let ext = unsafe { core::mem::replace(&mut EXT, false) };
        let up = sc & 0x80 != 0;
        let code = sc & 0x7F;
        let key = if ext {
            match code {
                0x1C => Key::Enter,
                0x1D => { unsafe { CTRL = !up; } Key::Ctrl }
                0x38 => { unsafe { ALT = !up; } Key::Alt }
                0x47 => Key::Home,
                0x48 => Key::Up,
                0x49 => Key::PageUp,
                0x4B => Key::Left,
                0x4D => Key::Right,
                0x4F => Key::End,
                0x50 => Key::Down,
                0x51 => Key::PageDown,
                0x53 => Key::Delete,
                0x5B | 0x5C => { unsafe { META = !up; } Key::Meta }
                0x35 => Key::Char('/'),
                _ => continue,
            }
        } else {
            match code {
                0x01 => Key::Escape,
                0x0E => Key::Backspace,
                0x0F => Key::Tab,
                0x1C => Key::Enter,
                0x1D => { unsafe { CTRL = !up; } Key::Ctrl }
                0x2A => { unsafe { LSHIFT = !up; } Key::Shift }
                0x36 => { unsafe { RSHIFT = !up; } Key::Shift }
                0x38 => { unsafe { ALT = !up; } Key::Alt }
                0x3A => { if !up { unsafe { CAPS = !CAPS; } } continue; }
                0x3B..=0x44 => Key::F(code - 0x3A),
                0x57 => Key::F(11),
                0x58 => Key::F(12),
                0x47 => Key::Home,
                0x48 => Key::Up,
                0x49 => Key::PageUp,
                0x4B => Key::Left,
                0x4D => Key::Right,
                0x4F => Key::End,
                0x50 => Key::Down,
                0x51 => Key::PageDown,
                0x53 => Key::Delete,
                c if (c as usize) < NORMAL.len() && NORMAL[c as usize] >= 0x20 => {
                    let m = mods();
                    let mut ch = if m.shift { SHIFTED[c as usize] } else { NORMAL[c as usize] } as char;
                    if unsafe { CAPS } && ch.is_ascii_alphabetic() {
                        ch = if m.shift { ch.to_ascii_lowercase() } else { ch.to_ascii_uppercase() };
                    }
                    Key::Char(ch)
                }
                _ => continue,
            }
        };
        let m = mods();
        if up {
            return Some(Event::KeyUp { key, mods: m });
        }
        let text = match key {
            Key::Char(c) if !m.ctrl && !m.alt => Some(c),
            _ => None,
        };
        // Ctrl+letter arrives as the lowercase letter with mods.ctrl.
        let key = match key {
            Key::Char(c) if m.ctrl => Key::Char(c.to_ascii_lowercase()),
            k => k,
        };
        return Some(Event::KeyDown { key, mods: m, text });
    }
}
