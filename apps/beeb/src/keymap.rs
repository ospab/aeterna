// SPDX-License-Identifier: AGPL-3.0-only
//! PC (set-1 scancode) to BBC keyboard. Positional layout: the PC key in the place of the BBC
//! key. Table in docs/en/beeb.md.

use beeb_core::keyboard::Key;

/// BBC key for a PC key, or `None`. F11/F12 are handled by the front end.
pub fn map(code: u8, extended: bool) -> Option<Key> {
    if extended {
        return match code {
            0x48 => Some(Key::Up), // Up
            0x50 => Some(Key::Down), // Down
            0x4B => Some(Key::Left), // Left
            0x4D => Some(Key::Right), // Right
            0x4F => Some(Key::Copy), // End = COPY
            0x53 => Some(Key::Delete), // Delete = DELETE
            0x1D => Some(Key::Ctrl), // right Ctrl
            0x52 => Some(Key::Underscore), // Insert = pound/underscore key
            0x1C => Some(Key::Return), // keypad Enter = RETURN
            _ => None,
        };
    }
    Some(match code {
        0x01 => Key::Escape, // Esc = ESCAPE
        0x02 => Key::D1, // 1
        0x03 => Key::D2, // 2
        0x04 => Key::D3, // 3
        0x05 => Key::D4, // 4
        0x06 => Key::D5, // 5
        0x07 => Key::D6, // 6
        0x08 => Key::D7, // 7
        0x09 => Key::D8, // 8
        0x0A => Key::D9, // 9
        0x0B => Key::D0, // 0
        0x0C => Key::Minus, // -
        0x0D => Key::Caret, // = -> ^
        0x0E => Key::Delete, // Backspace = DELETE
        0x0F => Key::Tab, // Tab
        0x10 => Key::Q, // Q
        0x11 => Key::W, // W
        0x12 => Key::E, // E
        0x13 => Key::R, // R
        0x14 => Key::T, // T
        0x15 => Key::Y, // Y
        0x16 => Key::U, // U
        0x17 => Key::I, // I
        0x18 => Key::O, // O
        0x19 => Key::P, // P
        0x1A => Key::LeftBracket, // [
        0x1B => Key::RightBracket, // ]
        0x1C => Key::Return, // Enter = RETURN
        0x1D => Key::Ctrl, // left Ctrl
        0x1E => Key::A, // A
        0x1F => Key::S, // S
        0x20 => Key::D, // D
        0x21 => Key::F, // F
        0x22 => Key::G, // G
        0x23 => Key::H, // H
        0x24 => Key::J, // J
        0x25 => Key::K, // K
        0x26 => Key::L, // L
        0x27 => Key::Semicolon, // ;
        0x28 => Key::Colon, // ' -> :
        0x29 => Key::At, // ` -> @
        0x2A | 0x36 => Key::Shift,
        0x2B => Key::Backslash, // backslash
        0x2C => Key::Z, // Z
        0x2D => Key::X, // X
        0x2E => Key::C, // C
        0x2F => Key::V, // V
        0x30 => Key::B, // B
        0x31 => Key::N, // N
        0x32 => Key::M, // M
        0x33 => Key::Comma, // ,
        0x34 => Key::Period, // .
        0x35 => Key::Slash, // /
        0x38 => Key::Underscore, // Alt -> pound? no: unused on BBC; map to left alt = nothing
        0x39 => Key::Space, // Space
        0x3A => Key::CapsLock, // Caps Lock = CAPS LOCK
        0x3B => Key::F0, // F1 = f0
        0x3C => Key::F1, // F2 = f1
        0x3D => Key::F2, // F3 = f2
        0x3E => Key::F3, // F4 = f3
        0x3F => Key::F4, // F5 = f4
        0x40 => Key::F5, // F6 = f5
        0x41 => Key::F6, // F7 = f6
        0x42 => Key::F7, // F8 = f7
        0x43 => Key::F8, // F9 = f8
        0x44 => Key::F9, // F10 = f9
        0x46 => Key::ShiftLock, // Scroll Lock = SHIFT LOCK
        _ => return None,
    })
}
