// SPDX-License-Identifier: AGPL-3.0-only
//! BBC Micro keyboard: the key enum the front-end maps PC keys onto, and the 10x8 matrix.

/// A key on the Model B keyboard. The two SHIFT keys of a PC map to `Shift`; `Break` is not a
/// matrix key: pressing it resets the machine (SHIFT held at that moment = auto-boot).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    Shift, Ctrl, CapsLock, ShiftLock, Tab, Escape,
    A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z,
    D0, D1, D2, D3, D4, D5, D6, D7, D8, D9,
    F0, F1, F2, F3, F4, F5, F6, F7, F8, F9,
    /// `-` (`=` on a PC keyboard shares this key with SHIFT)
    Minus,
    /// `^` / `~`
    Caret,
    /// `£` / `_` key
    Underscore,
    /// `@`
    At,
    /// `[` / `{`
    LeftBracket,
    /// `]` / `}`
    RightBracket,
    /// `\` / `|`
    Backslash,
    /// `;` / `+`
    Semicolon,
    /// `:` / `*`
    Colon,
    Comma, Period, Slash, Space,
    Left, Right, Up, Down,
    Copy, Delete, Return,
    Break,
}

impl Key {
    /// (column, row) in the keyboard matrix, None for `Break`.
    pub const fn matrix(self) -> Option<(u8, u8)> {
        use Key::*;
        Some(match self {
            Shift => (0, 0), Ctrl => (1, 0),
            Q => (0, 1), D3 => (1, 1), D4 => (2, 1), D5 => (3, 1), F4 => (4, 1), D8 => (5, 1),
            F7 => (6, 1), Minus => (7, 1), Caret => (8, 1), Left => (9, 1),
            F0 => (0, 2), W => (1, 2), E => (2, 2), T => (3, 2), D7 => (4, 2), I => (5, 2),
            D9 => (6, 2), D0 => (7, 2), Underscore => (8, 2), Down => (9, 2),
            D1 => (0, 3), D2 => (1, 3), D => (2, 3), R => (3, 3), D6 => (4, 3), U => (5, 3),
            O => (6, 3), P => (7, 3), LeftBracket => (8, 3), Up => (9, 3),
            CapsLock => (0, 4), A => (1, 4), X => (2, 4), F => (3, 4), Y => (4, 4), J => (5, 4),
            K => (6, 4), At => (7, 4), Colon => (8, 4), Return => (9, 4),
            ShiftLock => (0, 5), S => (1, 5), C => (2, 5), G => (3, 5), H => (4, 5), N => (5, 5),
            L => (6, 5), Semicolon => (7, 5), RightBracket => (8, 5), Delete => (9, 5),
            Tab => (0, 6), Z => (1, 6), Space => (2, 6), V => (3, 6), B => (4, 6), M => (5, 6),
            Comma => (6, 6), Period => (7, 6), Slash => (8, 6), Copy => (9, 6),
            Escape => (0, 7), F1 => (1, 7), F2 => (2, 7), F3 => (3, 7), F5 => (4, 7), F6 => (5, 7),
            F8 => (6, 7), F9 => (7, 7), Backslash => (8, 7), Right => (9, 7),
            Break => return None,
        })
    }
}

pub struct Keyboard {
    /// Per column, one bit per row (bit set = key down).
    cols: [u8; 10],
    /// Startup DIP links S8..S1 on row 0, columns 2..9 (col 9 = bit 0). All open = mode 7.
    pub links: u8,
}

impl Keyboard {
    pub fn new() -> Self { Keyboard { cols: [0; 10], links: 0 } }

    pub fn set(&mut self, key: Key, down: bool) {
        if let Some((c, r)) = key.matrix() {
            if down { self.cols[c as usize] |= 1 << r } else { self.cols[c as usize] &= !(1 << r) }
        }
    }

    pub fn shift_down(&self) -> bool { self.cols[0] & 1 != 0 }

    /// State of the key at (col,row) as the PA7 sense line sees it, including the DIP links.
    pub fn sense(&self, col: u8, row: u8) -> bool {
        if col > 9 || row > 7 { return false; }
        if row == 0 && col >= 2 { return self.links & (1 << (9 - col)) != 0; }
        self.cols[col as usize] & (1 << row) != 0
    }

    /// Any key on rows 1..7 down in one column (what CA2 sees when the column is selected by hand).
    pub fn col_any(&self, col: u8) -> bool { (col as usize) < 10 && self.cols[col as usize] & 0xFE != 0 }

    /// Any key on rows 1..7 down (row 0 does not raise the autoscan interrupt).
    pub fn any_key(&self) -> bool { self.cols.iter().any(|c| c & 0xFE != 0) }
}
