/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
`Term` for the UEFI text console (SimpleTextOutput / SimpleTextInput).
*/
use core::ptr;

use crate::console::{bs, st};
use crate::efi::*;
use crate::menu::{Key, Term};

pub struct UefiTerm {
    timer: Event,
    cols: usize,
    rows: usize,
}

impl UefiTerm {
    pub fn new() -> Self {
        let mut timer: Event = ptr::null_mut();
        unsafe {
            (bs().create_event)(EVT_TIMER, 0, ptr::null_mut(), ptr::null_mut(), &mut timer);
            let out = st().con_out;
            // Use the largest text mode the firmware offers up to 100x31: bigger menus, same code.
            let (mut best, mut bc, mut br) = ((*(*out).mode).mode as usize, 80usize, 25usize);
            let max = (*(*out).mode).max_mode as usize;
            let cur = (*(*out).mode).mode as usize;
            let (mut cc, mut cr) = (80usize, 25usize);
            if !is_error(((*out).query_mode)(out, cur, &mut cc, &mut cr)) {
                bc = cc;
                br = cr;
            }
            let _ = (&mut best, max);
            UefiTerm { timer, cols: bc.max(40), rows: br.max(15) }
        }
    }

    fn key_from(k: &InputKey) -> Key {
        match k.scan_code {
            SCAN_UP => return Key::Up,
            SCAN_DOWN => return Key::Down,
            SCAN_LEFT => return Key::Left,
            SCAN_RIGHT => return Key::Right,
            SCAN_HOME => return Key::Home,
            SCAN_END => return Key::End,
            SCAN_DELETE => return Key::Delete,
            SCAN_ESC => return Key::Esc,
            _ => {}
        }
        match k.unicode_char {
            0x0D | 0x0A => Key::Enter,
            0x08 => Key::Backspace,
            0x1B => Key::Esc,
            0 => Key::Other,
            c => char::from_u32(c as u32).map_or(Key::Other, Key::Char),
        }
    }
}

impl Term for UefiTerm {
    fn size(&self) -> (usize, usize) {
        (self.cols, self.rows)
    }

    fn clear(&mut self, attr: u8) {
        unsafe {
            let out = st().con_out;
            ((*out).set_attribute)(out, attr as usize);
            ((*out).clear_screen)(out);
        }
    }

    fn put(&mut self, row: usize, col: usize, s: &str, attr: u8) {
        if row >= self.rows || col >= self.cols {
            return;
        }
        // Never write the last cell of the last row: it would scroll the screen.
        let room = self.cols - col - if row + 1 == self.rows { 1 } else { 0 };
        let mut buf = [0u16; 160];
        let mut n = 0;
        for c in s.chars().take(room.min(buf.len() - 1)) {
            buf[n] = if (' '..='~').contains(&c) { c as u16 } else { b'?' as u16 };
            n += 1;
        }
        buf[n] = 0;
        unsafe {
            let out = st().con_out;
            ((*out).set_cursor_position)(out, col, row);
            ((*out).set_attribute)(out, attr as usize);
            ((*out).output_string)(out, buf.as_ptr());
        }
    }

    fn set_cursor(&mut self, row: usize, col: usize, visible: bool) {
        unsafe {
            let out = st().con_out;
            ((*out).set_cursor_position)(out, col, row);
            ((*out).enable_cursor)(out, visible);
        }
    }

    fn wait_key(&mut self, ms: u32) -> Option<Key> {
        unsafe {
            (bs().set_timer)(self.timer, TIMER_RELATIVE, ms as u64 * 10_000);
            loop {
                let events = [(*st().con_in).wait_for_key, self.timer];
                let mut index = 0usize;
                (bs().wait_for_event)(2, events.as_ptr(), &mut index);
                if index == 1 {
                    return None;
                }
                if let Some(k) = self.poll_key() {
                    (bs().set_timer)(self.timer, 0, 0);
                    return Some(k);
                }
            }
        }
    }

    fn poll_key(&mut self) -> Option<Key> {
        unsafe {
            let cin = st().con_in;
            let mut key = InputKey { scan_code: 0, unicode_char: 0 };
            if is_error(((*cin).read_key_stroke)(cin, &mut key)) {
                return None;
            }
            Some(Self::key_from(&key))
        }
    }
}
