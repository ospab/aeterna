// SPDX-License-Identifier: AGPL-3.0-only
//! DFS .ssd images and a high-level filing system (no DFS ROM, no 8271).
//!
//! How the MOS reaches us
//! ----------------------
//! machine.rs plants a tiny original "service ROM" (header + `JMP trap`) in a sideways slot. The
//! MOS offers it its service calls like any ROM:
//!   - call 3 (auto-boot): point FILEV/ARGSV/BGETV/BPUTV/GBPBV/FINDV/FSCV at trap addresses in the
//!     FRED page (&FC10..&FC16) and, after SHIFT+BREAK, run the boot option of the catalogue
//!     (*LOAD / *RUN / *EXEC !BOOT) by calling OSCLI from the trap;
//!   - call 4 (unrecognised command): *DIR *DRIVE *LIB *INFO *TITLE ... (see `star_command`);
//!   - call 8 (unrecognised OSWORD): OSWORD &7F, the 8271 command block (read/verify/read-ID).
//! Execution of a trap address is intercepted by the machine before the CPU fetches from it; the
//! handlers in this file read the registers (`Cpu`) and memory (`Mem`), do the work, and return an
//! `Out` telling the machine how to finish: return (RTS), jump (*RUN), print text and return, or
//! raise a BRK error (a BRK executed from an error block served in the FRED page).
//! The disc is read-only; saving reports "Disc read only". Handles are the DFS ones, &11..&15.

use crate::cpu::Cpu;
use alloc::string::String;
use alloc::vec::Vec;

pub trait Mem {
    fn rd(&mut self, a: u16) -> u8;
    fn wr(&mut self, a: u16, v: u8);
}

pub enum Out {
    Rts,
    Jump(u16),
    Text(String),
    Err(u8, &'static str),
}

#[derive(Clone)]
pub struct Entry {
    pub dir: u8,
    pub name: String,
    pub load: u32,
    pub exec: u32,
    pub len: u32,
    pub start: u32,
    pub locked: bool,
}

struct Open {
    start: usize,
    len: u32,
    ptr: u32,
}

pub struct Disc {
    img: Vec<u8>,
    cur_dir: u8,
    lib_dir: u8,
    cur_drive: u8,
    handles: [Option<Open>; 5],
    pub log: Vec<String>,
}

fn ext(v: u32) -> u32 { if v & 0x30000 == 0x30000 { v | 0xFFFC_0000 } else { v } }

fn upper(b: u8) -> u8 { b.to_ascii_uppercase() }

fn wild(pat: &[u8], s: &[u8]) -> bool {
    match pat.first() {
        None => s.is_empty(),
        Some(b'*') => (0..=s.len()).any(|i| wild(&pat[1..], &s[i..])),
        Some(&p) => !s.is_empty() && (p == b'#' || upper(p) == upper(s[0])) && wild(&pat[1..], &s[1..]),
    }
}

impl Default for Disc {
    fn default() -> Self { Self::new() }
}

impl Disc {
    pub fn new() -> Self {
        Disc { img: Vec::new(), cur_dir: b'$', lib_dir: b'$', cur_drive: 0, handles: [None, None, None, None, None], log: Vec::new() }
    }

    pub fn insert(&mut self, img: Vec<u8>) {
        self.img = img;
        self.cur_dir = b'$';
        self.lib_dir = b'$';
        self.handles = [None, None, None, None, None];
    }

    pub fn present(&self) -> bool { self.img.len() >= 512 }

    pub fn title(&self) -> String {
        let mut t = Vec::new();
        if self.present() {
            t.extend_from_slice(&self.img[0..8]);
            t.extend_from_slice(&self.img[0x100..0x104]);
        }
        let s: String = t.iter().take_while(|&&b| b != 0).map(|&b| b as char).collect();
        String::from(s.trim_end())
    }

    pub fn boot_option(&self) -> u8 { if self.present() { (self.img[0x106] >> 4) & 3 } else { 0 } }

    pub fn entries(&self) -> Vec<Entry> {
        let mut v = Vec::new();
        if !self.present() { return v; }
        let n = (self.img[0x105] / 8).min(31) as usize;
        for i in 0..n {
            let o = 8 + i * 8;
            let e = 0x108 + i * 8;
            let d = &self.img;
            let name: String = d[o..o + 7].iter().map(|&b| (b & 0x7F) as char).collect::<String>().trim_end().into();
            let hi = d[e + 6] as u32;
            v.push(Entry {
                dir: d[o + 7] & 0x7F,
                name,
                load: ext(d[e] as u32 | (d[e + 1] as u32) << 8 | ((hi >> 2) & 3) << 16),
                exec: ext(d[e + 2] as u32 | (d[e + 3] as u32) << 8 | ((hi >> 6) & 3) << 16),
                len: d[e + 4] as u32 | (d[e + 5] as u32) << 8 | ((hi >> 4) & 3) << 16,
                start: d[e + 7] as u32 | (hi & 3) << 8,
                locked: d[o + 7] & 0x80 != 0,
            });
        }
        v
    }

    pub fn data(&self, e: &Entry) -> &[u8] {
        let s = (e.start as usize * 256).min(self.img.len());
        let t = (s + e.len as usize).min(self.img.len());
        &self.img[s..t]
    }

    pub fn sector(&self, track: u32, sector: u32) -> Option<&[u8]> {
        let o = (track as usize * 10 + sector as usize) * 256;
        if sector < 10 && o + 256 <= self.img.len() { Some(&self.img[o..o + 256]) } else { None }
    }

    // ---- names ----

    /// Splits `[:d.][D.]name`; returns (explicit dir, name).
    fn split(s: &[u8]) -> (Option<u8>, Vec<u8>) {
        let mut s = s;
        if s.first() == Some(&b'"') { s = &s[1..]; }
        let mut i = 0;
        if s.len() >= 2 && s[0] == b':' {
            i = s.iter().position(|&b| b == b'.').map(|p| p + 1).unwrap_or(s.len());
        }
        let mut dir = None;
        if s.len() >= i + 2 && s[i + 1] == b'.' { dir = Some(upper(s[i])); i += 2; }
        let name: Vec<u8> = s[i..].iter().cloned().take_while(|&b| b != b'"').collect();
        (dir, name)
    }

    fn find(&self, spec: &[u8], with_lib: bool) -> Option<Entry> {
        let (dir, name) = Self::split(spec);
        let mut dirs = Vec::new();
        dirs.push(dir.unwrap_or(self.cur_dir));
        if dir.is_none() && with_lib { dirs.push(self.lib_dir); }
        let ents = self.entries();
        for d in dirs {
            if let Some(e) = ents.iter().find(|e| upper(e.dir) == upper(d) && wild(&name, e.name.as_bytes())) {
                return Some(e.clone());
            }
        }
        None
    }

    fn read_str<M: Mem + ?Sized>(m: &mut M, mut a: u16, stop_space: bool) -> Vec<u8> {
        let mut v = Vec::new();
        for _ in 0..256 {
            let b = m.rd(a);
            if b == 13 || (stop_space && (b == b' ')) { break; }
            v.push(b);
            a = a.wrapping_add(1);
        }
        v
    }

    fn rd16<M: Mem + ?Sized>(m: &mut M, a: u16) -> u16 { m.rd(a) as u16 | (m.rd(a.wrapping_add(1)) as u16) << 8 }
    fn rd32<M: Mem + ?Sized>(m: &mut M, a: u16) -> u32 { Self::rd16(m, a) as u32 | (Self::rd16(m, a.wrapping_add(2)) as u32) << 16 }
    fn wr32<M: Mem + ?Sized>(m: &mut M, a: u16, v: u32) { for i in 0..4 { m.wr(a.wrapping_add(i), (v >> (8 * i)) as u8); } }

    fn load_into<M: Mem + ?Sized>(&self, m: &mut M, e: &Entry, addr: u16) {
        for (i, &b) in self.data(e).iter().enumerate() { m.wr(addr.wrapping_add(i as u16), b); }
    }

    fn attr(e: &Entry) -> u32 { if e.locked { 0x0A } else { 0x33 } }

    // ---- vectors ----

    pub fn filev(&mut self, c: &mut Cpu, m: &mut dyn Mem) -> Out {
        let blk = c.x as u16 | (c.y as u16) << 8;
        let np = Self::rd16(m, blk);
        let name = Self::read_str(m, np, false);
        { if self.log.len() > 300 { self.log.remove(0); } self.log.push(alloc::format!("filev a={:02X} {:?}", c.a, String::from_utf8_lossy(&name))); }
        match c.a {
            0 | 1 | 2 | 3 | 4 | 6 => Out::Err(0xC9, "Disc read only"),
            5 | 0xFF => {
                let Some(e) = self.find(&name, c.a == 0xFF) else {
                    if c.a == 5 { c.a = 0; return Out::Rts; }
                    return Out::Err(0xD6, "File not found");
                };
                if c.a == 0xFF {
                    let to = if m.rd(blk.wrapping_add(6)) == 0 { Self::rd32(m, blk.wrapping_add(2)) } else { e.load };
                    self.load_into(m, &e, to as u16);
                }
                Self::wr32(m, blk.wrapping_add(2), e.load);
                Self::wr32(m, blk.wrapping_add(6), e.exec);
                Self::wr32(m, blk.wrapping_add(10), e.len);
                Self::wr32(m, blk.wrapping_add(14), Self::attr(&e));
                c.a = 1;
                Out::Rts
            }
            _ => Out::Rts,
        }
    }

    fn open(&self, h: u8) -> Option<usize> {
        if (0x11..=0x15).contains(&h) && self.handles[(h - 0x11) as usize].is_some() { Some((h - 0x11) as usize) } else { None }
    }

    pub fn findv(&mut self, c: &mut Cpu, m: &mut dyn Mem) -> Out {
        { if self.log.len() > 300 { self.log.remove(0); } self.log.push(alloc::format!("find a={:02X} x={:02X} y={:02X}", c.a, c.x, c.y)); }
        match c.a {
            0 => {
                if c.y == 0 { self.handles = [None, None, None, None, None]; m.wr(0x256, 0); }
                else if let Some(i) = self.open(c.y) {
                    self.handles[i] = None;
                    if m.rd(0x256) == c.y { m.wr(0x256, 0); }
                }
                Out::Rts
            }
            0x40 | 0xC0 | 0x80 => {
                if c.a == 0x80 { return Out::Err(0xC9, "Disc read only"); }
                let name = Self::read_str(m, c.x as u16 | (c.y as u16) << 8, false);
                let Some(e) = self.find(&name, false) else { c.a = 0; return Out::Rts; };
                let Some(slot) = self.handles.iter().position(|h| h.is_none()) else { return Out::Err(0xC0, "Too many open files"); };
                self.handles[slot] = Some(Open { start: e.start as usize * 256, len: e.len, ptr: 0 });
                c.a = 0x11 + slot as u8;
                Out::Rts
            }
            _ => Out::Rts,
        }
    }

    pub fn bgetv(&mut self, c: &mut Cpu, _m: &mut dyn Mem) -> Out {
        { if self.log.len() > 300 { self.log.remove(0); } self.log.push(alloc::format!("bget y={:02X}", c.y)); }
        let Some(i) = self.open(c.y) else { return Out::Err(0xDE, "Channel"); };
        let h = self.handles[i].as_mut().unwrap();
        if h.ptr >= h.len {
            c.a = 0xFE;
            c.p |= 1;
        } else {
            c.a = self.img.get(h.start + h.ptr as usize).copied().unwrap_or(0);
            h.ptr += 1;
            c.p &= !1;
        }
        Out::Rts
    }

    pub fn bputv(&mut self, _c: &mut Cpu, _m: &mut dyn Mem) -> Out { Out::Err(0xC9, "Disc read only") }

    pub fn argsv(&mut self, c: &mut Cpu, m: &mut dyn Mem) -> Out {
        { if self.log.len() > 300 { self.log.remove(0); } self.log.push(alloc::format!("args a={:02X} x={:02X} y={:02X}", c.a, c.x, c.y)); }
        if c.y == 0 {
            if c.a == 0 { c.a = 4; }
            return Out::Rts;
        }
        let Some(i) = self.open(c.y) else { return Out::Err(0xDE, "Channel"); };
        let h = self.handles[i].as_mut().unwrap();
        let zp = c.x as u16;
        match c.a {
            0 => Self::wr32(m, zp, h.ptr),
            1 => h.ptr = Self::rd32(m, zp).min(h.len),
            2 => Self::wr32(m, zp, h.len),
            _ => {}
        }
        Out::Rts
    }

    pub fn gbpbv(&mut self, c: &mut Cpu, m: &mut dyn Mem) -> Out {
        let blk = c.x as u16 | (c.y as u16) << 8;
        match c.a {
            3 | 4 => {
                let hd = m.rd(blk);
                let Some(i) = self.open(hd) else { return Out::Err(0xDE, "Channel"); };
                let mut addr = Self::rd32(m, blk.wrapping_add(1));
                let mut count = Self::rd32(m, blk.wrapping_add(5));
                let h = self.handles[i].as_mut().unwrap();
                if c.a == 3 { h.ptr = Self::rd32(m, blk.wrapping_add(9)).min(h.len); }
                while count > 0 && h.ptr < h.len {
                    m.wr(addr as u16, self.img.get(h.start + h.ptr as usize).copied().unwrap_or(0));
                    addr = addr.wrapping_add(1);
                    count -= 1;
                    h.ptr += 1;
                }
                Self::wr32(m, blk.wrapping_add(1), addr);
                Self::wr32(m, blk.wrapping_add(5), count);
                Self::wr32(m, blk.wrapping_add(9), h.ptr);
                if count != 0 { c.p |= 1 } else { c.p &= !1 }
                Out::Rts
            }
            5 => {
                let addr = Self::rd32(m, blk.wrapping_add(1)) as u16;
                let t = self.title();
                let mut b = Vec::new();
                b.push(t.len() as u8);
                b.extend_from_slice(t.as_bytes());
                b.push(self.boot_option());
                b.push(self.cur_drive);
                for (i, v) in b.iter().enumerate() { m.wr(addr.wrapping_add(i as u16), *v); }
                Out::Rts
            }
            6 | 7 => {
                let addr = Self::rd32(m, blk.wrapping_add(1)) as u16;
                let d = if c.a == 6 { self.cur_dir } else { self.lib_dir };
                for (i, v) in [1u8, b'0' + self.cur_drive, 1, d].iter().enumerate() { m.wr(addr.wrapping_add(i as u16), *v); }
                Out::Rts
            }
            _ => Out::Err(0xC9, "Disc read only"),
        }
    }

    pub fn fscv(&mut self, c: &mut Cpu, m: &mut dyn Mem) -> Out {
        { if self.log.len() > 300 { self.log.remove(0); } self.log.push(alloc::format!("fsc a={:02X} x={:02X} y={:02X}", c.a, c.x, c.y)); }
        let xy = c.x as u16 | (c.y as u16) << 8;
        match c.a {
            1 => {
                let eof = match self.open(c.x) { Some(i) => { let h = self.handles[i].as_ref().unwrap(); h.ptr >= h.len } _ => true };
                c.x = if eof { 0xFF } else { 0 };
                Out::Rts
            }
            2 | 3 | 4 => {
                let cmd = Self::read_str(m, xy, true);
                { if self.log.len() > 300 { self.log.remove(0); } self.log.push(alloc::format!("run {:?}", String::from_utf8_lossy(&cmd))); }
                match self.find(&cmd, true) {
                    Some(e) => {
                        self.load_into(m, &e, e.load as u16);
                        Out::Jump(e.exec as u16)
                    }
                    None if c.a == 3 => Out::Err(0xFE, "Bad command"),
                    None => Out::Err(0xD6, "File not found"),
                }
            }
            5 => Out::Text(self.catalogue()),
            7 => { c.x = 0x11; c.y = 0x15; Out::Rts }
            _ => Out::Rts,
        }
    }

    pub fn catalogue(&self) -> String {
        use alloc::format;
        let opt = ["off", "LOAD", "RUN", "EXEC"][self.boot_option() as usize];
        let mut s = format!("{}\r\nDrive {}   Option {} ({})\r\nDir. :{}.{}   Lib. :{}.{}\r\n\r\n",
            self.title(), self.cur_drive, self.boot_option(), opt, self.cur_drive, self.cur_dir as char,
            self.cur_drive, self.lib_dir as char);
        let mut ents = self.entries();
        ents.sort_by(|a, b| (a.dir != self.cur_dir, a.name.to_ascii_uppercase()).cmp(&(b.dir != self.cur_dir, b.name.to_ascii_uppercase())));
        for e in &ents {
            if e.dir == self.cur_dir { s += &format!("  {}{}\r\n", e.name, if e.locked { "  L" } else { "" }); }
            else { s += &format!("  {}.{}{}\r\n", e.dir as char, e.name, if e.locked { "  L" } else { "" }); }
        }
        s
    }

    /// Service call 4. `cmd` is the command line from the offset the MOS gave. Returns None when
    /// the command is not one of ours.
    pub fn star_command(&mut self, cmd: &[u8]) -> Option<Out> {
        let word: Vec<u8> = cmd.iter().cloned().take_while(|&b| b != b' ' && b != 13 && b != b'.').map(upper).collect();
        let rest: Vec<u8> = cmd[word.len().min(cmd.len())..].iter().cloned().skip_while(|&b| b == b' ').take_while(|&b| b != 13).collect();
        match &word[..] {
            b"DIR" | b"LIB" => {
                let (_, nm) = Self::split(&rest);
                let d = if rest.is_empty() { b'$' } else if rest.len() >= 3 && rest[0] == b':' { rest[3.min(rest.len() - 1)] } else { *nm.first().unwrap_or(&b'$') };
                if word == b"DIR" { self.cur_dir = d } else { self.lib_dir = d }
                Some(Out::Rts)
            }
            b"DRIVE" => { self.cur_drive = rest.first().map(|b| b.wrapping_sub(b'0')).unwrap_or(0) & 3; Some(Out::Rts) }
            b"DISC" | b"DISK" | b"DFS" | b"ENABLE" | b"COMPACT" | b"VERIFY" => Some(Out::Rts),
            b"INFO" | b"CAT" => Some(Out::Text(self.catalogue())),
            b"ACCESS" | b"TITLE" | b"DELETE" | b"DESTROY" | b"WIPE" | b"RENAME" | b"COPY" | b"BACKUP" | b"BUILD" | b"FORM" =>
                Some(Out::Err(0xC9, "Disc read only")),
            _ => None,
        }
    }

    /// OSWORD &7F (8271 command block) with the block at `blk`.
    pub fn osword7f(&mut self, m: &mut dyn Mem, blk: u16) {
        let addr = Self::rd16(m, blk.wrapping_add(1));
        let np = m.rd(blk.wrapping_add(5)) as u16;
        let cmd = m.rd(blk.wrapping_add(6)) & 0x3F;
        let res = blk.wrapping_add(7 + np);
        { if self.log.len() > 300 { self.log.remove(0); } self.log.push(alloc::format!("osword7f cmd={:02X} trk={:02X} sec={:02X} n={:02X}", cmd, m.rd(blk.wrapping_add(7)), m.rd(blk.wrapping_add(8)), m.rd(blk.wrapping_add(9)))); }
        let drive_ok = m.rd(blk) == 0 && self.present();
        let result: u8 = match cmd {
            0x13 | 0x17 | 0x1F => {
                // read data (multi) / read data+deleted / verify
                let track = m.rd(blk.wrapping_add(7)) as u32;
                let mut sec = m.rd(blk.wrapping_add(8)) as u32;
                let count = (m.rd(blk.wrapping_add(9)) & 0x1F) as u32;
                let mut a = addr;
                let mut r = 0u8;
                if !drive_ok { r = 0x10; }
                else {
                    for _ in 0..count {
                        let Some(s) = self.sector(track, sec) else { r = 0x1E; break; };
                        if cmd != 0x1F { for (i, &b) in s.iter().enumerate() { m.wr(a.wrapping_add(i as u16), b); } }
                        a = a.wrapping_add(256);
                        sec += 1;
                    }
                }
                r
            }
            0x1B => {
                // read ID: track, sector (0), count
                let track = m.rd(blk.wrapping_add(7)) as u8;
                if !drive_ok { 0x10 } else {
                    let count = m.rd(blk.wrapping_add(9)) as u16 & 0x1F;
                    for i in 0..count.max(1) {
                        let o = addr.wrapping_add(i * 4);
                        m.wr(o, track); m.wr(o.wrapping_add(1), 0); m.wr(o.wrapping_add(2), i as u8); m.wr(o.wrapping_add(3), 1);
                    }
                    0
                }
            }
            0x29 => if drive_ok { 0 } else { 0x10 },
            0x2C => 0x80,
            0x0B | 0x0F | 0x23 => 0x12,
            _ => 0,
        };
        m.wr(res, result);
    }
}
