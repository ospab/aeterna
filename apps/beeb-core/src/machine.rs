// SPDX-License-Identifier: AGPL-3.0-only
//! The Model B: memory map, SHEILA, glue between CPU, video, VIAs and disc.
//!
//! Timing: the CPU runs at 2 MHz, `step` returns cycles; after every instruction the VIAs get
//! cycles/2 ticks and the video gets a scan line per 128 cycles. SHEILA/FRED accesses are
//! stretched by 1-2 cycles (1 MHz bus). `run_frame` runs until the CRTC starts vsync (so one call
//! is exactly one video frame, 312/312.5 lines), not a fixed 40000 cycles.
//!
//! Filing system: see disc.rs. The trap addresses below live in the FRED page; the machine
//! intercepts the CPU's PC before fetching there.

use crate::cpu::{Bus, Cpu};
use crate::disc::{Disc, Mem, Out};
use crate::keyboard::{Key, Keyboard};
use crate::via::Via;
use crate::video::Video;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub const SCREEN_W: usize = 640;
pub const SCREEN_H: usize = 256;

const T_FILEV: u16 = 0xFC10;
const T_ARGSV: u16 = 0xFC11;
const T_BGETV: u16 = 0xFC12;
const T_BPUTV: u16 = 0xFC13;
const T_GBPBV: u16 = 0xFC14;
const T_FINDV: u16 = 0xFC15;
const T_FSCV: u16 = 0xFC16;
const T_SERVICE: u16 = 0xFC17;
const T_PUMP: u16 = 0xFC18;
/// BRK opcode served from the FRED buffer: error number and text follow.
const T_ERROR: u16 = 0xFC40;
const FRED_CLI: usize = 0x100;
const DFS_SLOT: usize = 14;

enum Act {
    Char(u8),
    Cli(String),
}

struct Hle {
    queue: VecDeque<Act>,
    saved: (u8, u8, u8, u8),
    boot_pending: bool,
    hooked: bool,
}

struct Hw {
    ram: Vec<u8>,
    mos: Vec<u8>,
    roms: Vec<Option<Vec<u8>>>,
    romsel: u8,
    sys: Via,
    usr: Via,
    kbd: Keyboard,
    video: Video,
    disc: Disc,
    latch: u8,
    fred: Vec<u8>,
    extra: u32,
    toggle: bool,
    cycles: u64,
    line_cyc: u32,
    half: u32,
    adc_timer: i32,
    adc_busy: bool,
    adc_chan: u8,
}

impl Hw {
    fn stretch(&mut self) {
        self.extra += 1 + self.toggle as u32;
        self.toggle = !self.toggle;
    }

    fn peek(&self, addr: u16) -> u8 {
        match addr {
            0..=0x7FFF => self.ram[addr as usize],
            0x8000..=0xBFFF => match &self.roms[(self.romsel & 15) as usize] {
                Some(r) => r[(addr - 0x8000) as usize],
                None => 0xFF,
            },
            0xFC00..=0xFDFF => self.fred[(addr - 0xFC00) as usize],
            0xFE00..=0xFEFF => 0xFF,
            _ => self.mos[(addr - 0xC000) as usize],
        }
    }

    fn update_ca2(&mut self) {
        let level = if self.latch & 8 != 0 { self.kbd.any_key() } else { self.kbd.col_any(self.sys.ora & self.sys.ddra & 15) };
        self.sys.set_ca2(level);
    }

    fn sheila_read(&mut self, a: u16) -> u8 {
        let off = (a & 0xFF) as u8;
        match off {
            0x00..=0x07 => if off & 1 != 0 { self.video.crtc_read() } else { 0 },
            0x08..=0x0F => if off & 1 == 0 { 0x02 } else { 0 },
            0x40..=0x5F => {
                let r = off & 15;
                if r == 1 || r == 15 {
                    let sel = self.sys.ora & self.sys.ddra;
                    let down = self.kbd.sense(sel & 15, (sel >> 4) & 7);
                    self.sys.pa_in = 0x7F | if down { 0x80 } else { 0 };
                }
                self.sys.read(r)
            }
            0x60..=0x7F => self.usr.read(off & 15),
            0xC0..=0xDF => match off & 3 {
                0 => (if self.adc_busy { 0x80 } else { 0x40 }) | self.adc_chan,
                1 => 0x80,
                _ => 0,
            },
            _ => 0xFF,
        }
    }

    fn sheila_write(&mut self, a: u16, v: u8) {
        let off = (a & 0xFF) as u8;
        match off {
            0x00..=0x07 => if off & 1 == 0 { self.video.crtc_sel = v & 31 } else { self.video.crtc_write(v) },
            0x20..=0x2F => if off & 1 == 0 { self.video.ula = v } else { self.video.palette_write(v) },
            0x30..=0x3F => self.romsel = v & 15,
            0x40..=0x5F => {
                let r = off & 15;
                self.sys.write(r, v);
                if r == 1 || r == 15 || r == 3 { self.update_ca2(); }
                if r == 0 {
                    let bit = 1u8 << (v & 7);
                    if v & 8 != 0 { self.latch |= bit } else { self.latch &= !bit }
                    self.update_ca2();
                }
            }
            0x60..=0x7F => self.usr.write(off & 15, v),
            0xC0..=0xDF => if off & 3 == 0 {
                self.adc_chan = v & 3;
                self.adc_busy = true;
                self.adc_timer = if v & 8 != 0 { 8000 } else { 20000 };
            },
            _ => {}
        }
    }

    fn advance(&mut self, c: u32) {
        self.cycles += c as u64;
        self.half += c;
        let t = self.half >> 1;
        self.half &= 1;
        self.sys.tick(t);
        self.usr.tick(t);
        if self.adc_busy {
            self.adc_timer -= c as i32;
            if self.adc_timer <= 0 { self.adc_busy = false; self.sys.cb1_edge(); }
        }
        self.line_cyc += c;
        while self.line_cyc >= 128 {
            self.line_cyc -= 128;
            let l = self.latch;
            let size = [0x4000u32, 0x2000, 0x5000, 0x2800][(((l >> 4) & 1) | ((l >> 5) & 1) << 1) as usize];
            let ev = self.video.line(&self.ram, size, &self.mos);
            let rising = self.sys.pcr_ca1_rising();
            if (ev.vsync_start && !rising) || (ev.vsync_end && rising) { self.sys.ca1_edge(); }
        }
    }

    fn irq(&self) -> bool { self.sys.irq() || self.usr.irq() }
}

impl Bus for Hw {
    fn read(&mut self, addr: u16) -> u8 {
        match addr {
            0xFC00..=0xFEFF => {
                self.stretch();
                if addr >= 0xFE00 { self.sheila_read(addr) } else { self.fred[(addr - 0xFC00) as usize] }
            }
            _ => self.peek(addr),
        }
    }

    fn write(&mut self, addr: u16, v: u8) {
        match addr {
            0..=0x7FFF => self.ram[addr as usize] = v,
            0xFE00..=0xFEFF => { self.stretch(); self.sheila_write(addr, v); }
            0xFC00..=0xFDFF => self.stretch(),
            _ => {}
        }
    }
}

impl Mem for Hw {
    fn rd(&mut self, a: u16) -> u8 { self.peek(a) }
    fn wr(&mut self, a: u16, v: u8) { if a < 0x8000 { self.ram[a as usize] = v; } }
}

pub struct Beeb {
    cpu: Cpu,
    hw: Hw,
    hle: Hle,
}

fn dfs_rom() -> Vec<u8> {
    let mut r = vec![0u8; 0x4000];
    r[3..6].copy_from_slice(&[0x4C, T_SERVICE as u8, (T_SERVICE >> 8) as u8]);
    r[6] = 0x80;
    r[7] = 0x0C;
    r[9..12].copy_from_slice(b"DFS");
    r[0x0D..0x10].copy_from_slice(b"(C)");
    r
}

impl Beeb {
    /// `mos` is the 16 KiB MOS 1.20 image.
    pub fn new(mos: &[u8]) -> Self {
        let mut m = vec![0u8; 0x4000];
        let n = mos.len().min(0x4000);
        m[..n].copy_from_slice(&mos[..n]);
        let mut roms: Vec<Option<Vec<u8>>> = Vec::new();
        for _ in 0..16 { roms.push(None); }
        roms[DFS_SLOT] = Some(dfs_rom());
        let hw = Hw {
            ram: vec![0; 0x8000], mos: m, roms, romsel: 0, sys: Via::new(), usr: Via::new(),
            kbd: Keyboard::new(), video: Video::new(), disc: Disc::new(), latch: 0,
            fred: vec![0xFF; 0x200], extra: 0, toggle: false, cycles: 0, line_cyc: 0, half: 0,
            adc_timer: 0, adc_busy: false, adc_chan: 0,
        };
        let mut b = Beeb {
            cpu: Cpu::new(), hw,
            hle: Hle { queue: VecDeque::new(), saved: (0, 0, 0, 0), boot_pending: false, hooked: false },
        };
        b.cpu.reset(&mut b.hw);
        b
    }

    pub fn insert_disc(&mut self, ssd: Vec<u8>) { self.hw.disc.insert(ssd); }

    /// Plugs a 16 KiB sideways ROM (e.g. a BASIC ROM the user owns) into `slot` 0..15. The
    /// built-in disc filing system service ROM sits in slot 14.
    pub fn insert_rom(&mut self, slot: usize, data: &[u8]) {
        if slot < 16 {
            let mut r = vec![0xFFu8; 0x4000];
            let n = data.len().min(0x4000);
            r[..n].copy_from_slice(&data[..n]);
            self.hw.roms[slot] = Some(r);
        }
    }

    /// Reset (BREAK). The first reset after `new` is a power-on; later ones are warm and keep
    /// RAM and the System VIA like real hardware. With `shift_break` and a disc inserted the
    /// catalogue boot option is run.
    pub fn reset(&mut self, shift_break: bool) {
        if self.hw.cycles == 0 {
            self.hw.sys = Via::new();
            for b in self.hw.ram.iter_mut() { *b = 0; }
        }
        self.hw.usr = Via::new();
        self.hle.queue.clear();
        self.hle.hooked = false;
        self.hle.hooked = false;
        self.hle.boot_pending = shift_break && self.hw.disc.present();
        self.hw.romsel = 0;
        self.cpu.reset(&mut self.hw);
        self.hw.update_ca2();
    }

    /// Runs one video frame (about 40_000 CPU cycles) and leaves the picture in `screen()`.
    pub fn run_frame(&mut self) {
        let mut elapsed: u32 = 0;
        self.hw.video.frame_done = false;
        while elapsed < 90_000 {
            elapsed += self.step_once();
            if self.hw.video.frame_done {
                if elapsed >= 30_000 { break; }
                self.hw.video.frame_done = false;
            }
        }
    }

    /// SCREEN_W * SCREEN_H pixels, 0x00RRGGBB.
    pub fn screen(&self) -> &[u32] { &self.hw.video.fb }

    /// BBC key down/up, see keyboard::Key. `Key::Break` resets (auto-boot if SHIFT is down).
    pub fn key(&mut self, key: Key, down: bool) {
        if key == Key::Break {
            if down { let s = self.hw.kbd.shift_down(); self.reset(s); }
            return;
        }
        self.hw.kbd.set(key, down);
        self.hw.update_ca2();
    }

    /// Video frames completed since power-on.
    pub fn frames(&self) -> u64 { self.hw.video.frame }
    pub fn disc_log(&self) -> &[String] { &self.hw.disc.log }
    pub fn pc(&self) -> u16 { self.cpu.pc }
    pub fn peek(&self, addr: u16) -> u8 { self.hw.peek(addr) }

    /// One-line dump of CPU and video state for host debugging.
    pub fn debug(&self) -> String {
        use alloc::format;
        let v = &self.hw.video;
        format!("pc={:04X} a={:02X} x={:02X} y={:02X} sp={:02X} p={:02X} ula={:02X} latch={:02X} crtc={:02X?} pal={:X?} sysIER={:02X} ifr={:02X} pcr={:02X} acr={:02X} ddra={:02X} orb={:02X} ddrb={:02X}",
            self.cpu.pc, self.cpu.a, self.cpu.x, self.cpu.y, self.cpu.s, self.cpu.p, v.ula, self.hw.latch, &v.crtc[..16], v.pal,
            self.hw.sys.ier, self.hw.sys.ifr, self.hw.sys.pcr, self.hw.sys.acr, self.hw.sys.ddra, self.hw.sys.orb, self.hw.sys.ddrb)
    }

    fn step_once(&mut self) -> u32 {
        if self.cpu.pc & 0xFFE0 == 0xFC00 {
            if self.trap(self.cpu.pc) { return 2; }
        }
        if self.hle.hooked && self.vectors_changed() { self.hook_vectors(); }
        self.hw.extra = 0;
        let c = self.cpu.step(&mut self.hw) + self.hw.extra;
        self.hw.advance(c);
        let irq = self.hw.irq();
        self.cpu.set_irq(irq);
        c
    }

    fn push(&mut self, v: u8) {
        self.hw.ram[0x100 + self.cpu.s as usize] = v;
        self.cpu.s = self.cpu.s.wrapping_sub(1);
    }

    fn do_rts(&mut self) {
        self.cpu.s = self.cpu.s.wrapping_add(1);
        let lo = self.hw.ram[0x100 + self.cpu.s as usize] as u16;
        self.cpu.s = self.cpu.s.wrapping_add(1);
        let hi = self.hw.ram[0x100 + self.cpu.s as usize] as u16;
        self.cpu.pc = ((hi << 8) | lo).wrapping_add(1);
    }

    fn pump_prepare(&mut self) {
        self.hle.saved = (self.cpu.a, self.cpu.x, self.cpu.y, self.cpu.p);
        self.cpu.pc = T_PUMP;
    }

    fn finish(&mut self, out: Out) {
        match out {
            Out::Rts => self.do_rts(),
            Out::Jump(a) => self.cpu.pc = a,
            Out::Text(s) => {
                for b in s.bytes() { self.hle.queue.push_back(Act::Char(b)); }
                self.pump_prepare();
            }
            Out::Err(code, msg) => {
                let f = &mut self.hw.fred;
                f[0x40] = 0;
                f[0x41] = code;
                let n = msg.len().min(100);
                f[0x42..0x42 + n].copy_from_slice(&msg.as_bytes()[..n]);
                f[0x42 + n] = 0;
                self.cpu.pc = T_ERROR;
            }
        }
    }

    fn with_disc(&mut self, f: fn(&mut Disc, &mut Cpu, &mut dyn Mem) -> Out) {
        let mut d = core::mem::take(&mut self.hw.disc);
        let out = f(&mut d, &mut self.cpu, &mut self.hw);
        self.hw.disc = d;
        self.finish(out);
    }

    fn trap(&mut self, pc: u16) -> bool {
        match pc {
            T_FILEV => self.with_disc(Disc::filev),
            T_ARGSV => self.with_disc(Disc::argsv),
            T_BGETV => self.with_disc(Disc::bgetv),
            T_BPUTV => self.with_disc(Disc::bputv),
            T_GBPBV => self.with_disc(Disc::gbpbv),
            T_FINDV => self.with_disc(Disc::findv),
            T_FSCV => self.with_disc(Disc::fscv),
            T_SERVICE => self.service(),
            T_PUMP => self.pump(),
            _ => return false,
        }
        true
    }

    fn pump(&mut self) {
        match self.hle.queue.pop_front() {
            Some(Act::Char(b)) => {
                self.cpu.a = b;
                self.push(((T_PUMP - 1) >> 8) as u8);
                self.push((T_PUMP - 1) as u8);
                self.cpu.pc = 0xFFEE;
            }
            Some(Act::Cli(s)) => {
                let f = &mut self.hw.fred;
                let n = s.len().min(200);
                f[FRED_CLI..FRED_CLI + n].copy_from_slice(&s.as_bytes()[..n]);
                f[FRED_CLI + n] = 13;
                self.cpu.x = 0x00;
                self.cpu.y = 0xFD;
                self.push(((T_PUMP - 1) >> 8) as u8);
                self.push((T_PUMP - 1) as u8);
                self.cpu.pc = 0xFFF7;
            }
            None => {
                let (a, x, y, p) = self.hle.saved;
                self.cpu.a = a;
                self.cpu.x = x;
                self.cpu.y = y;
                self.cpu.p = p;
                self.do_rts();
            }
        }
    }

    fn vectors_changed(&self) -> bool {
        [T_FILEV, T_ARGSV, T_BGETV, T_BPUTV, T_GBPBV, T_FINDV, T_FSCV].iter().enumerate()
            .any(|(i, t)| self.hw.ram[0x212 + i * 2] != *t as u8 || self.hw.ram[0x213 + i * 2] != (*t >> 8) as u8)
    }

    fn hook_vectors(&mut self) {
        self.hle.hooked = true;
        for (i, t) in [T_FILEV, T_ARGSV, T_BGETV, T_BPUTV, T_GBPBV, T_FINDV, T_FSCV].iter().enumerate() {
            self.hw.ram[0x212 + i * 2] = *t as u8;
            self.hw.ram[0x213 + i * 2] = (*t >> 8) as u8;
        }
    }

    /// The service entry of the built-in DFS ROM: A = service call number.
    fn service(&mut self) {
        let present = self.hw.disc.present();
        match self.cpu.a {
            1 => {
                if present && self.cpu.y < 0x19 { self.cpu.y = 0x19; }
                self.do_rts();
            }
            3 if present => {
                self.hook_vectors();
                for b in "ospab DFS\r\n\r\n".bytes() { self.hle.queue.push_back(Act::Char(b)); }
                if self.hle.boot_pending {
                    self.hle.boot_pending = false;
                    let cmd = match self.hw.disc.boot_option() {
                        1 => Some("LOAD !BOOT"),
                        2 => Some("RUN !BOOT"),
                        3 => Some("EXEC !BOOT"),
                        _ => None,
                    };
                    if let Some(c) = cmd { self.hle.queue.push_back(Act::Cli(String::from(c))); }
                }
                self.pump_prepare();
            }
            4 if present => {
                let p = self.hw.ram[0xF2] as u16 | (self.hw.ram[0xF3] as u16) << 8;
                let mut cmd = Vec::new();
                let mut a = p.wrapping_add(self.cpu.y as u16);
                for _ in 0..64 {
                    let b = self.hw.peek(a);
                    cmd.push(b);
                    if b == 13 { break; }
                    a = a.wrapping_add(1);
                }
                let mut d = core::mem::take(&mut self.hw.disc);
                let r = d.star_command(&cmd);
                self.hw.disc = d;
                match r {
                    Some(out) => { self.cpu.a = 0; self.finish(out); }
                    None => self.do_rts(),
                }
            }
            8 if present && self.hw.ram[0xEF] == 0x7F => {
                let blk = self.hw.ram[0xF0] as u16 | (self.hw.ram[0xF1] as u16) << 8;
                let mut d = core::mem::take(&mut self.hw.disc);
                d.osword7f(&mut self.hw, blk);
                self.hw.disc = d;
                self.cpu.a = 0;
                self.do_rts();
            }
            _ => self.do_rts(),
        }
    }
}
