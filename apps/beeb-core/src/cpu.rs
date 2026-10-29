// SPDX-License-Identifier: AGPL-3.0-only
//! MOS 6502 (NMOS) core. Owner: CPU agent.
//!
//! Host tests: the repo root and apps/ have .cargo/config.toml files forcing the OS target and
//! build-std, and cargo reads them from the CWD. Run from a directory outside the repo; the MSVC
//! link.exe is not on PATH here, so use the GNU toolchain:
//!   cd <dir outside repo> && cargo +stable-x86_64-pc-windows-gnu test --manifest-path D:/ospab-projects/ospab.os-v2/apps/beeb-core/Cargo.toml
//! Klaus Dormann's functional test (GPL test data, kept out of the repo) is an ignored test:
//!   KLAUS_BIN=<6502_functional_test.bin> cargo +stable-x86_64-pc-windows-gnu test --release --manifest-path ... -- --ignored klaus_functional
//! (KLAUS_SUCCESS=<hex> overrides the success trap, default 3469.)
//!
//! Timing: instruction-level, no dummy reads/writes on the bus. Page-cross penalty on indexed
//! reads, +1/+2 on taken branches, 7-cycle interrupts. CLI/SEI/PLP delay the IRQ poll by one
//! instruction.

pub trait Bus {
    fn read(&mut self, addr: u16) -> u8;
    fn write(&mut self, addr: u16, value: u8);
}

const F_C: u8 = 0x01;
const F_Z: u8 = 0x02;
const F_I: u8 = 0x04;
const F_D: u8 = 0x08;
const F_B: u8 = 0x10;
const F_U: u8 = 0x20;
const F_V: u8 = 0x40;
const F_N: u8 = 0x80;

// Addressing modes. IMP/ACC/REL carry no effective address.
const IMP: u8 = 0;
const ACC: u8 = 1;
const REL: u8 = 2;
const IMM: u8 = 3;
const ZP: u8 = 4;
const ZPX: u8 = 5;
const ZPY: u8 = 6;
const ABS: u8 = 7;
const ABX: u8 = 8;
const ABY: u8 = 9;
const IZX: u8 = 10;
const IZY: u8 = 11;
const IND: u8 = 12;

/// Cycle table flag: add a cycle when the indexed address crosses a page.
const PEN: u8 = 0x80;

const fn build(rows: [[u8; 16]; 16]) -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut r = 0;
    while r < 16 {
        let mut c = 0;
        while c < 16 {
            t[r * 16 + c] = rows[r][c];
            c += 1;
        }
        r += 1;
    }
    t
}

const M_BR: [u8; 16] = [REL, IZY, IMP, IZY, ZPX, ZPX, ZPX, ZPX, IMP, ABY, IMP, ABY, ABX, ABX, ABX, ABX];
const M_LO: [u8; 16] = [IMP, IZX, IMP, IZX, ZP, ZP, ZP, ZP, IMP, IMM, ACC, IMM, ABS, ABS, ABS, ABS];
const M_IM: [u8; 16] = [IMM, IZX, IMM, IZX, ZP, ZP, ZP, ZP, IMP, IMM, IMP, IMM, ABS, ABS, ABS, ABS];
const M_YY: [u8; 16] = [REL, IZY, IMP, IZY, ZPX, ZPX, ZPY, ZPY, IMP, ABY, IMP, ABY, ABX, ABX, ABY, ABY];

const MODE: [u8; 256] = build([
    M_LO, M_BR,
    [ABS, IZX, IMP, IZX, ZP, ZP, ZP, ZP, IMP, IMM, ACC, IMM, ABS, ABS, ABS, ABS],
    M_BR, M_LO, M_BR,
    [IMP, IZX, IMP, IZX, ZP, ZP, ZP, ZP, IMP, IMM, ACC, IMM, IND, ABS, ABS, ABS],
    M_BR,
    M_IM, M_YY, M_IM, M_YY, M_IM, M_BR, M_IM, M_BR,
]);

const C_BR: [u8; 16] = [2, 5 | PEN, 2, 8, 4, 4, 6, 6, 2, 4 | PEN, 2, 7, 4 | PEN, 4 | PEN, 7, 7];

const CYC: [u8; 256] = build([
    [7, 6, 2, 8, 3, 3, 5, 5, 3, 2, 2, 2, 4, 4, 6, 6],
    C_BR,
    [6, 6, 2, 8, 3, 3, 5, 5, 4, 2, 2, 2, 4, 4, 6, 6],
    C_BR,
    [6, 6, 2, 8, 3, 3, 5, 5, 3, 2, 2, 2, 3, 4, 6, 6],
    C_BR,
    [6, 6, 2, 8, 3, 3, 5, 5, 4, 2, 2, 2, 5, 4, 6, 6],
    C_BR,
    [2, 6, 2, 6, 3, 3, 3, 3, 2, 2, 2, 2, 4, 4, 4, 4],
    [2, 6, 2, 6, 4, 4, 4, 4, 2, 5, 2, 5, 5, 5, 5, 5],
    [2, 6, 2, 6, 3, 3, 3, 3, 2, 2, 2, 2, 4, 4, 4, 4],
    [2, 5 | PEN, 2, 5 | PEN, 4, 4, 4, 4, 2, 4 | PEN, 2, 4 | PEN, 4 | PEN, 4 | PEN, 4 | PEN, 4 | PEN],
    [2, 6, 2, 8, 3, 3, 5, 5, 2, 2, 2, 2, 4, 4, 6, 6],
    C_BR,
    [2, 6, 2, 8, 3, 3, 5, 5, 2, 2, 2, 2, 4, 4, 6, 6],
    C_BR,
]);

pub struct Cpu {
    pub a: u8,
    pub x: u8,
    pub y: u8,
    pub s: u8,
    pub p: u8,
    pub pc: u16,
    pub cycles: u64,
    irq_line: bool,
    nmi_pending: bool,
    halted: bool,
    i_lag: bool,
    i_old: u8,
}

impl Cpu {
    pub const fn new() -> Self {
        Cpu {
            a: 0,
            x: 0,
            y: 0,
            s: 0xFD,
            p: 0x24,
            pc: 0,
            cycles: 0,
            irq_line: false,
            nmi_pending: false,
            halted: false,
            i_lag: false,
            i_old: 0,
        }
    }

    /// Loads PC from the reset vector at $FFFC.
    pub fn reset<B: Bus>(&mut self, bus: &mut B) {
        self.p |= F_I | F_U;
        self.s = 0xFD;
        self.halted = false;
        self.nmi_pending = false;
        self.i_lag = false;
        self.pc = self.read16(bus, 0xFFFC);
        self.cycles += 7;
    }

    /// Level-triggered IRQ input (taken when the I flag is clear).
    pub fn set_irq(&mut self, level: bool) {
        self.irq_line = level;
    }

    /// Edge-triggered NMI.
    pub fn nmi(&mut self) {
        self.nmi_pending = true;
    }

    /// True after a KIL/JAM opcode; only reset recovers.
    pub fn is_halted(&self) -> bool {
        self.halted
    }

    #[inline(always)]
    fn read16<B: Bus>(&mut self, bus: &mut B, addr: u16) -> u16 {
        let lo = bus.read(addr) as u16;
        let hi = bus.read(addr.wrapping_add(1)) as u16;
        lo | hi << 8
    }

    #[inline(always)]
    fn fetch<B: Bus>(&mut self, bus: &mut B) -> u8 {
        let v = bus.read(self.pc);
        self.pc = self.pc.wrapping_add(1);
        v
    }

    #[inline(always)]
    fn fetch16<B: Bus>(&mut self, bus: &mut B) -> u16 {
        let lo = self.fetch(bus) as u16;
        let hi = self.fetch(bus) as u16;
        lo | hi << 8
    }

    #[inline(always)]
    fn push<B: Bus>(&mut self, bus: &mut B, v: u8) {
        bus.write(0x100 | self.s as u16, v);
        self.s = self.s.wrapping_sub(1);
    }

    #[inline(always)]
    fn pull<B: Bus>(&mut self, bus: &mut B) -> u8 {
        self.s = self.s.wrapping_add(1);
        bus.read(0x100 | self.s as u16)
    }

    #[inline(always)]
    fn set_nz(&mut self, v: u8) {
        self.p = (self.p & !(F_N | F_Z)) | (v & F_N) | if v == 0 { F_Z } else { 0 };
    }

    #[inline(always)]
    fn set_flag(&mut self, f: u8, on: bool) {
        if on {
            self.p |= f;
        } else {
            self.p &= !f;
        }
    }

    /// Effective address and whether an indexed access crossed a page.
    #[inline(always)]
    fn ea<B: Bus>(&mut self, bus: &mut B, mode: u8) -> (u16, bool) {
        match mode {
            IMM => {
                let a = self.pc;
                self.pc = self.pc.wrapping_add(1);
                (a, false)
            }
            ZP => (self.fetch(bus) as u16, false),
            ZPX => (self.fetch(bus).wrapping_add(self.x) as u16, false),
            ZPY => (self.fetch(bus).wrapping_add(self.y) as u16, false),
            ABS => (self.fetch16(bus), false),
            ABX => {
                let b = self.fetch16(bus);
                let a = b.wrapping_add(self.x as u16);
                (a, (b ^ a) & 0xFF00 != 0)
            }
            ABY => {
                let b = self.fetch16(bus);
                let a = b.wrapping_add(self.y as u16);
                (a, (b ^ a) & 0xFF00 != 0)
            }
            IZX => {
                let p = self.fetch(bus).wrapping_add(self.x);
                let lo = bus.read(p as u16) as u16;
                let hi = bus.read(p.wrapping_add(1) as u16) as u16;
                (lo | hi << 8, false)
            }
            IZY => {
                let p = self.fetch(bus);
                let lo = bus.read(p as u16) as u16;
                let hi = bus.read(p.wrapping_add(1) as u16) as u16;
                let b = lo | hi << 8;
                let a = b.wrapping_add(self.y as u16);
                (a, (b ^ a) & 0xFF00 != 0)
            }
            IND => {
                let p = self.fetch16(bus);
                let lo = bus.read(p) as u16;
                let hi = bus.read((p & 0xFF00) | (p.wrapping_add(1) & 0x00FF)) as u16;
                (lo | hi << 8, false)
            }
            _ => (0, false),
        }
    }

    fn interrupt<B: Bus>(&mut self, bus: &mut B, vector: u16) -> u32 {
        self.push(bus, (self.pc >> 8) as u8);
        self.push(bus, self.pc as u8);
        self.push(bus, (self.p & !F_B) | F_U);
        self.p |= F_I;
        self.pc = self.read16(bus, vector);
        self.cycles += 7;
        7
    }

    /// Runs one instruction (or takes a pending interrupt); returns the cycles used.
    pub fn step<B: Bus>(&mut self, bus: &mut B) -> u32 {
        if self.halted {
            self.cycles += 2;
            return 2;
        }
        let i_flag = if self.i_lag { self.i_old } else { self.p & F_I };
        self.i_lag = false;
        if self.nmi_pending {
            self.nmi_pending = false;
            return self.interrupt(bus, 0xFFFA);
        }
        if self.irq_line && i_flag == 0 {
            return self.interrupt(bus, 0xFFFE);
        }

        let op = self.fetch(bus);
        let info = CYC[op as usize];
        let mut cyc = (info & 0x7F) as u32;
        let (addr, crossed) = self.ea(bus, MODE[op as usize]);
        if crossed && info & PEN != 0 {
            cyc += 1;
        }
        let old_i = self.p & F_I;

        match op {
            0x00 => {
                self.pc = self.pc.wrapping_add(1);
                self.push(bus, (self.pc >> 8) as u8);
                self.push(bus, self.pc as u8);
                self.push(bus, self.p | F_B | F_U);
                self.p |= F_I;
                self.pc = self.read16(bus, 0xFFFE);
            }
            0x01 | 0x05 | 0x09 | 0x0D | 0x11 | 0x15 | 0x19 | 0x1D => {
                self.a |= bus.read(addr);
                self.set_nz(self.a);
            }
            0x21 | 0x25 | 0x29 | 0x2D | 0x31 | 0x35 | 0x39 | 0x3D => {
                self.a &= bus.read(addr);
                self.set_nz(self.a);
            }
            0x41 | 0x45 | 0x49 | 0x4D | 0x51 | 0x55 | 0x59 | 0x5D => {
                self.a ^= bus.read(addr);
                self.set_nz(self.a);
            }
            0x61 | 0x65 | 0x69 | 0x6D | 0x71 | 0x75 | 0x79 | 0x7D => {
                let m = bus.read(addr);
                self.adc(m);
            }
            0xE1 | 0xE5 | 0xE9 | 0xEB | 0xED | 0xF1 | 0xF5 | 0xF9 | 0xFD => {
                let m = bus.read(addr);
                self.sbc(m);
            }
            0xA1 | 0xA5 | 0xA9 | 0xAD | 0xB1 | 0xB5 | 0xB9 | 0xBD => {
                self.a = bus.read(addr);
                self.set_nz(self.a);
            }
            0xA2 | 0xA6 | 0xAE | 0xB6 | 0xBE => {
                self.x = bus.read(addr);
                self.set_nz(self.x);
            }
            0xA0 | 0xA4 | 0xAC | 0xB4 | 0xBC => {
                self.y = bus.read(addr);
                self.set_nz(self.y);
            }
            0x81 | 0x85 | 0x8D | 0x91 | 0x95 | 0x99 | 0x9D => bus.write(addr, self.a),
            0x86 | 0x8E | 0x96 => bus.write(addr, self.x),
            0x84 | 0x8C | 0x94 => bus.write(addr, self.y),
            0xC1 | 0xC5 | 0xC9 | 0xCD | 0xD1 | 0xD5 | 0xD9 | 0xDD => {
                let m = bus.read(addr);
                self.compare(self.a, m);
            }
            0xE0 | 0xE4 | 0xEC => {
                let m = bus.read(addr);
                self.compare(self.x, m);
            }
            0xC0 | 0xC4 | 0xCC => {
                let m = bus.read(addr);
                self.compare(self.y, m);
            }
            0x24 | 0x2C => {
                let m = bus.read(addr);
                self.set_flag(F_Z, self.a & m == 0);
                self.p = (self.p & !(F_N | F_V)) | (m & (F_N | F_V));
            }

            // Read-modify-write.
            0x06 | 0x0E | 0x16 | 0x1E => {
                let m = bus.read(addr);
                let r = self.asl(m);
                bus.write(addr, r);
            }
            0x26 | 0x2E | 0x36 | 0x3E => {
                let m = bus.read(addr);
                let r = self.rol(m);
                bus.write(addr, r);
            }
            0x46 | 0x4E | 0x56 | 0x5E => {
                let m = bus.read(addr);
                let r = self.lsr(m);
                bus.write(addr, r);
            }
            0x66 | 0x6E | 0x76 | 0x7E => {
                let m = bus.read(addr);
                let r = self.ror(m);
                bus.write(addr, r);
            }
            0xC6 | 0xCE | 0xD6 | 0xDE => {
                let r = bus.read(addr).wrapping_sub(1);
                self.set_nz(r);
                bus.write(addr, r);
            }
            0xE6 | 0xEE | 0xF6 | 0xFE => {
                let r = bus.read(addr).wrapping_add(1);
                self.set_nz(r);
                bus.write(addr, r);
            }
            0x0A => self.a = self.asl(self.a),
            0x2A => self.a = self.rol(self.a),
            0x4A => self.a = self.lsr(self.a),
            0x6A => self.a = self.ror(self.a),

            // Implied.
            0x08 => self.push(bus, self.p | F_B | F_U),
            0x28 => {
                self.p = (self.pull(bus) & !F_B) | F_U;
                self.i_lag = true;
            }
            0x48 => self.push(bus, self.a),
            0x68 => {
                self.a = self.pull(bus);
                self.set_nz(self.a);
            }
            0x18 => self.p &= !F_C,
            0x38 => self.p |= F_C,
            0x58 => {
                self.p &= !F_I;
                self.i_lag = true;
            }
            0x78 => {
                self.p |= F_I;
                self.i_lag = true;
            }
            0xB8 => self.p &= !F_V,
            0xD8 => self.p &= !F_D,
            0xF8 => self.p |= F_D,
            0x88 => {
                self.y = self.y.wrapping_sub(1);
                self.set_nz(self.y);
            }
            0xC8 => {
                self.y = self.y.wrapping_add(1);
                self.set_nz(self.y);
            }
            0xCA => {
                self.x = self.x.wrapping_sub(1);
                self.set_nz(self.x);
            }
            0xE8 => {
                self.x = self.x.wrapping_add(1);
                self.set_nz(self.x);
            }
            0x8A => {
                self.a = self.x;
                self.set_nz(self.a);
            }
            0x98 => {
                self.a = self.y;
                self.set_nz(self.a);
            }
            0xA8 => {
                self.y = self.a;
                self.set_nz(self.y);
            }
            0xAA => {
                self.x = self.a;
                self.set_nz(self.x);
            }
            0xBA => {
                self.x = self.s;
                self.set_nz(self.x);
            }
            0x9A => self.s = self.x,
            0xEA => {}

            // Control flow.
            0x20 => {
                let ret = self.pc.wrapping_sub(1);
                self.push(bus, (ret >> 8) as u8);
                self.push(bus, ret as u8);
                self.pc = addr;
            }
            0x4C | 0x6C => self.pc = addr,
            0x60 => {
                let lo = self.pull(bus) as u16;
                let hi = self.pull(bus) as u16;
                self.pc = (lo | hi << 8).wrapping_add(1);
            }
            0x40 => {
                self.p = (self.pull(bus) & !F_B) | F_U;
                let lo = self.pull(bus) as u16;
                let hi = self.pull(bus) as u16;
                self.pc = lo | hi << 8;
            }
            0x10 => cyc += self.branch(bus, self.p & F_N == 0),
            0x30 => cyc += self.branch(bus, self.p & F_N != 0),
            0x50 => cyc += self.branch(bus, self.p & F_V == 0),
            0x70 => cyc += self.branch(bus, self.p & F_V != 0),
            0x90 => cyc += self.branch(bus, self.p & F_C == 0),
            0xB0 => cyc += self.branch(bus, self.p & F_C != 0),
            0xD0 => cyc += self.branch(bus, self.p & F_Z == 0),
            0xF0 => cyc += self.branch(bus, self.p & F_Z != 0),

            // Undocumented read-modify-write combinations.
            0x03 | 0x07 | 0x0F | 0x13 | 0x17 | 0x1B | 0x1F => {
                let m = bus.read(addr);
                let r = self.asl(m);
                bus.write(addr, r);
                self.a |= r;
                self.set_nz(self.a);
            }
            0x23 | 0x27 | 0x2F | 0x33 | 0x37 | 0x3B | 0x3F => {
                let m = bus.read(addr);
                let r = self.rol(m);
                bus.write(addr, r);
                self.a &= r;
                self.set_nz(self.a);
            }
            0x43 | 0x47 | 0x4F | 0x53 | 0x57 | 0x5B | 0x5F => {
                let m = bus.read(addr);
                let r = self.lsr(m);
                bus.write(addr, r);
                self.a ^= r;
                self.set_nz(self.a);
            }
            0x63 | 0x67 | 0x6F | 0x73 | 0x77 | 0x7B | 0x7F => {
                let m = bus.read(addr);
                let r = self.ror(m);
                bus.write(addr, r);
                self.adc(r);
            }
            0xC3 | 0xC7 | 0xCF | 0xD3 | 0xD7 | 0xDB | 0xDF => {
                let r = bus.read(addr).wrapping_sub(1);
                bus.write(addr, r);
                self.compare(self.a, r);
            }
            0xE3 | 0xE7 | 0xEF | 0xF3 | 0xF7 | 0xFB | 0xFF => {
                let r = bus.read(addr).wrapping_add(1);
                bus.write(addr, r);
                self.sbc(r);
            }
            0x83 | 0x87 | 0x8F | 0x97 => bus.write(addr, self.a & self.x),
            0xA3 | 0xA7 | 0xAF | 0xB3 | 0xB7 | 0xBF => {
                let m = bus.read(addr);
                self.a = m;
                self.x = m;
                self.set_nz(m);
            }
            0xAB => {
                let m = bus.read(addr);
                self.a = m;
                self.x = m;
                self.set_nz(m);
            }
            0xBB => {
                let v = bus.read(addr) & self.s;
                self.a = v;
                self.x = v;
                self.s = v;
                self.set_nz(v);
            }
            0x0B | 0x2B => {
                self.a &= bus.read(addr);
                self.set_nz(self.a);
                self.set_flag(F_C, self.a & 0x80 != 0);
            }
            0x4B => {
                self.a &= bus.read(addr);
                self.a = self.lsr(self.a);
            }
            0x6B => {
                let t = self.a & bus.read(addr);
                self.arr(t);
            }
            0x8B => {
                self.a = (self.a | 0xEE) & self.x & bus.read(addr);
                self.set_nz(self.a);
            }
            0xCB => {
                let m = bus.read(addr);
                let ax = self.a & self.x;
                self.set_flag(F_C, ax >= m);
                self.x = ax.wrapping_sub(m);
                self.set_nz(self.x);
            }
            0x93 | 0x9F => {
                let hi = ((addr.wrapping_sub(self.y as u16) >> 8) as u8).wrapping_add(1);
                let v = self.a & self.x & hi;
                self.store_unstable(bus, addr, crossed, v);
            }
            0x9B => {
                self.s = self.a & self.x;
                let hi = ((addr.wrapping_sub(self.y as u16) >> 8) as u8).wrapping_add(1);
                let v = self.s & hi;
                self.store_unstable(bus, addr, crossed, v);
            }
            0x9C => {
                let hi = ((addr.wrapping_sub(self.x as u16) >> 8) as u8).wrapping_add(1);
                let v = self.y & hi;
                self.store_unstable(bus, addr, crossed, v);
            }
            0x9E => {
                let hi = ((addr.wrapping_sub(self.y as u16) >> 8) as u8).wrapping_add(1);
                let v = self.x & hi;
                self.store_unstable(bus, addr, crossed, v);
            }

            // NOP variants with operands: the operand is read for its bus side effects.
            0x04 | 0x44 | 0x64 | 0x0C | 0x14 | 0x34 | 0x54 | 0x74 | 0xD4 | 0xF4 | 0x1C | 0x3C
            | 0x5C | 0x7C | 0xDC | 0xFC | 0x80 | 0x82 | 0x89 | 0xC2 | 0xE2 => {
                let _ = bus.read(addr);
            }
            0x1A | 0x3A | 0x5A | 0x7A | 0xDA | 0xFA => {}

            // KIL/JAM: 0x02 0x12 0x22 0x32 0x42 0x52 0x62 0x72 0x92 0xB2 0xD2 0xF2
            _ => {
                self.halted = true;
                self.pc = self.pc.wrapping_sub(1);
            }
        }

        if self.i_lag {
            self.i_old = old_i;
        }
        self.cycles += cyc as u64;
        cyc
    }

    #[inline(always)]
    fn branch<B: Bus>(&mut self, bus: &mut B, taken: bool) -> u32 {
        let off = self.fetch(bus) as i8 as u16;
        if !taken {
            return 0;
        }
        let old = self.pc;
        self.pc = old.wrapping_add(off);
        if (old ^ self.pc) & 0xFF00 != 0 {
            2
        } else {
            1
        }
    }

    #[inline(always)]
    fn compare(&mut self, r: u8, m: u8) {
        self.set_flag(F_C, r >= m);
        self.set_nz(r.wrapping_sub(m));
    }

    #[inline(always)]
    fn asl(&mut self, v: u8) -> u8 {
        self.set_flag(F_C, v & 0x80 != 0);
        let r = v << 1;
        self.set_nz(r);
        r
    }

    #[inline(always)]
    fn lsr(&mut self, v: u8) -> u8 {
        self.set_flag(F_C, v & 1 != 0);
        let r = v >> 1;
        self.set_nz(r);
        r
    }

    #[inline(always)]
    fn rol(&mut self, v: u8) -> u8 {
        let c = self.p & F_C;
        self.set_flag(F_C, v & 0x80 != 0);
        let r = v << 1 | c;
        self.set_nz(r);
        r
    }

    #[inline(always)]
    fn ror(&mut self, v: u8) -> u8 {
        let c = self.p & F_C;
        self.set_flag(F_C, v & 1 != 0);
        let r = v >> 1 | c << 7;
        self.set_nz(r);
        r
    }

    fn adc(&mut self, m: u8) {
        let a = self.a;
        let c = (self.p & F_C) as u16;
        if self.p & F_D == 0 {
            let sum = a as u16 + m as u16 + c;
            let r = sum as u8;
            self.set_flag(F_C, sum > 0xFF);
            self.set_flag(F_V, (a ^ r) & (m ^ r) & 0x80 != 0);
            self.set_nz(r);
            self.a = r;
        } else {
            // NMOS: Z from the binary sum, N/V from the intermediate, C from the corrected value.
            let bin = (a as u16 + m as u16 + c) as u8;
            let mut lo = (a & 0x0F) as u16 + (m & 0x0F) as u16 + c;
            if lo >= 0x0A {
                lo = ((lo + 6) & 0x0F) + 0x10;
            }
            let mut r = (a & 0xF0) as u16 + (m & 0xF0) as u16 + lo;
            self.set_flag(F_Z, bin == 0);
            self.set_flag(F_N, r & 0x80 != 0);
            self.set_flag(F_V, (a as u16 ^ r) & (m as u16 ^ r) & 0x80 != 0);
            if r >= 0xA0 {
                r += 0x60;
            }
            self.set_flag(F_C, r >= 0x100);
            self.a = r as u8;
        }
    }

    fn sbc(&mut self, m: u8) {
        if self.p & F_D == 0 {
            self.adc(!m);
        } else {
            let a = self.a;
            let c = (self.p & F_C) as i16;
            // Flags are those of the binary subtraction.
            let sum = a as u16 + (!m) as u16 + c as u16;
            let r = sum as u8;
            self.set_flag(F_C, sum > 0xFF);
            self.set_flag(F_V, (a ^ r) & (!m ^ r) & 0x80 != 0);
            self.set_nz(r);
            let mut lo = (a & 0x0F) as i16 - (m & 0x0F) as i16 + c - 1;
            if lo < 0 {
                lo = ((lo - 6) & 0x0F) - 0x10;
            }
            let mut v = (a & 0xF0) as i16 - (m & 0xF0) as i16 + lo;
            if v < 0 {
                v -= 0x60;
            }
            self.a = v as u8;
        }
    }

    fn arr(&mut self, t: u8) {
        let cin = self.p & F_C;
        let mut r = t >> 1 | cin << 7;
        self.set_nz(r);
        if self.p & F_D == 0 {
            self.set_flag(F_C, r & 0x40 != 0);
            self.set_flag(F_V, (r ^ r << 1) & 0x40 != 0);
        } else {
            self.set_flag(F_V, (t ^ r) & 0x40 != 0);
            if (t & 0x0F) + (t & 1) > 5 {
                r = (r & 0xF0) | (r.wrapping_add(6) & 0x0F);
            }
            if (t as u16 & 0xF0) + (t as u16 & 0x10) > 0x50 {
                r = r.wrapping_add(0x60);
                self.p |= F_C;
            } else {
                self.p &= !F_C;
            }
        }
        self.a = r;
    }

    fn store_unstable<B: Bus>(&mut self, bus: &mut B, addr: u16, crossed: bool, v: u8) {
        let a = if crossed { (addr & 0x00FF) | (v as u16) << 8 } else { addr };
        bus.write(a, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::boxed::Box;

    struct Ram(Box<[u8; 65536]>);

    impl Ram {
        fn new() -> Self {
            Ram(Box::new([0u8; 65536]))
        }
        fn load(&mut self, at: u16, bytes: &[u8]) {
            for (i, b) in bytes.iter().enumerate() {
                self.0[at as usize + i] = *b;
            }
        }
    }

    impl Bus for Ram {
        fn read(&mut self, a: u16) -> u8 {
            self.0[a as usize]
        }
        fn write(&mut self, a: u16, v: u8) {
            self.0[a as usize] = v;
        }
    }

    fn setup(code: &[u8]) -> (Cpu, Ram) {
        let mut ram = Ram::new();
        ram.load(0x0200, code);
        ram.load(0xFFFC, &[0x00, 0x02]);
        ram.load(0xFFFE, &[0x00, 0x30]);
        ram.load(0xFFFA, &[0x00, 0x40]);
        let mut cpu = Cpu::new();
        cpu.reset(&mut ram);
        (cpu, ram)
    }

    fn run(cpu: &mut Cpu, ram: &mut Ram, n: usize) {
        for _ in 0..n {
            cpu.step(ram);
        }
    }

    #[test]
    fn reset_vector() {
        let (cpu, _) = setup(&[]);
        assert_eq!(cpu.pc, 0x0200);
        assert_ne!(cpu.p & F_I, 0);
    }

    #[test]
    fn decimal_adc() {
        // SED CLC LDA #$58 ADC #$46 -> $04 C=1
        let (mut cpu, mut ram) = setup(&[0xF8, 0x18, 0xA9, 0x58, 0x69, 0x46]);
        run(&mut cpu, &mut ram, 4);
        assert_eq!(cpu.a, 0x04);
        assert_ne!(cpu.p & F_C, 0);
        // $99 + $01 = $00 C=1, Z set from binary sum? binary = $9A so Z clear on NMOS
        let (mut cpu, mut ram) = setup(&[0xF8, 0x18, 0xA9, 0x99, 0x69, 0x01]);
        run(&mut cpu, &mut ram, 4);
        assert_eq!(cpu.a, 0x00);
        assert_ne!(cpu.p & F_C, 0);
        assert_eq!(cpu.p & F_Z, 0);
    }

    #[test]
    fn decimal_sbc() {
        // SED SEC LDA #$46 SBC #$12 -> $34 C=1
        let (mut cpu, mut ram) = setup(&[0xF8, 0x38, 0xA9, 0x46, 0xE9, 0x12]);
        run(&mut cpu, &mut ram, 4);
        assert_eq!(cpu.a, 0x34);
        assert_ne!(cpu.p & F_C, 0);
        // $00 - $01 = $99 C=0
        let (mut cpu, mut ram) = setup(&[0xF8, 0x38, 0xA9, 0x00, 0xE9, 0x01]);
        run(&mut cpu, &mut ram, 4);
        assert_eq!(cpu.a, 0x99);
        assert_eq!(cpu.p & F_C, 0);
    }

    #[test]
    fn binary_overflow() {
        // CLC LDA #$50 ADC #$50 -> $A0, V=1, N=1
        let (mut cpu, mut ram) = setup(&[0x18, 0xA9, 0x50, 0x69, 0x50]);
        run(&mut cpu, &mut ram, 3);
        assert_eq!(cpu.a, 0xA0);
        assert_ne!(cpu.p & F_V, 0);
        assert_ne!(cpu.p & F_N, 0);
        assert_eq!(cpu.p & F_C, 0);
    }

    #[test]
    fn page_cross_penalty() {
        // LDX #1; LDA $12FF,X (cross: 5); LDA $1200,X (4); STA $12FF,X (5 always)
        let (mut cpu, mut ram) = setup(&[0xA2, 0x01, 0xBD, 0xFF, 0x12, 0xBD, 0x00, 0x12, 0x9D, 0xFF, 0x12]);
        assert_eq!(cpu.step(&mut ram), 2);
        assert_eq!(cpu.step(&mut ram), 5);
        assert_eq!(cpu.step(&mut ram), 4);
        assert_eq!(cpu.step(&mut ram), 5);
    }

    #[test]
    fn indirect_indexed_cycles() {
        // LDY #1; LDA ($10),Y with $10 -> $12FF crosses
        let (mut cpu, mut ram) = setup(&[0xA0, 0x01, 0xB1, 0x10, 0xB1, 0x12]);
        ram.load(0x10, &[0xFF, 0x12, 0x00, 0x12]);
        cpu.step(&mut ram);
        assert_eq!(cpu.step(&mut ram), 6);
        assert_eq!(cpu.step(&mut ram), 5);
    }

    #[test]
    fn branch_cycles() {
        // BNE not taken (Z set): 2; BEQ taken same page: 3; taken across page: 4
        let (mut cpu, mut ram) = setup(&[0xA9, 0x00, 0xD0, 0x10, 0xF0, 0x02]);
        cpu.step(&mut ram);
        assert_eq!(cpu.step(&mut ram), 2);
        assert_eq!(cpu.step(&mut ram), 3);
        assert_eq!(cpu.pc, 0x0208);
        ram.load(0x02F0, &[0xF0, 0x20]);
        cpu.pc = 0x02F0;
        assert_eq!(cpu.step(&mut ram), 4);
        assert_eq!(cpu.pc, 0x0312);
    }

    #[test]
    fn zero_page_wrap() {
        // LDX #2; LDA $FF,X reads $0001
        let (mut cpu, mut ram) = setup(&[0xA2, 0x02, 0xB5, 0xFF]);
        ram.0[1] = 0x77;
        ram.0[0x101] = 0x11;
        run(&mut cpu, &mut ram, 2);
        assert_eq!(cpu.a, 0x77);
    }

    #[test]
    fn indexed_indirect_zp_wrap() {
        // LDX #0; LDA ($FF,X): pointer bytes at $FF and $00
        let (mut cpu, mut ram) = setup(&[0xA2, 0x00, 0xA1, 0xFF]);
        ram.0[0xFF] = 0x34;
        ram.0[0x00] = 0x12;
        ram.0[0x1234] = 0x5A;
        run(&mut cpu, &mut ram, 2);
        assert_eq!(cpu.a, 0x5A);
    }

    #[test]
    fn jmp_indirect_bug() {
        let (mut cpu, mut ram) = setup(&[0x6C, 0xFF, 0x10]);
        ram.0[0x10FF] = 0x34;
        ram.0[0x1000] = 0x12;
        ram.0[0x1100] = 0x99;
        assert_eq!(cpu.step(&mut ram), 5);
        assert_eq!(cpu.pc, 0x1234);
    }

    #[test]
    fn brk_rti() {
        let (mut cpu, mut ram) = setup(&[0x00, 0xEA, 0xEA]);
        ram.load(0x3000, &[0x40]);
        let sp = cpu.s;
        assert_eq!(cpu.step(&mut ram), 7);
        assert_eq!(cpu.pc, 0x3000);
        assert_eq!(cpu.s, sp.wrapping_sub(3));
        assert_eq!(ram.0[0x100 + sp as usize], 0x02);
        assert_eq!(ram.0[0x100 + sp as usize - 1], 0x02);
        assert_ne!(ram.0[0x100 + sp as usize - 2] & F_B, 0);
        assert_eq!(cpu.step(&mut ram), 6);
        assert_eq!(cpu.pc, 0x0202);
        assert_eq!(cpu.s, sp);
    }

    #[test]
    fn php_plp_b_flag() {
        // PHP; PLA -> B and bit 5 set in pushed value
        let (mut cpu, mut ram) = setup(&[0x08, 0x68]);
        run(&mut cpu, &mut ram, 2);
        assert_eq!(cpu.a & 0x30, 0x30);
    }

    #[test]
    fn jsr_rts() {
        let (mut cpu, mut ram) = setup(&[0x20, 0x00, 0x30, 0xEA]);
        ram.load(0x3000, &[0x60]);
        assert_eq!(cpu.step(&mut ram), 6);
        assert_eq!(cpu.step(&mut ram), 6);
        assert_eq!(cpu.pc, 0x0203);
    }

    #[test]
    fn irq_masked_and_taken() {
        // SEI state after reset: IRQ ignored, then CLI, NOP, IRQ taken after CLI latency
        let (mut cpu, mut ram) = setup(&[0xEA, 0x58, 0xEA, 0xEA]);
        cpu.set_irq(true);
        cpu.step(&mut ram);
        assert_eq!(cpu.pc, 0x0201);
        cpu.step(&mut ram); // CLI
        assert_eq!(cpu.pc, 0x0202);
        cpu.step(&mut ram); // NOP still runs (latency)
        assert_eq!(cpu.pc, 0x0203);
        assert_eq!(cpu.step(&mut ram), 7);
        assert_eq!(cpu.pc, 0x3000);
        let pushed = ram.0[0x100 + cpu.s as usize + 1];
        assert_eq!(pushed & F_B, 0);
        assert_ne!(cpu.p & F_I, 0);
    }

    #[test]
    fn nmi_priority_and_edge() {
        let (mut cpu, mut ram) = setup(&[0x58, 0xEA, 0xEA, 0xEA]);
        cpu.step(&mut ram);
        cpu.step(&mut ram);
        cpu.set_irq(true);
        cpu.nmi();
        assert_eq!(cpu.step(&mut ram), 7);
        assert_eq!(cpu.pc, 0x4000);
        // NMI is consumed; the IRQ stays masked by I set during entry.
        ram.load(0x4000, &[0xEA]);
        cpu.step(&mut ram);
        assert_eq!(cpu.pc, 0x4001);
    }

    #[test]
    fn undocumented_basics() {
        // LAX $10; SAX $11; DCP $10; ISC $12
        let (mut cpu, mut ram) = setup(&[0xA7, 0x10, 0xA9, 0x0F, 0x87, 0x11, 0xC7, 0x10]);
        ram.0[0x10] = 0x81;
        cpu.step(&mut ram);
        assert_eq!((cpu.a, cpu.x), (0x81, 0x81));
        cpu.step(&mut ram);
        cpu.step(&mut ram);
        assert_eq!(ram.0[0x11], 0x0F & 0x81);
        cpu.step(&mut ram);
        assert_eq!(ram.0[0x10], 0x80);
    }

    #[test]
    fn nop_variant_lengths() {
        let (mut cpu, mut ram) = setup(&[0x80, 0x00, 0x04, 0x00, 0x0C, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x14, 0x00]);
        assert_eq!(cpu.step(&mut ram), 2);
        assert_eq!(cpu.pc, 0x0202);
        assert_eq!(cpu.step(&mut ram), 3);
        assert_eq!(cpu.pc, 0x0204);
        assert_eq!(cpu.step(&mut ram), 4);
        assert_eq!(cpu.pc, 0x0207);
        assert_eq!(cpu.step(&mut ram), 4);
        assert_eq!(cpu.pc, 0x020A);
        assert_eq!(cpu.step(&mut ram), 4);
        assert_eq!(cpu.pc, 0x020C);
    }

    #[test]
    fn kil_halts() {
        let (mut cpu, mut ram) = setup(&[0x02]);
        cpu.step(&mut ram);
        assert!(cpu.is_halted());
        assert_eq!(cpu.pc, 0x0200);
        cpu.step(&mut ram);
        assert_eq!(cpu.pc, 0x0200);
    }

    #[test]
    fn all_opcodes_execute() {
        for op in 0..=255u8 {
            let (mut cpu, mut ram) = setup(&[op, 0x10, 0x10]);
            cpu.step(&mut ram);
        }
    }

    fn run_trap(path: &str, load: u16, start: u16, limit: u64) -> (u16, Cpu, Ram) {
        let data = std::fs::read(path).expect("read test binary");
        let mut ram = Ram::new();
        ram.load(load, &data);
        let mut cpu = Cpu::new();
        cpu.pc = start;
        cpu.p = 0x24;
        let mut n = 0u64;
        loop {
            let pc = cpu.pc;
            cpu.step(&mut ram);
            if cpu.pc == pc {
                return (pc, cpu, ram);
            }
            n += 1;
            assert!(n < limit, "no trap after {} instructions, pc={:04x}", n, cpu.pc);
        }
    }

    #[test]
    #[ignore]
    fn klaus_functional() {
        let path = std::env::var("KLAUS_BIN").expect("KLAUS_BIN not set");
        let success = std::env::var("KLAUS_SUCCESS")
            .ok()
            .and_then(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0x3469);
        let (pc, cpu, _) = run_trap(&path, 0, 0x0400, 200_000_000);
        assert_eq!(pc, success, "trapped at {:04x}, cycles {}", pc, cpu.cycles);
    }

    #[test]
    #[ignore]
    fn klaus_decimal() {
        let path = std::env::var("KLAUS_DEC_BIN").expect("KLAUS_DEC_BIN not set");
        let done = std::env::var("KLAUS_DEC_DONE")
            .ok()
            .and_then(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).ok());
        let (pc, _, ram) = run_trap(&path, 0x0200, 0x0200, 2_000_000_000);
        if let Some(d) = done {
            assert_eq!(pc, d);
        }
        assert_eq!(ram.0[0x0B], 0, "decimal test ERROR byte, trapped at {:04x}", pc);
    }
}
