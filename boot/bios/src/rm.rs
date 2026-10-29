/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Stage1, stage2 entry and the long mode <-> real mode thunk (rm.S), plus the Rust side:
`int()` calls a BIOS interrupt with a register block.
*/
use core::ptr;

pub const REGS_ADDR: usize = 0x6F00;
pub const RM_STACK: usize = 0x6E00;
pub const BOOT_DRIVE_ADDR: usize = 0x600;

core::arch::global_asm!(
    include_str!("rm.S"),
    regs = const REGS_ADDR,
    rmstack = const RM_STACK,
    bootdrv = const BOOT_DRIVE_ADDR,
);

extern "sysv64" {
    fn rm_call(int_no: u32);
}

/// Register block exchanged with the real-mode thunk (layout fixed by rm.S).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Regs {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub flags: u32,
    pub ds: u16,
    pub es: u16,
}

impl Regs {
    pub fn new() -> Regs {
        Regs::default()
    }

    pub fn carry(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn zero(&self) -> bool {
        self.flags & 0x40 != 0
    }

    pub fn ah(&self) -> u8 {
        (self.eax >> 8) as u8
    }

    pub fn ax(&self) -> u16 {
        self.eax as u16
    }

    /// Point ES:DI at a linear address below 1 MiB.
    pub fn es_di(&mut self, addr: u32) {
        self.es = (addr >> 4) as u16;
        self.edi = addr & 15;
    }

    /// Point DS:SI at a linear address below 1 MiB.
    pub fn ds_si(&mut self, addr: u32) {
        self.ds = (addr >> 4) as u16;
        self.esi = addr & 15;
    }
}

/// Run `int n` in real mode with the given registers; the results are stored back.
pub fn int(n: u8, r: &mut Regs) {
    unsafe {
        r.flags &= 0x0000_0001;
        ptr::copy_nonoverlapping(r as *const Regs as *const u8, REGS_ADDR as *mut u8, core::mem::size_of::<Regs>());
        rm_call(n as u32);
        ptr::copy_nonoverlapping(REGS_ADDR as *const u8, r as *mut Regs as *mut u8, 32);
    }
}

pub fn boot_drive() -> u8 {
    unsafe { ptr::read_volatile(BOOT_DRIVE_ADDR as *const u8) }
}
