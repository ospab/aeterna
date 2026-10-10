// SPDX-License-Identifier: AGPL-3.0-only
//! Raw system calls. ABI: number in RAX, arguments in RDI, RSI, RDX, R10, R8;
//! result in RAX (negative = error). SYSCALL clobbers RCX and R11.

/// System call numbers. Must match `core/syscall/mod.rs` in the kernel.
pub mod nr {
    pub const EXIT: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const READ: u64 = 2;
    pub const OPEN: u64 = 3;
    pub const CLOSE: u64 = 4;
    pub const YIELD: u64 = 20;
    pub const GETPID: u64 = 22;
    pub const WAITPID: u64 = 32;
    pub const MMAP: u64 = 40;
    pub const MUNMAP: u64 = 41;
    pub const UPTIME: u64 = 51;
    pub const HANDLE_CLOSE: u64 = 200;
    pub const HANDLE_DUP: u64 = 201;
    pub const HANDLE_INFO: u64 = 202;
    pub const CHANNEL_CREATE: u64 = 210;
    pub const IPC_CALL: u64 = 211;
    pub const IPC_SEND: u64 = 212;
    pub const IPC_RECV: u64 = 213;
    pub const IPC_REPLY: u64 = 214;
    pub const NOTIFY_CREATE: u64 = 220;
    pub const NOTIFY_SIGNAL: u64 = 221;
    pub const NOTIFY_WAIT: u64 = 222;
    pub const PROCESS_SELF: u64 = 230;
    pub const THREAD_SELF: u64 = 231;
    pub const PROCESS_WAIT: u64 = 232;
    pub const PROCESS_KILL: u64 = 233;
    pub const MEM_CREATE: u64 = 240;
    pub const MEM_MAP: u64 = 241;
    pub const MEM_UNMAP: u64 = 242;
    pub const MEM_CREATE_CONTIG: u64 = 243;
    pub const MEM_PHYS: u64 = 244;
    pub const MEM_SIZE: u64 = 245;
    pub const IRQ_BIND: u64 = 250;
    pub const IRQ_ACK: u64 = 251;
    pub const IOPORT_ENABLE: u64 = 252;
    pub const IOPORT_DISABLE: u64 = 253;
}

/// Kernel error codes (negated in RAX).
pub mod err {
    pub const INVALID_SYSCALL: i64 = -1;
    pub const PERMISSION_DENIED: i64 = -2;
    pub const INVALID_ARGUMENT: i64 = -3;
    pub const NOT_FOUND: i64 = -4;
    pub const BUSY: i64 = -5;
    pub const OUT_OF_MEMORY: i64 = -6;
    pub const NOT_SUPPORTED: i64 = -7;
    pub const BAD_ADDRESS: i64 = -10;
    pub const BAD_HANDLE: i64 = -11;
    pub const WRONG_TYPE: i64 = -12;
    pub const PEER_CLOSED: i64 = -13;
    pub const TABLE_FULL: i64 = -14;
    pub const TIMEOUT: i64 = -15;
}

#[inline(always)]
pub unsafe fn syscall0(n: u64) -> i64 {
    let r: i64;
    core::arch::asm!("syscall", inlateout("rax") n as i64 => r,
        out("rcx") _, out("r11") _, options(nostack));
    r
}

#[inline(always)]
pub unsafe fn syscall1(n: u64, a1: u64) -> i64 {
    let r: i64;
    core::arch::asm!("syscall", inlateout("rax") n as i64 => r, in("rdi") a1,
        out("rcx") _, out("r11") _, options(nostack));
    r
}

#[inline(always)]
pub unsafe fn syscall2(n: u64, a1: u64, a2: u64) -> i64 {
    let r: i64;
    core::arch::asm!("syscall", inlateout("rax") n as i64 => r, in("rdi") a1, in("rsi") a2,
        out("rcx") _, out("r11") _, options(nostack));
    r
}

#[inline(always)]
pub unsafe fn syscall3(n: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let r: i64;
    core::arch::asm!("syscall", inlateout("rax") n as i64 => r, in("rdi") a1, in("rsi") a2,
        in("rdx") a3, out("rcx") _, out("r11") _, options(nostack));
    r
}
