// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! liboos — the runtime library for ospab.os user programs.
//!
//! Provides the process entry point (`_start`), system call wrappers, a heap for
//! `alloc`, `print!`/`println!`, and a panic handler. A program looks like:
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//! liboos::entry!(main);
//! fn main(args: liboos::Args) -> i32 {
//!     liboos::println!("hello");
//!     0
//! }
//! ```
#![no_std]

extern crate alloc;

pub mod sys;
pub mod ipc;
mod heap;
mod rt;

pub use rt::Args;

/// Write bytes to a file descriptor (1 = stdout, 2 = stderr). Returns bytes written or a negative error.
pub fn write(fd: u64, bytes: &[u8]) -> i64 {
    unsafe { sys::syscall3(sys::nr::WRITE, fd, bytes.as_ptr() as u64, bytes.len() as u64) }
}

/// Terminate the calling process with `code`.
pub fn exit(code: i32) -> ! {
    unsafe {
        sys::syscall1(sys::nr::EXIT, code as u64);
    }
    // exit never returns; if it somehow did, trap.
    loop {
        unsafe { core::arch::asm!("ud2", options(noreturn)) };
    }
}

/// Process id of the caller.
pub fn getpid() -> u32 {
    unsafe { sys::syscall0(sys::nr::GETPID) as u32 }
}

/// Give up the rest of the time slice.
pub fn yield_now() {
    unsafe {
        sys::syscall0(sys::nr::YIELD);
    }
}

/// Timer ticks since boot (100 Hz).
pub fn uptime_ticks() -> u64 {
    unsafe { sys::syscall0(sys::nr::UPTIME) as u64 }
}

/// Map `size` bytes of fresh zeroed memory. Returns the address or a negative error.
pub fn mmap(size: usize) -> Result<*mut u8, i64> {
    let r = unsafe { sys::syscall3(sys::nr::MMAP, 0, size as u64, 0) };
    if r <= 0 { Err(r) } else { Ok(r as *mut u8) }
}

/// Unmap memory returned by `mmap`.
pub fn munmap(ptr: *mut u8, size: usize) -> i64 {
    unsafe { sys::syscall2(sys::nr::MUNMAP, ptr as u64, size as u64) }
}

#[doc(hidden)]
pub struct Stdout;

impl core::fmt::Write for Stdout {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if write(1, s.as_bytes()) < 0 { Err(core::fmt::Error) } else { Ok(()) }
    }
}

#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments) {
    let _ = core::fmt::Write::write_fmt(&mut Stdout, args);
}

/// Print to stdout.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::_print(format_args!($($arg)*)) };
}

/// Print to stdout with a trailing newline.
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::_print(format_args!("{}\n", format_args!($($arg)*))) };
}

/// Declare the program's entry function: `fn main(args: liboos::Args) -> i32`.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[no_mangle]
        pub extern "Rust" fn __oos_main(args: $crate::Args) -> i32 {
            $main(args)
        }
    };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let _ = core::fmt::Write::write_fmt(&mut Stdout, format_args!("panic: {}\n", info));
    exit(101)
}
