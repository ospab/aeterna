/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Firmware services used before ExitBootServices: console, page/pool allocation,
the `alloc` heap. Nothing here may be called after ExitBootServices.
*/
use core::alloc::{GlobalAlloc, Layout};
use core::fmt;
use core::ptr;

use crate::efi::*;

static mut ST: *mut SystemTable = ptr::null_mut();
static mut BOOT_SERVICES_ACTIVE: bool = false;

pub unsafe fn init(st: *mut SystemTable) {
    ST = st;
    BOOT_SERVICES_ACTIVE = true;
}

pub fn st() -> &'static SystemTable {
    unsafe { &*ST }
}

pub fn bs() -> &'static BootServices {
    unsafe {
        assert!(BOOT_SERVICES_ACTIVE, "boot services used after exit");
        &*(*ST).boot_services
    }
}

/// Called right before ExitBootServices: any later firmware call is a bug.
pub fn boot_services_done() {
    unsafe { BOOT_SERVICES_ACTIVE = false };
}

// ─── Console ────────────────────────────────────────────────────────────────

pub struct Console;

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        unsafe {
            if !BOOT_SERVICES_ACTIVE {
                serial_write(s);
                return Ok(());
            }
            let out = (*ST).con_out;
            let mut buf = [0u16; 129];
            let mut n = 0;
            let flush = |buf: &mut [u16; 129], n: &mut usize| {
                buf[*n] = 0;
                ((*out).output_string)(out, buf.as_ptr());
                *n = 0;
            };
            for c in s.chars() {
                if c == '\n' {
                    buf[n] = b'\r' as u16;
                    n += 1;
                }
                buf[n] = if (c as u32) < 0x10000 { c as u16 } else { b'?' as u16 };
                n += 1;
                if n >= 126 {
                    flush(&mut buf, &mut n);
                }
            }
            if n > 0 {
                flush(&mut buf, &mut n);
            }
        }
        Ok(())
    }
}

/// COM1, for the few messages after ExitBootServices (firmware already set it up).
unsafe fn serial_write(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            serial_byte(b'\r');
        }
        serial_byte(b);
    }
}

unsafe fn serial_byte(b: u8) {
    for _ in 0..100_000 {
        let lsr: u8;
        core::arch::asm!("in al, dx", out("al") lsr, in("dx") 0x3FDu16, options(nomem, nostack));
        if lsr & 0x20 != 0 {
            break;
        }
    }
    core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") b, options(nomem, nostack));
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let _ = core::fmt::Write::write_fmt(&mut $crate::console::Console, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{ $crate::print!($($arg)*); $crate::print!("\n"); }};
}

// ─── Memory ─────────────────────────────────────────────────────────────────

pub const PAGE: u64 = 4096;

/// Allocate `pages` zeroed 4 KiB pages anywhere, tagged with `mem_type`.
pub fn alloc_pages(pages: usize, mem_type: u32) -> u64 {
    let mut addr = 0u64;
    let s = unsafe { (bs().allocate_pages)(ALLOCATE_ANY_PAGES, mem_type, pages, &mut addr) };
    if is_error(s) {
        panic!("out of memory ({} pages)", pages);
    }
    unsafe { ptr::write_bytes(addr as *mut u8, 0, pages * PAGE as usize) };
    addr
}

struct PoolAlloc;

unsafe impl GlobalAlloc for PoolAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Pool memory is 8-byte aligned; over-allocate for bigger alignments and
        // keep the original pointer just below the returned one.
        let align = layout.align().max(8);
        let size = layout.size() + align + 8;
        let mut p: *mut u8 = ptr::null_mut();
        if is_error((bs().allocate_pool)(LOADER_DATA, size, &mut p)) {
            return ptr::null_mut();
        }
        let user = ((p as usize + 8 + align - 1) & !(align - 1)) as *mut u8;
        *(user as *mut *mut u8).sub(1) = p;
        user
    }

    unsafe fn dealloc(&self, user: *mut u8, _layout: Layout) {
        let p = *(user as *mut *mut u8).sub(1);
        (bs().free_pool)(p);
    }
}

#[global_allocator]
static HEAP: PoolAlloc = PoolAlloc;
