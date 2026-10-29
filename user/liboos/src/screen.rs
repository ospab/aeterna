// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Screen, raw keyboard and clock for games and emulators (syscalls 21, 260..264, 270).
//! See docs/en/syscall-abi.md, "Screen, keyboard, clock".
//!
//! ```ignore
//! let fb = liboos::screen::acquire()?;       // console stops drawing
//! liboos::screen::kbd_raw(true);
//! loop {
//!     while let Some(ev) = liboos::screen::key_event() { /* ... */ }
//!     // draw into fb.pixels() ...
//!     liboos::screen::flush();
//! }
//! ```
use crate::sys::{self, nr};

/// The mapped framebuffer. Pixels are 32 bit; the colour channel positions are in `*_shift`.
#[derive(Clone, Copy, Debug)]
pub struct Framebuffer {
    pub addr: *mut u32,
    pub width: u32,
    pub height: u32,
    /// Bytes per line.
    pub pitch: u32,
    pub bpp: u32,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl Framebuffer {
    /// Pixels per line.
    pub fn stride(&self) -> usize {
        (self.pitch / 4) as usize
    }

    /// The whole mapped area as a slice of `stride() * height` pixels.
    ///
    /// # Safety
    /// Only one slice at a time; valid until `release` or exit.
    pub unsafe fn pixels(&self) -> &'static mut [u32] {
        core::slice::from_raw_parts_mut(self.addr, self.stride() * self.height as usize)
    }

    /// Pack 8-bit channels into this framebuffer's pixel format.
    pub fn rgb(&self, r: u8, g: u8, b: u8) -> u32 {
        ((r as u32) << self.red_shift) | ((g as u32) << self.green_shift) | ((b as u32) << self.blue_shift)
    }
}

/// Map the screen. From now until `release` (or exit) the kernel console does not draw.
/// Errors: -2 no permission, -5 another program owns the screen, -7 no framebuffer.
pub fn acquire() -> Result<Framebuffer, i64> {
    let mut raw = [0u8; 32];
    let r = unsafe { sys::syscall1(nr::SCREEN_ACQUIRE, raw.as_mut_ptr() as u64) };
    if r < 0 {
        return Err(r);
    }
    let u32_at = |i: usize| u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
    let mut a = [0u8; 8];
    a.copy_from_slice(&raw[0..8]);
    Ok(Framebuffer {
        addr: u64::from_le_bytes(a) as *mut u32,
        width: u32_at(8),
        height: u32_at(12),
        pitch: u32_at(16),
        bpp: u32_at(20),
        red_shift: raw[24],
        green_shift: raw[25],
        blue_shift: raw[26],
    })
}

/// Give the screen back to the console, which repaints. Do not touch the pixels afterwards.
pub fn release() -> i64 {
    unsafe { sys::syscall0(nr::SCREEN_RELEASE) }
}

/// Tell the display that pixels changed (needed on VMware SVGA, harmless elsewhere).
pub fn flush() -> i64 {
    unsafe { sys::syscall0(nr::SCREEN_FLUSH) }
}

/// Switch the keyboard between raw events (`true`) and the console line discipline.
/// The kernel restores the line mode when the program exits. Ctrl+C still kills the program.
pub fn kbd_raw(on: bool) -> i64 {
    unsafe { sys::syscall1(nr::KBD_MODE, on as u64) }
}

/// One raw keyboard event (PC set-1 scancode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    /// Scancode without the release bit, 1..=0x7F.
    pub code: u8,
    /// Preceded by 0xE0 (arrows, right Ctrl/Alt, keypad Enter, Home, ...).
    pub extended: bool,
    pub pressed: bool,
}

/// Next key event, or `None` if there is none. Needs `kbd_raw(true)` first.
pub fn key_event() -> Option<KeyEvent> {
    let r = unsafe { sys::syscall0(nr::KBD_EVENT) };
    if r <= 0 {
        return None;
    }
    Some(KeyEvent {
        code: (r & 0xFF) as u8,
        extended: r & 0x100 != 0,
        pressed: r & 0x200 == 0,
    })
}

/// Monotonic time in nanoseconds since boot.
pub fn clock_ns() -> u64 {
    unsafe { sys::syscall0(nr::CLOCK_NS) as u64 }
}

/// Sleep at least `ms` milliseconds (granularity is the 10 ms kernel tick).
pub fn sleep_ms(ms: u64) {
    unsafe {
        sys::syscall1(nr::SLEEP, ms);
    }
}
