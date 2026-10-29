/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Ring-3 games and emulators: the screen, raw keyboard events and a monotonic clock.
ABI of each call: docs/en/syscall-abi.md ("Screen, keyboard, clock").

  260 screen_acquire(info*)   map the framebuffer, console stops drawing
  261 screen_release()        give it back (also done when the process dies)
  262 screen_flush()          tell the display (VMware SVGA) that pixels changed
  263 kbd_mode(raw)           1 = raw press/release events, 0 = console line input
  264 kbd_event()             next raw event, 0 if none
  270 clock_ns()              monotonic nanoseconds
  21  sleep_ms(ms)
*/

use crate::core::object;
use crate::core::scheduler::{self, Capability};
use crate::mm::usercopy;

use super::SyscallError as E;

const PAGE: u64 = 4096;

fn can_screen() -> bool {
    scheduler::has_capability(Capability::Framebuf) || scheduler::has_capability(Capability::System)
}

/// 260: map the framebuffer read/write (no-execute) into the caller and write a 32-byte
/// description to `info`: addr u64, width u32, height u32, pitch u32 (bytes), bpp u32,
/// red/green/blue shift u8 each, 1 pad byte. Returns 0. Busy if the screen is already owned.
pub fn screen_acquire(info: u64) -> i64 {
    if !can_screen() {
        return E::PermissionDenied as i64;
    }
    if !usercopy::range_ok(info, 32) {
        return E::BadAddress as i64;
    }
    let fb = match crate::arch::x86_64::framebuffer::info() {
        Some(f) => f,
        None => return E::NotSupported as i64,
    };
    let pid = scheduler::current_pid();
    if !crate::arch::x86_64::framebuffer::acquire_screen(pid) {
        return E::Busy as i64;
    }
    let va = match map_framebuffer(&fb) {
        Ok(v) => v,
        Err(e) => {
            crate::arch::x86_64::framebuffer::release_screen(pid);
            return e;
        }
    };
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&va.to_le_bytes());
    out[8..12].copy_from_slice(&(fb.width as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(fb.height as u32).to_le_bytes());
    out[16..20].copy_from_slice(&(fb.pitch as u32).to_le_bytes());
    out[20..24].copy_from_slice(&(fb.bpp as u32).to_le_bytes());
    out[24] = fb.red_shift;
    out[25] = fb.green_shift;
    out[26] = fb.blue_shift;
    if let Err(e) = usercopy::copy_to_user(info, &out) {
        crate::arch::x86_64::framebuffer::release_screen(pid);
        return E::from(e) as i64;
    }
    0
}

fn map_framebuffer(fb: &crate::arch::x86_64::framebuffer::Framebuffer) -> Result<u64, i64> {
    let virt = fb.address as u64;
    let phys = crate::mm::r#virtual::translate_current(virt).ok_or(E::NotSupported as i64)?;
    let off = phys % PAGE;
    let bytes = fb.pitch * fb.height + off;
    let size = (bytes + PAGE - 1) / PAGE * PAGE;
    let id = object::kernel_new_mmio(phys - off, size).ok_or(E::NotSupported as i64)?;
    let me = scheduler::current_pid();
    let rights = object::rights::MAP | object::rights::READ | object::rights::WRITE;
    let h = match object::kernel_install(me, id, rights) {
        Some(h) => h,
        None => {
            object::kernel_release(id);
            return Err(E::TableFull as i64);
        }
    };
    let r = object::mem_map(h, 0, object::prot::READ | object::prot::WRITE);
    // The mapping keeps its own reference to the object.
    let _ = object::handle_close(h);
    r.map(|va| va + off)
}

/// 261: give the screen back; the console repaints. The mapping stays until exit but must not
/// be used any more.
pub fn screen_release() -> i64 {
    if crate::arch::x86_64::framebuffer::release_screen(scheduler::current_pid()) {
        0
    } else {
        E::InvalidArgument as i64
    }
}

/// 262
pub fn screen_flush() -> i64 {
    check_interrupt();
    if crate::arch::x86_64::framebuffer::screen_owner() != scheduler::current_pid() {
        return E::PermissionDenied as i64;
    }
    crate::drivers::gpu::flush_screen();
    0
}

/// 263
pub fn kbd_mode(raw: u64) -> i64 {
    if !can_screen() {
        return E::PermissionDenied as i64;
    }
    let pid = scheduler::current_pid();
    if raw != 0 {
        if crate::arch::x86_64::keyboard::raw_acquire(pid) { 0 } else { E::Busy as i64 }
    } else {
        crate::arch::x86_64::keyboard::raw_release(pid);
        0
    }
}

/// 264
pub fn kbd_event() -> i64 {
    check_interrupt();
    if crate::arch::x86_64::keyboard::raw_owner() != scheduler::current_pid() {
        return E::PermissionDenied as i64;
    }
    crate::arch::x86_64::keyboard::raw_event()
}

/// 270
pub fn clock_ns() -> i64 {
    crate::time::monotonic_ns() as i64
}

/// Ctrl+C for a program that owns the screen or the raw keyboard: the shell cannot always run
/// (a game that never blocks starves it), so the program is ended here, at its next call.
fn check_interrupt() {
    let me = scheduler::current_pid();
    let owner = crate::arch::x86_64::keyboard::raw_owner() == me
        || crate::arch::x86_64::framebuffer::screen_owner() == me;
    if owner && crate::arch::x86_64::keyboard::take_interrupt() {
        super::syscall_exit(130);
    }
}

/// 21: sleep at least `ms` milliseconds. The task really sleeps (other tasks, the shell
/// included, run); it wakes on the 100 Hz tick, so it can be up to 10 ms late.
pub fn sleep_ms(ms: u64) -> i64 {
    check_interrupt();
    let ticks = (ms.min(60_000) + 9) / 10;
    let deadline = crate::arch::x86_64::idt::timer_ticks() + ticks.max(1);
    while crate::arch::x86_64::idt::timer_ticks() < deadline {
        scheduler::park(deadline);
    }
    check_interrupt();
    0
}

/// The process is gone: give back the screen and the keyboard.
pub fn process_gone(pid: u32) {
    crate::arch::x86_64::keyboard::raw_release(pid);
    crate::arch::x86_64::framebuffer::release_screen(pid);
}
