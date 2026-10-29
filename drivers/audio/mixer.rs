/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Kernel mixer for ring-3 sound streams (syscalls 271..275, core/syscall/audio.rs).

Each stream owns a ring of ~200 ms of signed 16-bit stereo frames at the rate the program
opened it with (mono is stored as two equal channels). The device is fed from the 100 Hz
timer tick (audio::timer_tick -> audio::mix_feed -> render): every tick the streams are
resampled to the device rate (linear interpolation), scaled by the stream volume, summed
and passed through a soft knee above 3/4 scale (as the DOOM mixer does). Nothing is written
to the device while no stream has data, so the device stays silent and other users of
audio::submit (DOOM, soundtest) are not disturbed.

Locking: LOCK protects SLOTS. Syscall paths take it with interrupts off, so the timer
interrupt (which only try-locks) never finds it held on this CPU.
*/

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::core::syscall::SyscallError as E;

/// Streams open at the same time, all processes together.
pub const MAX_STREAMS: usize = 4;
/// Frames rendered per call (keeps the interrupt-time stack use small).
pub const CHUNK: usize = 128;

struct Slot {
    pid: u32,
    rate: u32,
    ch: u8,
    vol: u8,
    /// Ring capacity in frames.
    cap: usize,
    /// Index of the oldest frame.
    rd: usize,
    /// Frames buffered.
    count: usize,
    /// Position between frame `rd` and `rd + 1`, Q16.
    frac: u32,
    /// `cap * 2` samples, L R interleaved.
    buf: Vec<i16>,
}

static LOCK: AtomicBool = AtomicBool::new(false);
static OPEN: AtomicU32 = AtomicU32::new(0);
static mut SLOTS: [Option<Slot>; MAX_STREAMS] = [const { None }; MAX_STREAMS];

struct Guard {
    irq: bool,
}

fn lock() -> Guard {
    let flags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}; cli", out(reg) flags, options(nomem));
    }
    while LOCK.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
    Guard { irq: flags & (1 << 9) != 0 }
}

impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.store(false, Ordering::Release);
        if self.irq {
            unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
        }
    }
}

fn slots() -> &'static mut [Option<Slot>; MAX_STREAMS] {
    // SAFETY: callers hold LOCK.
    unsafe { &mut *core::ptr::addr_of_mut!(SLOTS) }
}

/// Gain for a stream volume 0..=100 (perceptual curve, Q15), as the HDA software volume.
fn gain(vol: u8) -> i32 {
    let v = vol.min(100) as i32;
    (v * v * 32768) / 10000
}

/// True if at least one stream is open (cheap, lock free).
pub fn active() -> bool {
    OPEN.load(Ordering::Relaxed) != 0
}

/// Open a stream for `pid`. Returns the stream id (1..=MAX_STREAMS).
pub fn open(pid: u32, rate: u32, ch: u8) -> Result<usize, i64> {
    let cap = (rate / 5) as usize;
    let mut buf: Vec<i16> = Vec::new();
    if buf.try_reserve_exact(cap * 2).is_err() {
        return Err(E::OutOfMemory as i64);
    }
    buf.resize(cap * 2, 0);
    let g = lock();
    for (i, s) in slots().iter_mut().enumerate() {
        if s.is_none() {
            *s = Some(Slot { pid, rate, ch, vol: 100, cap, rd: 0, count: 0, frac: 0, buf });
            OPEN.fetch_add(1, Ordering::Relaxed);
            drop(g);
            return Ok(i + 1);
        }
    }
    drop(g);
    Err(E::TableFull as i64)
}

fn slot_of(id: usize, pid: u32) -> Option<&'static mut Slot> {
    if id == 0 || id > MAX_STREAMS {
        return None;
    }
    match &mut slots()[id - 1] {
        Some(s) if s.pid == pid => Some(s),
        _ => None,
    }
}

/// Queue s16le samples (interleaved when stereo). Returns the bytes accepted: whole frames
/// only, as many as fit.
pub fn write(id: usize, pid: u32, data: &[u8]) -> Result<usize, i64> {
    let _g = lock();
    let s = slot_of(id, pid).ok_or(E::BadHandle as i64)?;
    let fsz = 2 * s.ch as usize;
    let frames = (data.len() / fsz).min(s.cap - s.count);
    let mut wr = (s.rd + s.count) % s.cap;
    for f in 0..frames {
        let p = f * fsz;
        let l = i16::from_le_bytes([data[p], data[p + 1]]);
        let r = if s.ch == 2 { i16::from_le_bytes([data[p + 2], data[p + 3]]) } else { l };
        s.buf[wr * 2] = l;
        s.buf[wr * 2 + 1] = r;
        wr += 1;
        if wr == s.cap {
            wr = 0;
        }
    }
    s.count += frames;
    Ok(frames * fsz)
}

/// Frames still buffered, at the stream's own rate. A frame that is only half consumed by
/// the resampler (it needs its successor) does not count.
pub fn queued(id: usize, pid: u32) -> Result<usize, i64> {
    let _g = lock();
    let s = slot_of(id, pid).ok_or(E::BadHandle as i64)?;
    Ok(if s.frac != 0 { s.count.saturating_sub(1) } else { s.count })
}

pub fn set_volume(id: usize, pid: u32, vol: u8) -> Result<(), i64> {
    let _g = lock();
    slot_of(id, pid).ok_or(E::BadHandle as i64)?.vol = vol.min(100);
    Ok(())
}

pub fn close(id: usize, pid: u32) -> Result<(), i64> {
    let old;
    {
        let _g = lock();
        slot_of(id, pid).ok_or(E::BadHandle as i64)?;
        old = slots()[id - 1].take();
        OPEN.fetch_sub(1, Ordering::Relaxed);
    }
    drop(old); // free the buffer with interrupts on and the lock released
    Ok(())
}

/// Close every stream of a process that is gone.
pub fn close_all(pid: u32) {
    for id in 1..=MAX_STREAMS {
        let _ = close(id, pid);
    }
}

/// Mix the next `out.len() / 2` frames (stereo interleaved, device rate `out_rate`) of all
/// streams into `out`. Returns false, leaving `out` silent, if no stream had any data.
/// Called from the timer interrupt: only try-locks.
pub fn render(out: &mut [i16], out_rate: u32) -> bool {
    let frames = (out.len() / 2).min(CHUNK);
    for o in out.iter_mut() {
        *o = 0;
    }
    if out_rate == 0 || LOCK.swap(true, Ordering::Acquire) {
        return false;
    }
    let mut acc = [0i32; CHUNK * 2];
    let mut any = false;
    for s in slots().iter_mut().flatten() {
        let step = (((s.rate as u64) << 16) / out_rate as u64) as u32;
        let g = gain(s.vol);
        for f in 0..frames {
            let (l, r);
            if s.frac == 0 {
                if s.count < 1 {
                    break;
                }
                l = s.buf[s.rd * 2] as i32;
                r = s.buf[s.rd * 2 + 1] as i32;
            } else {
                if s.count < 2 {
                    break;
                }
                let n = if s.rd + 1 == s.cap { 0 } else { s.rd + 1 };
                let k = (s.frac >> 1) as i32; // Q15
                let (l0, r0) = (s.buf[s.rd * 2] as i32, s.buf[s.rd * 2 + 1] as i32);
                let (l1, r1) = (s.buf[n * 2] as i32, s.buf[n * 2 + 1] as i32);
                l = l0 + (((l1 - l0) * k) >> 15);
                r = r0 + (((r1 - r0) * k) >> 15);
            }
            acc[f * 2] += (l * g) >> 15;
            acc[f * 2 + 1] += (r * g) >> 15;
            any = true;
            s.frac += step;
            while s.frac >= 65536 {
                s.frac -= 65536;
                if s.count > 0 {
                    s.count -= 1;
                    s.rd += 1;
                    if s.rd == s.cap {
                        s.rd = 0;
                    }
                }
            }
        }
    }
    LOCK.store(false, Ordering::Release);
    if any {
        for i in 0..frames * 2 {
            let mut v = acc[i];
            // Soft knee above 3/4 scale instead of hard clipping.
            if v > 24576 {
                v = 24576 + ((v - 24576) >> 2);
            } else if v < -24576 {
                v = -24576 + ((v + 24576) >> 2);
            }
            out[i] = v.clamp(-32768, 32767) as i16;
        }
    }
    any
}
