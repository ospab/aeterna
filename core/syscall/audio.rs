/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Ring-3 sound output: streams of signed 16-bit PCM mixed by the kernel (drivers/audio/mixer.rs).
ABI of each call: docs/en/syscall-abi.md ("Audio").

  271 audio_open(rate, channels)       -> stream id (>= 1) or a negative error
  272 audio_write(stream, ptr, bytes)  -> bytes accepted, never blocks
  273 audio_queued(stream)             -> frames still buffered
  274 audio_close(stream)
  275 audio_volume(stream, 0..=100)
*/

use crate::core::scheduler::{self, Capability};
use crate::drivers::audio::mixer;
use crate::mm::usercopy;

use super::SyscallError as E;

/// Most bytes one audio_write moves (bigger requests are clamped; the buffer is smaller).
const MAX_WRITE: usize = 256 * 1024;

fn can_audio() -> bool {
    scheduler::has_capability(Capability::Framebuf) || scheduler::has_capability(Capability::System)
}

/// 271: open a stream. `rate` is 48000, 44100 or 22050 Hz, `channels` 1 or 2; samples are
/// signed 16-bit little endian, interleaved. The kernel resamples to the device rate.
/// -7 if there is no sound device, -14 if all streams are in use, -3 for other formats.
pub fn audio_open(rate: u64, channels: u64) -> i64 {
    if !can_audio() {
        return E::PermissionDenied as i64;
    }
    if !matches!(rate, 48000 | 44100 | 22050) || !matches!(channels, 1 | 2) {
        return E::InvalidArgument as i64;
    }
    if !crate::drivers::audio::is_ready() {
        return E::NotSupported as i64;
    }
    match mixer::open(scheduler::current_pid(), rate as u32, channels as u8) {
        Ok(id) => id as i64,
        Err(e) => e,
    }
}

/// 272: queue samples; returns the bytes accepted (whole frames, possibly 0 when the buffer
/// is full). Never blocks.
pub fn audio_write(stream: u64, ptr: u64, bytes: u64) -> i64 {
    let pid = scheduler::current_pid();
    let total = (bytes as usize).min(MAX_WRITE);
    if !usercopy::range_ok(ptr, total) {
        return E::BadAddress as i64;
    }
    let mut chunk = [0u8; 2048];
    let mut done = 0usize;
    while done < total {
        let n = (total - done).min(chunk.len());
        if let Err(e) = usercopy::copy_from_user(&mut chunk[..n], ptr + done as u64) {
            return if done > 0 { done as i64 } else { E::from(e) as i64 };
        }
        match mixer::write(stream as usize, pid, &chunk[..n]) {
            Ok(took) => {
                done += took;
                if took < n {
                    break; // buffer full (or a partial frame at the end)
                }
            }
            Err(e) => return if done > 0 { done as i64 } else { e },
        }
    }
    done as i64
}

/// 273: frames (at the stream's own rate) not yet played by the mixer. The device holds up
/// to about 60 ms more.
pub fn audio_queued(stream: u64) -> i64 {
    match mixer::queued(stream as usize, scheduler::current_pid()) {
        Ok(n) => n as i64,
        Err(e) => e,
    }
}

/// 274
pub fn audio_close(stream: u64) -> i64 {
    match mixer::close(stream as usize, scheduler::current_pid()) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// 275: per-stream volume, 0..=100 (default 100), same curve as the master volume of the
/// software mixer (gain = (v/100)^2).
pub fn audio_volume(stream: u64, vol: u64) -> i64 {
    if vol > 100 {
        return E::InvalidArgument as i64;
    }
    match mixer::set_volume(stream as usize, scheduler::current_pid(), vol as u8) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// The process is gone: close its streams.
pub fn process_gone(pid: u32) {
    mixer::close_all(pid);
}
