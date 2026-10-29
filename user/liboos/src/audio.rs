// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Sound output (syscalls 271..275). See docs/en/syscall-abi.md, "Audio".
//!
//! The kernel mixes all open streams, resamples to the device rate and plays them from its
//! timer tick; the program only keeps the stream buffer (about 200 ms) topped up.
//!
//! ```ignore
//! if let Ok(a) = liboos::audio::Audio::open(48000, 1) {   // Err = no sound card: carry on silently
//!     let mut sent = 0;
//!     while sent < samples.len() {
//!         sent += a.write(&samples[sent..]);
//!         liboos::screen::sleep_ms(20);
//!     }
//!     a.drain();
//! }
//! ```
use crate::sys::{self, nr};

/// An open sound stream. Closed on drop (and by the kernel when the program exits).
pub struct Audio {
    id: u64,
    channels: u32,
    rate: u32,
}

impl Audio {
    /// Open a stream: `rate` 48000, 44100 or 22050 Hz, `channels` 1 or 2, samples `i16`
    /// interleaved. Errors: -7 no sound device, -14 all streams in use, -3 bad format,
    /// -2 no permission.
    pub fn open(rate: u32, channels: u32) -> Result<Audio, i64> {
        let r = unsafe { sys::syscall2(nr::AUDIO_OPEN, rate as u64, channels as u64) };
        if r < 0 {
            return Err(r);
        }
        Ok(Audio { id: r as u64, channels, rate })
    }

    /// Queue samples (`frames * channels` values). Never blocks. Returns how many samples were
    /// accepted (a multiple of the channel count), 0 if the buffer is full.
    pub fn write(&self, samples: &[i16]) -> usize {
        // i16 slices are little endian on x86_64, the stream format.
        let r = unsafe {
            sys::syscall3(nr::AUDIO_WRITE, self.id, samples.as_ptr() as u64, (samples.len() * 2) as u64)
        };
        if r <= 0 {
            0
        } else {
            r as usize / 2
        }
    }

    /// Frames still buffered in the kernel (at this stream's rate). Keep it above about
    /// `rate / 20` to avoid gaps.
    pub fn queued(&self) -> usize {
        let r = unsafe { sys::syscall1(nr::AUDIO_QUEUED, self.id) };
        if r < 0 {
            0
        } else {
            r as usize
        }
    }

    /// Stream volume 0..=100 (default 100).
    pub fn set_volume(&self, percent: u32) -> i64 {
        unsafe { sys::syscall2(nr::AUDIO_VOLUME, self.id, percent as u64) }
    }

    pub fn rate(&self) -> u32 {
        self.rate
    }

    pub fn channels(&self) -> u32 {
        self.channels
    }

    /// Block (sleeping) until everything written has been played, including the tail the
    /// device still holds.
    pub fn drain(&self) {
        while self.queued() > 0 {
            crate::screen::sleep_ms(10);
        }
        crate::screen::sleep_ms(100);
    }
}

impl Drop for Audio {
    fn drop(&mut self) {
        unsafe {
            sys::syscall1(nr::AUDIO_CLOSE, self.id);
        }
    }
}
