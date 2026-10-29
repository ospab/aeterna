// SPDX-License-Identifier: AGPL-3.0-only
//! BBC Micro Model B emulator core. No ROMs or game images are included: the MOS ROM and the
//! disc images are supplied by the user at run time.
//!
//! Interface (shared by cpu.rs and the machine modules, keep it stable):
//! - `cpu::Bus` is what the CPU sees; `machine::Beeb` implements it.
//! - `cpu::Cpu::step` runs one instruction and returns the cycles it took (2 MHz clock).
//! - `machine::Beeb::run_frame` runs 40_000 cycles (one 50 Hz frame) and leaves the picture in
//!   `screen()`: SCREEN_W x SCREEN_H pixels, 0x00RRGGBB.
#![no_std]
extern crate alloc;

pub mod cpu;
pub mod machine;
pub mod video;
pub mod via;
pub mod keyboard;
pub mod disc;
pub mod sound;
