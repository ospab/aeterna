// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// Block device trait and host devices.

pub const BLOCK_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoError;

/// A device of 4096-byte blocks. Buffers are multiples of `BLOCK_SIZE`.
/// Writes may be cached by the device until `flush` returns.
pub trait BlockDevice {
    fn block_count(&self) -> u64;
    fn read_blocks(&mut self, start: u64, buf: &mut [u8]) -> Result<(), IoError>;
    fn write_blocks(&mut self, start: u64, buf: &[u8]) -> Result<(), IoError>;
    fn flush(&mut self) -> Result<(), IoError>;
}

#[cfg(feature = "std")]
pub mod host {
    use super::*;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::vec::Vec;

    /// Small xorshift generator for tests and fault injection.
    pub struct Rng(pub u64);
    impl Rng {
        pub fn new(seed: u64) -> Rng {
            Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
        }
        pub fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        pub fn below(&mut self, n: u64) -> u64 {
            if n == 0 { 0 } else { self.next() % n }
        }
    }

    /// RAM device.
    pub struct MemDevice {
        pub data: Vec<u8>,
    }
    impl MemDevice {
        pub fn new(blocks: u64) -> MemDevice {
            MemDevice { data: std::vec![0u8; blocks as usize * BLOCK_SIZE] }
        }
        pub fn from_vec(data: Vec<u8>) -> MemDevice {
            MemDevice { data }
        }
    }
    impl BlockDevice for MemDevice {
        fn block_count(&self) -> u64 {
            (self.data.len() / BLOCK_SIZE) as u64
        }
        fn read_blocks(&mut self, start: u64, buf: &mut [u8]) -> Result<(), IoError> {
            let o = start as usize * BLOCK_SIZE;
            let e = o.checked_add(buf.len()).ok_or(IoError)?;
            if e > self.data.len() { return Err(IoError); }
            buf.copy_from_slice(&self.data[o..e]);
            Ok(())
        }
        fn write_blocks(&mut self, start: u64, buf: &[u8]) -> Result<(), IoError> {
            let o = start as usize * BLOCK_SIZE;
            let e = o.checked_add(buf.len()).ok_or(IoError)?;
            if e > self.data.len() { return Err(IoError); }
            self.data[o..e].copy_from_slice(buf);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), IoError> {
            Ok(())
        }
    }

    /// A device over a file or a region of a file (a partition in a disk image).
    pub struct FileDevice {
        file: File,
        offset: u64,
        blocks: u64,
    }
    impl FileDevice {
        /// `offset` and `len` in bytes. `len` is rounded down to whole blocks.
        pub fn new(file: File, offset: u64, len: u64) -> FileDevice {
            FileDevice { file, offset, blocks: len / BLOCK_SIZE as u64 }
        }
    }
    impl BlockDevice for FileDevice {
        fn block_count(&self) -> u64 {
            self.blocks
        }
        fn read_blocks(&mut self, start: u64, buf: &mut [u8]) -> Result<(), IoError> {
            if start + (buf.len() / BLOCK_SIZE) as u64 > self.blocks { return Err(IoError); }
            self.file.seek(SeekFrom::Start(self.offset + start * BLOCK_SIZE as u64)).map_err(|_| IoError)?;
            self.file.read_exact(buf).map_err(|_| IoError)
        }
        fn write_blocks(&mut self, start: u64, buf: &[u8]) -> Result<(), IoError> {
            if start + (buf.len() / BLOCK_SIZE) as u64 > self.blocks { return Err(IoError); }
            self.file.seek(SeekFrom::Start(self.offset + start * BLOCK_SIZE as u64)).map_err(|_| IoError)?;
            self.file.write_all(buf).map_err(|_| IoError)
        }
        fn flush(&mut self) -> Result<(), IoError> {
            self.file.flush().map_err(|_| IoError)?;
            self.file.sync_data().map_err(|_| IoError)
        }
    }

    /// Device that loses power after a given number of block writes. Writes
    /// are volatile until `flush`. `crash_image` returns what the disk could
    /// contain after the power cut: all flushed data plus a random subset
    /// of the unflushed writes, in random order, some of them torn.
    pub struct FaultDevice {
        durable: Vec<u8>,
        pending: Vec<(u64, Vec<u8>)>,
        latest: HashMap<u64, usize>,
        pub writes: u64,
        pub cut_after: Option<u64>,
        pub dead: bool,
    }
    impl FaultDevice {
        pub fn new(image: Vec<u8>, cut_after: Option<u64>) -> FaultDevice {
            FaultDevice { durable: image, pending: Vec::new(), latest: HashMap::new(), writes: 0, cut_after, dead: false }
        }
        pub fn crash_image(&self, seed: u64) -> Vec<u8> {
            let mut rng = Rng::new(seed);
            let mut img = self.durable.clone();
            let mut order: Vec<usize> = (0..self.pending.len()).collect();
            // random subset
            let mode = rng.below(4);
            order.retain(|_| match mode {
                0 => false,
                1 => true,
                _ => rng.below(2) == 0,
            });
            // random order
            for i in (1..order.len()).rev() {
                let j = rng.below(i as u64 + 1) as usize;
                order.swap(i, j);
            }
            for i in order {
                let (blk, data) = &self.pending[i];
                let o = *blk as usize * BLOCK_SIZE;
                if rng.below(8) == 0 {
                    // torn write: only a prefix of 512-byte sectors lands
                    let sectors = rng.below(8) as usize;
                    img[o..o + sectors * 512].copy_from_slice(&data[..sectors * 512]);
                } else {
                    img[o..o + BLOCK_SIZE].copy_from_slice(data);
                }
            }
            img
        }
        pub fn durable(&self) -> &[u8] {
            &self.durable
        }
    }
    impl BlockDevice for FaultDevice {
        fn block_count(&self) -> u64 {
            (self.durable.len() / BLOCK_SIZE) as u64
        }
        fn read_blocks(&mut self, start: u64, buf: &mut [u8]) -> Result<(), IoError> {
            if self.dead { return Err(IoError); }
            for (i, c) in buf.chunks_mut(BLOCK_SIZE).enumerate() {
                let b = start + i as u64;
                if let Some(&k) = self.latest.get(&b) {
                    c.copy_from_slice(&self.pending[k].1);
                } else {
                    let o = b as usize * BLOCK_SIZE;
                    if o + BLOCK_SIZE > self.durable.len() { return Err(IoError); }
                    c.copy_from_slice(&self.durable[o..o + BLOCK_SIZE]);
                }
            }
            Ok(())
        }
        fn write_blocks(&mut self, start: u64, buf: &[u8]) -> Result<(), IoError> {
            if self.dead { return Err(IoError); }
            for (i, c) in buf.chunks(BLOCK_SIZE).enumerate() {
                if self.cut_after == Some(0) {
                    self.dead = true;
                    return Err(IoError);
                }
                let b = start + i as u64;
                if (b as usize + 1) * BLOCK_SIZE > self.durable.len() { return Err(IoError); }
                self.latest.insert(b, self.pending.len());
                self.pending.push((b, c.to_vec()));
                self.writes += 1;
                // Power fails right after the N-th write was issued, before its flush.
                if self.cut_after == Some(self.writes) {
                    self.dead = true;
                    return Err(IoError);
                }
            }
            Ok(())
        }
        fn flush(&mut self) -> Result<(), IoError> {
            if self.dead { return Err(IoError); }
            for (b, d) in self.pending.drain(..) {
                let o = b as usize * BLOCK_SIZE;
                self.durable[o..o + BLOCK_SIZE].copy_from_slice(&d);
            }
            self.latest.clear();
            Ok(())
        }
    }
}
