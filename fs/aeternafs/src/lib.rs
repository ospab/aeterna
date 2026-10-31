// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// AeternaFS v2: copy-on-write filesystem. See docs/en/aeternafs.md.

#![no_std]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod crc;
pub mod dev;
mod freemap;
mod fs;
mod fsck;
mod layout;
mod ops;
mod tree;

pub use dev::{BlockDevice, IoError, BLOCK_SIZE};
pub use fs::{Fs, SnapInfo, SnapView, StatFs};
pub use fsck::FsckReport;
pub use layout::Key;
pub use ops::{DirEntry, Stat, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};

/// Seconds between the Unix epoch and the ospab epoch (2012-08-09 UTC).
pub const OSPAB_EPOCH_UNIX_SECS: i64 = 1_344_470_400;

pub const MAX_NAME: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Io,
    /// A block failed its checksum (block number).
    Checksum(u64),
    Corrupt(&'static str),
    NotFound,
    Exists,
    NotDir,
    IsDir,
    NotEmpty,
    NoSpace,
    NameTooLong,
    InvalidName,
    Invalid,
    NoSuchSnapshot,
    NotFormatted,
    TooSmall,
    Poisoned,
    TooLarge,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Io => write!(f, "I/O error"),
            Error::Checksum(b) => write!(f, "checksum mismatch in block {}", b),
            Error::Corrupt(s) => write!(f, "corrupt metadata: {}", s),
            Error::NotFound => write!(f, "not found"),
            Error::Exists => write!(f, "already exists"),
            Error::NotDir => write!(f, "not a directory"),
            Error::IsDir => write!(f, "is a directory"),
            Error::NotEmpty => write!(f, "directory not empty"),
            Error::NoSpace => write!(f, "no space left"),
            Error::NameTooLong => write!(f, "name too long"),
            Error::InvalidName => write!(f, "invalid name"),
            Error::Invalid => write!(f, "invalid argument"),
            Error::NoSuchSnapshot => write!(f, "no such snapshot"),
            Error::NotFormatted => write!(f, "not an AeternaFS volume"),
            Error::TooSmall => write!(f, "device too small"),
            Error::Poisoned => write!(f, "filesystem failed after an I/O error"),
            Error::TooLarge => write!(f, "too large"),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
