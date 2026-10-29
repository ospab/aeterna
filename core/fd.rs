/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Per-process file descriptor table. Lives in the task control block (core/scheduler) and is
dropped when the task is reaped, which closes every descriptor.

  fd 0, 1, 2   always present: stdin, stdout, stderr. Not stored, not closable.
  fd 3 and up  open VFS files: path, offset, access mode.

Only the owning task changes its table, and only through `scheduler::with_current_fds`
(SCHED lock held, interrupts off): the closure must not do I/O or take other locks.
*/

use alloc::string::String;
use alloc::vec::Vec;

/// Highest number of descriptors (std streams included) one process may hold.
pub const MAX_FDS: usize = 64;
const STD_FDS: usize = 3;

#[derive(Debug, Clone)]
pub struct OpenFile {
    /// Absolute VFS path.
    pub path: String,
    pub offset: usize,
    pub readable: bool,
    pub writable: bool,
    /// Written through this descriptor (the deferred disk sync picks it up).
    pub dirty: bool,
}

#[derive(Debug, Clone)]
pub struct FdTable {
    /// Slot `i` is descriptor `i + 3`.
    files: Vec<Option<OpenFile>>,
}

impl FdTable {
    pub const fn new() -> FdTable {
        FdTable { files: Vec::new() }
    }

    /// Is `fd` one of the standard streams?
    pub fn is_std(fd: usize) -> bool {
        fd < STD_FDS
    }

    /// Install a file in the lowest free slot. None when the table is full.
    pub fn alloc(&mut self, f: OpenFile) -> Option<usize> {
        if let Some(i) = self.files.iter().position(|s| s.is_none()) {
            self.files[i] = Some(f);
            return Some(i + STD_FDS);
        }
        if self.files.len() + STD_FDS >= MAX_FDS {
            return None;
        }
        self.files.push(Some(f));
        Some(self.files.len() - 1 + STD_FDS)
    }

    pub fn get(&self, fd: usize) -> Option<&OpenFile> {
        fd.checked_sub(STD_FDS).and_then(|i| self.files.get(i)).and_then(|s| s.as_ref())
    }

    pub fn get_mut(&mut self, fd: usize) -> Option<&mut OpenFile> {
        fd.checked_sub(STD_FDS).and_then(|i| self.files.get_mut(i)).and_then(|s| s.as_mut())
    }

    /// Close a file descriptor. False for std streams and unknown descriptors.
    pub fn close(&mut self, fd: usize) -> bool {
        match fd.checked_sub(STD_FDS).and_then(|i| self.files.get_mut(i)) {
            Some(s) if s.is_some() => {
                *s = None;
                true
            }
            _ => false,
        }
    }

    /// Close every file (fd >= 3). Returns how many were open.
    pub fn close_files(&mut self) -> usize {
        let n = self.files.iter().filter(|s| s.is_some()).count();
        self.files.clear();
        n
    }

    pub fn open_count(&self) -> usize {
        self.files.iter().filter(|s| s.is_some()).count()
    }
}
