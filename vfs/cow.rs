/*
 * AETERNA CoW (Copy-on-Write) Overlay Filesystem
 *
 * Implements an overlay VFS node that reads from `upper` and `base`,
 * but writes exclusively to `upper`. If a file exists only in `base`
 * and is opened for writing, it is copied up to `upper` before modification.
 */

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use crate::userspace::fs::{FileSystem, DirEntry, NodeType};

static mut COW_INSTANCE: Option<CowFS> = None;

pub fn init(base: &'static dyn FileSystem, upper: &'static dyn FileSystem) -> &'static CowFS {
    unsafe {
        COW_INSTANCE = Some(CowFS::new(base, upper));
        COW_INSTANCE.as_ref().unwrap()
    }
}

pub struct CowFS {
    base: &'static dyn FileSystem,
    upper: &'static dyn FileSystem,
    name: String,
}

impl CowFS {
    pub fn new(base: &'static dyn FileSystem, upper: &'static dyn FileSystem) -> Self {
        CowFS {
            base,
            upper,
            name: alloc::format!("cowfs({}+{})", upper.name(), base.name()),
        }
    }

    /// Internal copy-up operation: reads a file from base and writes it to upper.
    fn copy_up(&self, path: &str) -> bool {
        if self.upper.exists(path) {
            return true; // Already in upper
        }
        if let Some(data) = self.base.read_file(path) {
            crate::arch::x86_64::serial::write_str("[CowFS] Copying up file: ");
            crate::arch::x86_64::serial::write_str(path);
            crate::arch::x86_64::serial::write_str("\r\n");
            // Create parents in upper if necessary
            let mut parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if parts.len() > 1 {
                parts.pop(); // Remove filename
                let mut dir_path = String::from("/");
                for p in parts {
                    dir_path.push_str(p);
                    if !self.upper.exists(&dir_path) {
                        self.upper.mkdir(&dir_path);
                    }
                    dir_path.push_str("/");
                }
            }
            return self.upper.write_file(path, &data);
        }
        false
    }
}

impl FileSystem for CowFS {
    fn name(&self) -> &str {
        &self.name
    }

    fn read_at(&self, path: &str, offset: usize, buf: &mut [u8]) -> Option<usize> {
        if self.upper.exists(path) {
            self.upper.read_at(path, offset, buf)
        } else {
            self.base.read_at(path, offset, buf)
        }
    }

    fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        if self.upper.exists(path) {
            self.upper.read_file(path)
        } else {
            self.base.read_file(path)
        }
    }

    fn write_at(&self, path: &str, offset: usize, data: &[u8]) -> bool {
        if !self.upper.exists(path) && self.base.exists(path) {
            if !self.copy_up(path) {
                return false;
            }
        }
        self.upper.write_at(path, offset, data)
    }

    fn write_file(&self, path: &str, data: &[u8]) -> bool {
        if !self.upper.exists(path) && self.base.exists(path) {
            // Overwriting whole file: no need to copy old data, just ensure parents exist
            self.copy_up(path); 
        }
        self.upper.write_file(path, data)
    }

    fn append_file(&self, path: &str, data: &[u8]) -> bool {
        if !self.upper.exists(path) && self.base.exists(path) {
            if !self.copy_up(path) {
                return false;
            }
        }
        self.upper.append_file(path, data)
    }

    fn readdir(&self, path: &str) -> Option<Vec<DirEntry>> {
        let mut entries = Vec::new();
        let upper_res = self.upper.readdir(path);
        let base_res = self.base.readdir(path);

        if upper_res.is_none() && base_res.is_none() {
            return None;
        }

        if let Some(upper_entries) = upper_res {
            for entry in upper_entries {
                entries.push(entry);
            }
        }

        if let Some(base_entries) = base_res {
            for be in base_entries {
                // Check if already present from upper to avoid duplicates
                if !entries.iter().any(|e| e.name == be.name) {
                    entries.push(be);
                }
            }
        }

        Some(entries)
    }

    fn mkdir(&self, path: &str) -> bool {
        // Must happen in upper
        self.upper.mkdir(path)
    }

    fn touch(&self, path: &str) -> bool {
        // Must happen in upper
        self.upper.touch(path)
    }

    fn exists(&self, path: &str) -> bool {
        self.upper.exists(path) || self.base.exists(path)
    }

    fn stat(&self, path: &str) -> Option<DirEntry> {
        if self.upper.exists(path) {
            self.upper.stat(path)
        } else {
            self.base.stat(path)
        }
    }

    fn remove(&self, path: &str) -> bool {
        // Removing a file is tricky in an overlay.
        // If it's in upper, we can delete it. 
        // If it's in base, deleting from upper doesn't hide it from base.
        // A true Whiteout implementation is needed in Phase 6.
        // For now, we only delete from upper.
        if self.upper.exists(path) {
            self.upper.remove(path)
        } else {
            false // Cannot physically delete from a read-only base
        }
    }

    fn rename(&self, from: &str, to: &str) -> bool {
        if !self.upper.exists(from) && self.base.exists(from) {
            if !self.copy_up(from) {
                return false;
            }
        }
        self.upper.rename(from, to)
    }
}
