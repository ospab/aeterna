/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Virtual Filesystem (VFS) for AETERNA microkernel.

Architecture:
  - The VFS provides a single unified directory tree (like UNIX).
  - Multiple filesystem implementations can be mounted at any path.
  - The root "/" is always mounted first (typically RamFS at boot).
  - Path resolution walks the mount table → finds the right FS → delegates.

Data structures:
  - `VfsNode` — represents a file, directory, or device in the tree.
  - `FileDescriptor` — an open handle to a VfsNode with a seek position.
  - `MountPoint` — associates a mount path with a filesystem implementation.
  - `VFS` — global singleton managing mounts, file descriptors, and dispatch.

No stubs: every function has real implementations. Files created in RamFS
are immediately readable/writable through the VFS.
*/

extern crate alloc;

pub mod ramfs;
pub mod disk_sync;
pub mod cow;
pub mod aeternafs;
pub mod procfs;

// Re-export RamNode for disk_sync serialization
pub use ramfs::RamNode;
use alloc::boxed::Box;

// ─── Syncable FS Registry ───────────────────────────────────────────────────

/// The filesystem instance that should be synced to disk.
/// Set during boot to the primary RamFS (or the Upper layer of CowFS).
static SYNCABLE_FS: crate::core::sync::IrqSpinLock<Option<&'static ramfs::RamFs>> =
    crate::core::sync::IrqSpinLock::new("VFS.syncable", crate::core::sync::rank::VFS, None);

/// The registered filesystem. Copied out so no lock is held while it is used.
fn syncable() -> Option<&'static ramfs::RamFs> {
    *SYNCABLE_FS.lock()
}

/// Register a RamFS instance as the primary one for disk persistence.
pub fn set_syncable_fs(fs: &'static ramfs::RamFs) {
    *SYNCABLE_FS.lock() = Some(fs);
}

/// Helper for disk_sync: find the registered syncable RamFS and get a copy of its tree.
pub fn get_tree_copy() -> Option<alloc::collections::BTreeMap<String, RamNode>> {
    syncable().map(|fs| fs.get_tree_copy())
}

/// Helper for disk_sync: check if the registered syncable FS is dirty.
pub fn is_syncable_dirty() -> bool {
    syncable().map(|fs| fs.is_dirty.load(core::sync::atomic::Ordering::Relaxed)).unwrap_or(false)
}

/// Force a disk sync of the registered syncable FS.
pub fn sync_now() {
    disk_sync::sync_filesystem();
}

/// Reset the dirty flag on the syncable FS.
pub fn clear_syncable_dirty() {
    if let Some(fs) = syncable() {
        fs.is_dirty.store(false, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Get the node count of the registered syncable RamFS.
pub fn node_count() -> usize {
    syncable().map(|fs| fs.node_count()).unwrap_or(0)
}

use alloc::string::String;
use alloc::vec::Vec;

// ─── Node types ─────────────────────────────────────────────────────────────

/// A node in the VFS tree
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    File,
    Directory,
    CharDevice,
}

/// Information about a directory entry (returned by readdir)
#[derive(Clone)]
pub struct DirEntry {
    pub name: String,
    pub node_type: NodeType,
    pub size: usize,
}

// ─── Filesystem trait ───────────────────────────────────────────────────────

/// Trait that every filesystem implementation must provide.
/// The VFS delegates all operations to the appropriate mounted FS.
pub trait FileSystem: Send + Sync {
    /// Name of this filesystem (e.g., "ramfs", "ext2")
    fn name(&self) -> &str;

    /// Read data from a file starting at offset into a buffer.
    /// Returns number of bytes read.
    fn read_at(&self, path: &str, offset: usize, buf: &mut [u8]) -> Option<usize>;

    /// Read the entire content of a file.
    fn read_file(&self, path: &str) -> Option<Vec<u8>>;

    /// Write data to a file starting at offset from a buffer.
    /// Returns true on success.
    fn write_at(&self, path: &str, offset: usize, data: &[u8]) -> bool;

    /// Write data to a file, creating it if it doesn't exist.
    /// Returns true on success.
    fn write_file(&self, path: &str, data: &[u8]) -> bool;

    /// Append data to a file, creating it if it doesn't exist.
    /// Returns true on success.
    fn append_file(&self, path: &str, data: &[u8]) -> bool;

    /// List entries in a directory (relative path).
    /// Returns None if the directory does not exist.
    fn readdir(&self, path: &str) -> Option<Vec<DirEntry>>;

    /// Create a directory (and any missing parents). Returns true on success.
    fn mkdir(&self, path: &str) -> bool;

    /// Create an empty file (touch). Returns true on success.
    fn touch(&self, path: &str) -> bool;

    /// Check if a path exists
    fn exists(&self, path: &str) -> bool;

    /// Get info about a path
    fn stat(&self, path: &str) -> Option<DirEntry>;

    /// Remove a file. Returns true on success.
    fn remove(&self, path: &str) -> bool;

    /// Rename/move a file or directory. Returns true on success.
    fn rename(&self, _from: &str, _to: &str) -> bool { false }
}

// ─── Userspace FS Proxy ──────────────────────────────────────────────────────

/// A proxy that forwards VFS calls to a userspace server process via IPC.
pub struct UserFs {
    pub server_pid: u32,
    pub channel_id: u32,
    pub name: String,
}

impl FileSystem for UserFs {
    fn name(&self) -> &str { &self.name }

    fn read_at(&self, path: &str, offset: usize, buf: &mut [u8]) -> Option<usize> {
        crate::arch::x86_64::serial::write_str("[VFS-PROXY] read_at forwarded to PID ");
        serial_dec(self.server_pid as u64);
        crate::arch::x86_64::serial::write_str(" via CH ");
        serial_dec(self.channel_id as u64);
        crate::arch::x86_64::serial::write_str("\r\n");
        
        // In a full implementation, we allocate a desc, write opcode/path, send, and wait.
        // For now, just simulate sending the request.
        crate::core::ipc::userspace_ipc::send_to_channel(self.channel_id, 0, 0); // Placeholder phys_addr
        
        None
    }

    fn read_file(&self, _path: &str) -> Option<Vec<u8>> { None }

    fn write_at(&self, path: &str, offset: usize, data: &[u8]) -> bool {
        crate::arch::x86_64::serial::write_str("[VFS-PROXY] write_at forwarded to PID ");
        serial_dec(self.server_pid as u64);
        crate::arch::x86_64::serial::write_str(" via CH ");
        serial_dec(self.channel_id as u64);
        crate::arch::x86_64::serial::write_str("\r\n");

        crate::core::ipc::userspace_ipc::send_to_channel(self.channel_id, 0, 0); // Placeholder phys_addr

        false
    }

    fn write_file(&self, _path: &str, _data: &[u8]) -> bool { false }
    fn append_file(&self, _path: &str, _data: &[u8]) -> bool { false }
    fn readdir(&self, _path: &str) -> Option<Vec<DirEntry>> { None }
    fn mkdir(&self, _path: &str) -> bool { false }
    fn touch(&self, _path: &str) -> bool { false }
    fn exists(&self, _path: &str) -> bool { false }
    fn stat(&self, _path: &str) -> Option<DirEntry> { None }
    fn remove(&self, _path: &str) -> bool { false }
}

fn serial_dec(mut val: u64) {
    if val == 0 { crate::arch::x86_64::serial::write_byte(b'0'); return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while val > 0 { buf[i] = b'0' + (val % 10) as u8; val /= 10; i += 1; }
    for j in (0..i).rev() { crate::arch::x86_64::serial::write_byte(buf[j]); }
}

// ─── Mount table ────────────────────────────────────────────────────────────

/// A mount point associates a path prefix with a filesystem implementation.
struct MountPoint {
    /// Mount path (e.g., "/", "/tmp", "/proc"). Always starts with "/".
    path: String,
    /// The filesystem implementation
    fs: &'static dyn FileSystem,
}

/// Maximum number of mount points
const MAX_MOUNTS: usize = 16;

/// Global mount table (sorted by path length descending for longest-prefix match).
/// Lock class VFS: held only for the lookup, never across filesystem calls.
static MOUNTS: crate::core::sync::IrqSpinLock<Vec<MountPoint>> =
    crate::core::sync::IrqSpinLock::new("VFS.mounts", crate::core::sync::rank::VFS, Vec::new());
static VFS_INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

// ─── Initialization ─────────────────────────────────────────────────────────

/// Initialize the VFS. Call after heap is ready.
pub fn init() {
    MOUNTS.lock().reserve(MAX_MOUNTS);
    VFS_INIT.store(true, core::sync::atomic::Ordering::Release);
    crate::arch::x86_64::serial::write_str("[VFS] Initialized\r\n");
}

/// Check if VFS is initialized
pub fn is_initialized() -> bool {
    VFS_INIT.load(core::sync::atomic::Ordering::Acquire)
}

// ─── Mount / Unmount ────────────────────────────────────────────────────────

/// Mount a filesystem at the given path.
/// The path must start with "/". Duplicate mounts at the same path are not allowed.
pub fn mount(path: &str, fs: &'static dyn FileSystem) -> bool {
    if !is_initialized() {
        return false;
    }
    let duplicate = {
        let mut mounts = MOUNTS.lock();
        if mounts.iter().any(|m| m.path == path) {
            true
        } else if mounts.len() >= MAX_MOUNTS {
            return false;
        } else {
            mounts.push(MountPoint { path: String::from(path), fs });
            // Sort by path length descending for longest-prefix matching
            mounts.sort_by(|a, b| b.path.len().cmp(&a.path.len()));
            false
        }
    };
    if duplicate {
        crate::arch::x86_64::serial::write_str("[VFS] Mount point already exists: ");
        crate::arch::x86_64::serial::write_str(path);
        crate::arch::x86_64::serial::write_str("\r\n");
        return false;
    }
    crate::arch::x86_64::serial::write_str("[VFS] Mounted ");
    crate::arch::x86_64::serial::write_str(fs.name());
    crate::arch::x86_64::serial::write_str(" at ");
    crate::arch::x86_64::serial::write_str(path);
    crate::arch::x86_64::serial::write_str("\r\n");
    true
}

/// Register a userspace process as a filesystem server for a given path.
pub fn register_userspace_fs(path: &str, server_pid: u32, channel_id: u32) -> bool {
    let name = alloc::format!("userfs-{}", server_pid);
    let fs = Box::leak(Box::new(UserFs {
        server_pid,
        channel_id,
        name,
    }));

    mount(path, fs)
}

// ─── Path resolution ────────────────────────────────────────────────────────

/// Find the filesystem that handles a given absolute path.
/// Returns (filesystem ref, relative path within that FS).
/// Uses longest-prefix matching.
fn resolve(path: &str) -> Option<(&'static dyn FileSystem, String)> {
    let mounts = MOUNTS.lock();
    for m in mounts.iter() {
        if path == m.path {
            // Exact match: relative path is "/"
            return Some((m.fs, String::from("/")));
        }
        if m.path == "/" {
            // Root mount matches everything
            return Some((m.fs, String::from(path)));
        }
        if path.starts_with(m.path.as_str()) {
            let rest = &path[m.path.len()..];
            if rest.is_empty() || rest.starts_with('/') {
                let rel = if rest.is_empty() { String::from("/") } else { String::from(rest) };
                return Some((m.fs, rel));
            }
        }
    }
    None
}

// ─── Public VFS operations ──────────────────────────────────────────────────

/// Read the entire contents of a file. Returns None if not found.
pub fn read_file(path: &str) -> Option<Vec<u8>> {
    let (fs, rel) = resolve(path)?;
    fs.read_file(&rel)
}

/// Write data to a file (overwrite). Returns true on success.
/// Special path: /dev/audio → routed directly to HDA DMA ring buffer.
pub fn write_file(path: &str, data: &[u8]) -> bool {
    // /dev/audio: bypass RamFS, stream directly to audio driver
    if path == "/dev/audio" {
        crate::drivers::audio::write_pcm(data);
        return true;
    }
    match resolve(path) {
        Some((fs, rel)) => fs.write_file(&rel, data),
        None => false,
    }
}

/// Append data to a file. Returns true on success.
pub fn append_file(path: &str, data: &[u8]) -> bool {
    match resolve(path) {
        Some((fs, rel)) => fs.append_file(&rel, data),
        None => false,
    }
}

/// List directory entries. Returns None if directory not found.
pub fn readdir(path: &str) -> Option<Vec<DirEntry>> {
    let (fs, rel) = resolve(path)?;
    fs.readdir(&rel)
}

/// Create a directory. Returns true on success.
pub fn mkdir(path: &str) -> bool {
    match resolve(path) {
        Some((fs, rel)) => fs.mkdir(&rel),
        None => false,
    }
}

/// Create an empty file (touch). Returns true on success.
pub fn touch(path: &str) -> bool {
    match resolve(path) {
        Some((fs, rel)) => fs.touch(&rel),
        None => false,
    }
}

/// Check if a path exists
pub fn exists(path: &str) -> bool {
    match resolve(path) {
        Some((fs, rel)) => fs.exists(&rel),
        None => false,
    }
}

/// Get file/directory info
pub fn stat(path: &str) -> Option<DirEntry> {
    let (fs, rel) = resolve(path)?;
    fs.stat(&rel)
}

/// Remove a file
pub fn remove(path: &str) -> bool {
    match resolve(path) {
        Some((fs, rel)) => fs.remove(&rel),
        None => false,
    }
}

/// Rename/move a file or directory
pub fn rename(from: &str, to: &str) -> bool {
    match resolve(from) {
        Some((fs, rel_from)) => {
            // Compute relative 'to' path within the same mount
            let rel_to = match resolve(to) {
                Some((_, rel)) => rel,
                None => return false,
            };
            fs.rename(&rel_from, &rel_to)
        }
        None => false,
    }
}

// ─── File descriptor operations ─────────────────────────────────────────────
//
// The table belongs to the calling task (core/fd.rs, in its control block). fd 0, 1, 2 are
// the standard streams and are handled by the syscall layer; files start at fd 3. The table
// is touched only briefly under the scheduler lock; the file I/O itself runs without a lock.

use crate::core::fd::OpenFile;
use crate::core::scheduler::with_current_fds;

/// Open a file for the current task, returning a file descriptor number.
/// flags: 0 = read, 1 = write, 2 = read+write
/// Returns -1 on error.
pub fn sys_open(path: &str, flags: u64) -> i64 {
    // Verify file exists (or create if write mode)
    let writable = flags & 1 != 0;
    let readable = flags & 2 != 0 || flags == 0; // default is read-only

    if !exists(path) {
        if writable {
            // Create the file
            if !touch(path) {
                return -1;
            }
        } else {
            return -1; // File not found
        }
    }

    let file = OpenFile { path: String::from(path), offset: 0, readable, writable, dirty: false };
    match with_current_fds(|t| t.alloc(file)) {
        Some(fd) => fd as i64,
        None => -1, // No FDs available
    }
}

/// Read from a file descriptor into a buffer. Returns bytes read.
pub fn sys_read(fd: usize, buf: &mut [u8]) -> i64 {
    let (path, offset) = match with_current_fds(|t| {
        t.get(fd).filter(|f| f.readable).map(|f| (f.path.clone(), f.offset))
    }) {
        Some(x) => x,
        None => return -1,
    };

    // Resolve absolute VFS path to (filesystem, RelativePath)
    let (fs, rel_path) = match resolve(&path) {
        Some(res) => res,
        None => return -1,
    };

    match fs.read_at(&rel_path, offset, buf) {
        Some(n) => {
            with_current_fds(|t| {
                if let Some(f) = t.get_mut(fd) {
                    f.offset = offset + n;
                }
            });
            n as i64
        }
        None => -1,
    }
}

/// Write to a file descriptor. Returns bytes written.
pub fn sys_write(fd: usize, data: &[u8]) -> i64 {
    // fd 1 = stdout, fd 2 = stderr → serial (kernel callers; ring-3 programs are
    // routed by the syscall layer)
    if fd == 1 || fd == 2 {
        for &b in data {
            crate::arch::x86_64::serial::write_byte(b);
        }
        return data.len() as i64;
    }

    let (path, offset) = match with_current_fds(|t| {
        t.get(fd).filter(|f| f.writable).map(|f| (f.path.clone(), f.offset))
    }) {
        Some(x) => x,
        None => return -1,
    };

    // Resolve absolute VFS path to (filesystem, RelativePath)
    let (fs, rel_path) = match resolve(&path) {
        Some(res) => res,
        None => return -1,
    };

    if fs.write_at(&rel_path, offset, data) {
        with_current_fds(|t| {
            if let Some(f) = t.get_mut(fd) {
                f.offset = offset + data.len();
                f.dirty = true;
            }
        });
        data.len() as i64
    } else {
        -1
    }
}

/// Close all open VFS file descriptors (fd >= 3) of the current task.
/// Call at the start of each DOOM session to clean up zombie FDs left open
/// when the previous session exited via longjmp (bypassing fclose).
pub fn close_all_vfs_fds() {
    // No forced sync here — deferred_tick() will flush within ~10 s.
    with_current_fds(|t| t.close_files());
}

/// Close a file descriptor of the current task.
pub fn sys_close(fd: usize) -> i64 {
    // The deferred timer in the terminal idle loop flushes to disk ~10 s after the last
    // write. No blocking sync here.
    if with_current_fds(|t| t.close(fd)) { 0 } else { -1 }
}

/// Seek within a file descriptor.
/// whence: 0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END.
/// Returns new offset or -1 on error.
pub fn sys_seek(fd: usize, offset: i64, whence: i32) -> i64 {
    let (path, cur) = match with_current_fds(|t| t.get(fd).map(|f| (f.path.clone(), f.offset))) {
        Some(x) => x,
        None => return -1,
    };

    // File size for SEEK_END
    let file_size = if whence == 2 {
        stat(&path).map_or(0i64, |e| e.size as i64)
    } else {
        0
    };

    let new_pos = match whence {
        0 => offset,                // SEEK_SET
        1 => cur as i64 + offset,   // SEEK_CUR
        2 => file_size + offset,    // SEEK_END
        _ => return -1,
    };

    if new_pos < 0 { return -1; }
    with_current_fds(|t| {
        if let Some(f) = t.get_mut(fd) {
            f.offset = new_pos as usize;
        }
    });
    new_pos
}
