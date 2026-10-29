/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

RamFS — In-memory filesystem for AETERNA microkernel.

Design:
  - Uses BTreeMap<String, RamNode> to store the entire directory tree.
  - Every path is stored as an absolute path relative to the mount point.
  - Directories are just RamNode::Dir entries; their children are discovered
    by prefix-matching in the BTreeMap (sorted lexicographically).
  - Files store their data as Vec<u8>.
  - All operations are O(log n) lookup via BTreeMap.
  - Thread safety: uses a spin mutex (single-core for now).

This is NOT a stub — files created here persist in RAM until power-off.
*/

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::{DirEntry, FileSystem, NodeType};

// ─── RamFS node types ───────────────────────────────────────────────────────

/// A node in the RamFS tree (public for disk_sync.rs)
pub enum RamNode {
    /// A regular file with byte contents
    File(Vec<u8>),
    /// A directory (children discovered by prefix scan)
    Dir,
}

// ─── RamFS Struct ───────────────────────────────────────────────────────────

pub struct RamFs {
    tree: core::cell::UnsafeCell<BTreeMap<String, RamNode>>,
    lock: AtomicBool,
    pub is_dirty: AtomicBool,
    pub is_readonly: bool,
}

unsafe impl Send for RamFs {}
unsafe impl Sync for RamFs {}

impl RamFs {
    /// Create a new, empty RamFS instance.
    pub fn new() -> Self {
        Self {
            tree: core::cell::UnsafeCell::new(BTreeMap::new()),
            lock: AtomicBool::new(false),
            is_dirty: AtomicBool::new(false),
            is_readonly: false,
        }
    }

    /// Create a new RamFS instance with default system files.
    pub fn with_defaults() -> Self {
        let fs = Self::new();
        fs.populate_defaults();
        fs
    }

    fn lock(&self) {
        // Task-level lock: a contender yields the CPU (a preempted holder gets to run).
        crate::core::sync::yield_lock(&self.lock);
    }

    fn unlock(&self) {
        self.lock.store(false, Ordering::Release);
    }

    fn populate_defaults(&self) {
        self.lock();
        unsafe {
            let tree = &mut *self.tree.get();
            // Root directory
            tree.insert(String::from("/"), RamNode::Dir);

            // Standard directories
            tree.insert(String::from("/etc"), RamNode::Dir);
            tree.insert(String::from("/tmp"), RamNode::Dir);
            tree.insert(String::from("/home"), RamNode::Dir);
            tree.insert(String::from("/home/root"), RamNode::Dir);
            tree.insert(String::from("/var"), RamNode::Dir);
            tree.insert(String::from("/var/log"), RamNode::Dir);
            tree.insert(String::from("/dev"), RamNode::Dir);
            tree.insert(String::from("/boot"), RamNode::Dir);
            tree.insert(String::from("/proc"), RamNode::Dir);
            tree.insert(String::from("/sys"), RamNode::Dir);
            tree.insert(String::from("/sys/kernel"), RamNode::Dir);
            tree.insert(String::from("/sys/devices"), RamNode::Dir);
            tree.insert(String::from("/info"), RamNode::Dir);
            tree.insert(String::from("/doom"), RamNode::Dir);

            // /etc/hostname
            tree.insert(
                String::from("/etc/hostname"),
                RamNode::File(Vec::from(b"ospab\n" as &[u8])),
            );

            // /etc/os-release
            tree.insert(
                String::from("/etc/os-release"),
                RamNode::File(Vec::from(
                    concat!(
                        "NAME=\"ospab.os\"\n",
                        "ID=ospab\n",
                        "VERSION=\"", env!("CARGO_PKG_VERSION"), "\"\n",
                        "VERSION_ID=", env!("CARGO_PKG_VERSION"), "\n",
                        "PRETTY_NAME=\"ospab.os ", env!("CARGO_PKG_VERSION"), " (kernel AETERNA)\"\n",
                        "KERNEL=AETERNA\n",
                        "LICENSE=AGPL-3.0-only\n",
                    ).as_bytes() as &[u8],
                )),
            );

            // /etc/motd
            tree.insert(
                String::from("/etc/motd"),
                RamNode::File(Vec::from(
                    b"Welcome to ospab.os (AETERNA Microkernel)\nType 'help' for available commands.\n" as &[u8],
                )),
            );

            // /etc/hosts
            tree.insert(
                String::from("/etc/hosts"),
                RamNode::File(Vec::from(
                    b"# AETERNA /etc/hosts\n127.0.0.1\tlocalhost\n10.0.2.2\tgateway router host\n10.0.2.3\tdns nameserver\n216.239.35.0\ttime1.google.com ntp\n216.239.35.4\ttime2.google.com\n162.159.200.1\ttime.cloudflare.com\n" as &[u8],
                )),
            );

            // /etc/resolv.conf
            tree.insert(
                String::from("/etc/resolv.conf"),
                RamNode::File(Vec::from(
                    b"# AETERNA DNS resolver config\n# Managed manually\nnameserver 1.1.1.1\nnameserver 1.0.0.1\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n" as &[u8],
                )),
            );

            // /CHANGELOG.md
            tree.insert(
                String::from("/CHANGELOG.md"),
                RamNode::File(Vec::from(
                    b"# AETERNA Changelog\n\n## [1.0.0] - 2026-03-05\n- First public release of AETERNA microkernel\n- POSIX-style VFS layer with RamFS and AHCI sync\n- Networking via RTL8139 and Intel e1000 (ARP, IP, ICMP, UDP, SNTP)\n- Interactive shell (plum) with env, aliases, and bash scripts\n- Text editor (grape) and package manager (tomato)\n- Port of DOOM (doomgeneric) running on bare metal\n- Internal Verification Suite (IVS) for mem/sched/net/audio\n- Compute-First preemptive scheduler with Capability-based security\n- SIMD-accelerated Aeterna Neural Engine (ANE) for AI inference\n" as &[u8],
                )),
            );

            // /dev entries
            for dev in &["/dev/null", "/dev/zero", "/dev/console", "/dev/ttyS0", "/dev/fb0", "/dev/mem"] {
                tree.insert(String::from(*dev), RamNode::File(Vec::new()));
            }
        }
        self.unlock();
    }
}

// ─── Helper: normalize path ─────────────────────────────────────────────────

/// Normalize a path: remove trailing slashes, ensure starts with "/"
fn normalize(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return String::from("/");
    }
    let mut p = String::from(path);
    // Ensure starts with /
    if !p.starts_with('/') {
        p.insert(0, '/');
    }
    // Remove trailing slash
    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    p
}

/// Extract the filename (last component) from a path
fn filename(path: &str) -> &str {
    match path.rfind('/') {
        Some(pos) if pos < path.len() - 1 => &path[pos + 1..],
        _ => path,
    }
}

/// Extract the parent directory from a path
fn parent(path: &str) -> String {
    if path == "/" {
        return String::from("/");
    }
    match path.rfind('/') {
        Some(0) => String::from("/"),
        Some(pos) => String::from(&path[..pos]),
        None => String::from("/"),
    }
}

// ─── FileSystem trait implementation ────────────────────────────────────────

impl FileSystem for RamFs {
    fn name(&self) -> &str {
        "ramfs"
    }

    fn read_at(&self, path: &str, offset: usize, buf: &mut [u8]) -> Option<usize> {
        let path = normalize(path);
        self.lock();
        let result = unsafe {
            let tree = &*self.tree.get();
            match tree.get(&path) {
                Some(RamNode::File(data)) => {
                    if offset >= data.len() {
                        Some(0)
                    } else {
                        let available = data.len() - offset;
                        let to_copy = available.min(buf.len());
                        buf[..to_copy].copy_from_slice(&data[offset..offset + to_copy]);
                        Some(to_copy)
                    }
                }
                _ => None, // Not a file or doesn't exist
            }
        };
        self.unlock();
        result
    }

    fn write_at(&self, path: &str, offset: usize, data: &[u8]) -> bool {
        if self.is_readonly { return false; }
        let path = normalize(path);
        self.lock();
        let ok = unsafe {
            let tree = &mut *self.tree.get();
            match tree.get_mut(&path) {
                Some(RamNode::File(existing)) => {
                    let end = offset + data.len();
                    if existing.len() < end {
                        existing.resize(end, 0);
                    }
                    existing[offset..end].copy_from_slice(data);
                    true
                }
                _ => {
                    // File doesn't exist or is a directory — if not dir, create it
                    if tree.contains_key(&path) {
                        false
                    } else {
                        // Auto-create parent dirs
                        let par = parent(&path);
                        if par != "/" && !tree.contains_key(&par) {
                            self.mkdir_internal_locked(tree, &par);
                        }
                        let mut file_data = vec![0u8; offset + data.len()];
                        file_data[offset..offset + data.len()].copy_from_slice(data);
                        tree.insert(path, RamNode::File(file_data));
                        true
                    }
                }
            }
        };
        self.unlock();
        if ok { self.mark_dirty(); }
        ok
    }

    fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        let path = normalize(path);
        self.lock();
        let result = unsafe {
            let tree = &*self.tree.get();
            match tree.get(&path) {
                Some(RamNode::File(data)) => Some(data.clone()),
                _ => None,
            }
        };
        self.unlock();
        result
    }

    fn write_file(&self, path: &str, data: &[u8]) -> bool {
        if self.is_readonly { return false; }
        let path = normalize(path);
        self.lock();
        let ok = unsafe {
            let tree = &mut *self.tree.get();
            let par = parent(&path);
            if matches!(tree.get(&path), Some(RamNode::Dir)) || matches!(tree.get(&par), Some(RamNode::File(_))) {
                // never replace a directory (it would orphan its children)
                // and never create a file "inside" a file
                false
            } else {
                // Ensure parent directory exists
                if par != "/" && !tree.contains_key(&par) {
                    self.mkdir_internal_locked(tree, &par);
                }
                tree.insert(path, RamNode::File(Vec::from(data)));
                true
            }
        };
        self.unlock();
        if ok { self.mark_dirty(); }
        ok
    }

    fn append_file(&self, path: &str, data: &[u8]) -> bool {
        if self.is_readonly { return false; }
        let path = normalize(path);
        self.lock();
        let ok = unsafe {
            let tree = &mut *self.tree.get();
            match tree.get_mut(&path) {
                Some(RamNode::File(existing)) => {
                    existing.extend_from_slice(data);
                    true
                }
                _ => {
                    // File doesn't exist — create it
                    let par = parent(&path);
                    if par != "/" && !tree.contains_key(&par) {
                        self.mkdir_internal_locked(tree, &par);
                    }
                    tree.insert(path, RamNode::File(Vec::from(data)));
                    true
                }
            }
        };
        self.unlock();
        if ok { self.mark_dirty(); }
        ok
    }

    fn readdir(&self, path: &str) -> Option<Vec<DirEntry>> {
        let path = normalize(path);
        self.lock();
        let result = unsafe {
            let tree = &*self.tree.get();

            // Check that the directory itself exists
            match tree.get(&path) {
                Some(RamNode::Dir) => {}
                None if path == "/" => {} // root always exists
                _ => { self.unlock(); return None; }
            }

            let mut entries = Vec::new();
            let prefix = if path == "/" {
                String::from("/")
            } else {
                let mut p = path.clone();
                p.push('/');
                p
            };

            for (key, node) in tree.iter() {
                if key == "/" { continue; }
                if key.starts_with(prefix.as_str()) {
                    let rest = &key[prefix.len()..];
                    if !rest.is_empty() && !rest.contains('/') {
                        let (ntype, size) = match node {
                            RamNode::File(data) => (NodeType::File, data.len()),
                            RamNode::Dir => (NodeType::Directory, 0),
                        };
                        entries.push(DirEntry {
                            name: String::from(rest),
                            node_type: ntype,
                            size,
                        });
                    }
                }
            }

            entries.sort_by(|a, b| {
                match (a.node_type, b.node_type) {
                    (NodeType::Directory, NodeType::File) => core::cmp::Ordering::Less,
                    (NodeType::File, NodeType::Directory) => core::cmp::Ordering::Greater,
                    _ => a.name.cmp(&b.name),
                }
            });

            Some(entries)
        };
        self.unlock();
        result
    }

    fn mkdir(&self, path: &str) -> bool {
        if self.is_readonly { return false; }
        let path = normalize(path);
        self.lock();
        let ok = unsafe {
            let tree = &mut *self.tree.get();
            self.mkdir_internal_locked(tree, &path)
        };
        self.unlock();
        if ok { self.mark_dirty(); }
        ok
    }

    fn touch(&self, path: &str) -> bool {
        if self.is_readonly { return false; }
        let path = normalize(path);
        self.lock();
        let ok = unsafe {
            let tree = &mut *self.tree.get();
            if tree.contains_key(&path) {
                true
            } else {
                let par = parent(&path);
                if par != "/" && !tree.contains_key(&par) {
                    self.mkdir_internal_locked(tree, &par);
                }
                tree.insert(path, RamNode::File(Vec::new()));
                true
            }
        };
        self.unlock();
        if ok { self.mark_dirty(); }
        ok
    }

    fn exists(&self, path: &str) -> bool {
        let path = normalize(path);
        self.lock();
        let result = unsafe {
            let tree = &*self.tree.get();
            tree.contains_key(&path)
        };
        self.unlock();
        result
    }

    fn stat(&self, path: &str) -> Option<DirEntry> {
        let path = normalize(path);
        self.lock();
        let result = unsafe {
            let tree = &*self.tree.get();
            match tree.get(&path) {
                Some(RamNode::File(data)) => Some(DirEntry {
                    name: String::from(filename(&path)),
                    node_type: NodeType::File,
                    size: data.len(),
                }),
                Some(RamNode::Dir) => Some(DirEntry {
                    name: String::from(filename(&path)),
                    node_type: NodeType::Directory,
                    size: 0,
                }),
                None => None,
            }
        };
        self.unlock();
        result
    }

    fn remove(&self, path: &str) -> bool {
        if self.is_readonly { return false; }
        let path = normalize(path);
        if path == "/" { return false; }
        self.lock();
        let ok = unsafe {
            let tree = &mut *self.tree.get();
            if let Some(RamNode::Dir) = tree.get(&path) {
                let prefix = {
                    let mut p = path.clone();
                    p.push('/');
                    p
                };
                let has_children = tree.keys().any(|k| k.starts_with(prefix.as_str()));
                if has_children {
                    self.unlock();
                    return false;
                }
            }
            tree.remove(&path).is_some()
        };
        self.unlock();
        if ok { self.mark_dirty(); }
        ok
    }

    fn rename(&self, from: &str, to: &str) -> bool {
        if self.is_readonly { return false; }
        let from_path = normalize(from);
        let to_path = normalize(to);
        if from_path == to_path { return true; }

        self.lock();
        let ok = unsafe {
            let tree = &mut *self.tree.get();
            if !tree.contains_key(&from_path) {
                false
            } else {
                let prefix = alloc::format!("{}/", from_path);
                let mut moves: Vec<(String, RamNode)> = Vec::new();
                if let Some(node) = tree.remove(&from_path) {
                    moves.push((to_path.clone(), node));
                }
                let children: Vec<String> = tree.keys()
                    .filter(|k| k.starts_with(&prefix))
                    .cloned()
                    .collect();
                for child_key in children {
                    if let Some(node) = tree.remove(&child_key) {
                        let new_key = alloc::format!("{}{}", to_path, &child_key[from_path.len()..]);
                        moves.push((new_key, node));
                    }
                }
                let par = parent(&to_path);
                if par != "/" && !tree.contains_key(&par) {
                    self.mkdir_internal_locked(tree, &par);
                }
                for (path, node) in moves {
                    tree.insert(path, node);
                }
                true
            }
        };
        self.unlock();
        if ok { self.mark_dirty(); }
        ok
    }
}

impl RamFs {
    /// Create directory and all missing parents (internal, must hold lock)
    unsafe fn mkdir_internal_locked(&self, tree: &mut BTreeMap<String, RamNode>, path: &str) -> bool {
        if path == "/" || path.is_empty() { return true; }
        let par = parent(path);
        if par != "/" && !tree.contains_key(&par) {
            self.mkdir_internal_locked(tree, &par);
        }
        if !tree.contains_key(path) {
            tree.insert(String::from(path), RamNode::Dir);
        }
        true
    }

    /// Mark the filesystem dirty and record the current tick for disk sync.
    pub fn mark_dirty(&self) {
        self.is_dirty.store(true, Ordering::Relaxed);
        crate::fs::disk_sync::mark_dirty_at_tick();
    }

    /// Get number of files/dirs in this RamFS instance.
    pub fn node_count(&self) -> usize {
        self.lock();
        let count = unsafe { (*self.tree.get()).len() };
        self.unlock();
        count
    }

    /// Get a copy of the entire tree (for serialization).
    pub fn get_tree_copy(&self) -> BTreeMap<String, RamNode> {
        self.lock();
        let copy = unsafe {
            let tree = &*self.tree.get();
            let mut copy = BTreeMap::new();
            for (path, node) in tree.iter() {
                let node_copy = match node {
                    RamNode::Dir => RamNode::Dir,
                    RamNode::File(data) => RamNode::File(data.clone()),
                };
                copy.insert(String::from(path), node_copy);
            }
            copy
        };
        self.unlock();
        copy
    }

    /// Restore tree from serialized data.
    pub fn restore_from_tree(&self, tree: BTreeMap<String, RamNode>) {
        self.lock();
        unsafe {
            *self.tree.get() = tree;
        }
        self.unlock();
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn push_dec(buf: &mut Vec<u8>, val: u64) {
    if val == 0 {
        buf.push(b'0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut n = val;
    let mut i = 0;
    while n > 0 {
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in (0..i).rev() {
        buf.push(digits[j]);
    }
}
