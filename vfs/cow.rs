/*
 * AETERNA CoW (Copy-on-Write) Overlay Filesystem
 *
 * Reads come from `upper` first, then from the read-only `base`; all writes
 * go to `upper`.  A file that exists only in `base` is copied up before it
 * is modified.
 *
 * Deleting or renaming something that exists in `base` records a
 * "whiteout" (the path is hidden from then on).  Whiteouts are stored as
 * a list of paths in the upper layer file `/.cow_whiteouts`, so they are
 * saved to disk together with the rest of the upper layer.  That file is
 * hidden from directory listings.
 */

use alloc::string::String;
use alloc::vec::Vec;
use super::{FileSystem, DirEntry, NodeType};

const WHITEOUT_FILE: &str = "/.cow_whiteouts";

pub struct CowFs {
    base: &'static dyn FileSystem,
    upper: &'static dyn FileSystem,
    name: String,
}

fn norm(path: &str) -> String {
    let mut p = String::from(path);
    if !p.starts_with('/') { p.insert(0, '/'); }
    while p.len() > 1 && p.ends_with('/') { p.pop(); }
    p
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" { alloc::format!("/{}", name) } else { alloc::format!("{}/{}", dir, name) }
}

impl CowFs {
    pub fn new(base: &'static dyn FileSystem, upper: &'static dyn FileSystem) -> Self {
        CowFs {
            base,
            upper,
            name: alloc::format!("cowfs({}+{})", upper.name(), base.name()),
        }
    }

    // ── whiteouts ───────────────────────────────────────────────────────────

    fn whiteouts(&self) -> Vec<String> {
        match self.upper.read_file(WHITEOUT_FILE) {
            Some(d) => core::str::from_utf8(&d)
                .unwrap_or("")
                .lines()
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect(),
            None => Vec::new(),
        }
    }

    fn save_whiteouts(&self, list: &[String]) {
        if list.is_empty() {
            if self.upper.exists(WHITEOUT_FILE) { self.upper.remove(WHITEOUT_FILE); }
            return;
        }
        let mut s = String::new();
        for w in list { s.push_str(w); s.push('\n'); }
        self.upper.write_file(WHITEOUT_FILE, s.as_bytes());
    }

    /// Is `path` (or one of its ancestors) hidden by a whiteout?
    fn hidden(&self, path: &str) -> bool {
        if !self.upper.exists(WHITEOUT_FILE) { return false; }
        let p = norm(path);
        for w in self.whiteouts() {
            if p == w || (p.starts_with(w.as_str()) && p.as_bytes().get(w.len()) == Some(&b'/')) {
                return true;
            }
        }
        false
    }

    fn add_whiteout(&self, path: &str) {
        let p = norm(path);
        let mut list = self.whiteouts();
        if !list.iter().any(|w| *w == p) {
            list.push(p);
            self.save_whiteouts(&list);
        }
    }

    /// The path is being (re)created in upper: un-hide it and its ancestors.
    fn clear_whiteout(&self, path: &str) {
        if !self.upper.exists(WHITEOUT_FILE) { return; }
        let p = norm(path);
        let list = self.whiteouts();
        let keep: Vec<String> = list.iter()
            .filter(|w| !(p == **w || (p.starts_with(w.as_str()) && p.as_bytes().get(w.len()) == Some(&b'/'))))
            .cloned()
            .collect();
        if keep.len() != list.len() {
            self.save_whiteouts(&keep);
        }
    }

    /// Visible in base (exists there and not whited out)?
    fn in_base(&self, path: &str) -> bool {
        self.base.exists(path) && !self.hidden(path)
    }

    /// Copy a base file (or a whole base directory tree) up into upper.
    fn copy_up(&self, path: &str) -> bool {
        if self.upper.exists(path) && !matches!(self.upper.stat(path), Some(e) if e.node_type == NodeType::Directory) {
            return true;
        }
        match self.base.stat(path) {
            Some(e) if e.node_type == NodeType::Directory => {
                if !self.upper.exists(path) && !self.upper.mkdir(path) { return false; }
                if let Some(children) = self.base.readdir(path) {
                    for c in children {
                        let cp = join(path, &c.name);
                        if self.hidden(&cp) { continue; }
                        if !self.copy_up(&cp) { return false; }
                    }
                }
                true
            }
            Some(_) => match self.base.read_file(path) {
                Some(data) => {
                    crate::arch::x86_64::serial::write_str("[CowFS] Copying up file: ");
                    crate::arch::x86_64::serial::write_str(path);
                    crate::arch::x86_64::serial::write_str("\r\n");
                    self.upper.write_file(path, &data)
                }
                None => false,
            },
            None => false,
        }
    }

    fn is_dir(&self, path: &str) -> bool {
        matches!(self.stat(path), Some(e) if e.node_type == NodeType::Directory)
    }
}

impl FileSystem for CowFs {
    fn name(&self) -> &str {
        &self.name
    }

    fn read_at(&self, path: &str, offset: usize, buf: &mut [u8]) -> Option<usize> {
        if self.upper.exists(path) {
            self.upper.read_at(path, offset, buf)
        } else if self.in_base(path) {
            self.base.read_at(path, offset, buf)
        } else {
            None
        }
    }

    fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        if norm(path) == WHITEOUT_FILE { return None; }
        if self.upper.exists(path) {
            self.upper.read_file(path)
        } else if self.in_base(path) {
            self.base.read_file(path)
        } else {
            None
        }
    }

    fn write_at(&self, path: &str, offset: usize, data: &[u8]) -> bool {
        if !self.upper.exists(path) && self.in_base(path) {
            if !self.copy_up(path) {
                return false;
            }
        }
        self.clear_whiteout(path);
        self.upper.write_at(path, offset, data)
    }

    fn write_file(&self, path: &str, data: &[u8]) -> bool {
        if self.is_dir(path) { return false; }
        self.clear_whiteout(path);
        self.upper.write_file(path, data)
    }

    fn append_file(&self, path: &str, data: &[u8]) -> bool {
        if self.is_dir(path) { return false; }
        if !self.upper.exists(path) && self.in_base(path) {
            if !self.copy_up(path) {
                return false;
            }
        }
        self.clear_whiteout(path);
        self.upper.append_file(path, data)
    }

    fn readdir(&self, path: &str) -> Option<Vec<DirEntry>> {
        let p = norm(path);
        let upper_res = self.upper.readdir(&p);
        let base_res = if self.hidden(&p) && p != "/" { None } else { self.base.readdir(&p) };

        if upper_res.is_none() && base_res.is_none() {
            return None;
        }

        let mut entries: Vec<DirEntry> = Vec::new();
        if let Some(upper_entries) = upper_res {
            for entry in upper_entries {
                if p == "/" && entry.name == ".cow_whiteouts" { continue; }
                entries.push(entry);
            }
        }
        if let Some(base_entries) = base_res {
            for be in base_entries {
                if entries.iter().any(|e| e.name == be.name) { continue; }
                if self.hidden(&join(&p, &be.name)) { continue; }
                entries.push(be);
            }
        }
        Some(entries)
    }

    fn mkdir(&self, path: &str) -> bool {
        self.clear_whiteout(path);
        self.upper.mkdir(path)
    }

    fn touch(&self, path: &str) -> bool {
        if self.exists(path) { return true; }
        self.clear_whiteout(path);
        self.upper.touch(path)
    }

    fn exists(&self, path: &str) -> bool {
        if norm(path) == WHITEOUT_FILE { return false; }
        self.upper.exists(path) || self.in_base(path)
    }

    fn stat(&self, path: &str) -> Option<DirEntry> {
        if norm(path) == WHITEOUT_FILE { return None; }
        if self.upper.exists(path) {
            self.upper.stat(path)
        } else if self.in_base(path) {
            self.base.stat(path)
        } else {
            None
        }
    }

    fn remove(&self, path: &str) -> bool {
        let p = norm(path);
        if p == "/" || !self.exists(&p) { return false; }
        // a directory must be empty in the merged view
        if self.is_dir(&p) {
            if let Some(children) = self.readdir(&p) {
                if !children.is_empty() { return false; }
            }
        }
        if self.upper.exists(&p) && !self.upper.remove(&p) {
            return false;
        }
        if self.base.exists(&p) {
            self.add_whiteout(&p);
        }
        true
    }

    fn rename(&self, from: &str, to: &str) -> bool {
        let from = norm(from);
        let to = norm(to);
        if !self.exists(&from) { return false; }
        if from == to { return true; }
        // bring the whole source into upper first
        if self.in_base(&from) && !self.copy_up(&from) {
            return false;
        }
        self.clear_whiteout(&to);
        if !self.upper.rename(&from, &to) {
            return false;
        }
        if self.base.exists(&from) {
            self.add_whiteout(&from);
        }
        true
    }
}
