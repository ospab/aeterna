/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Boot-time setup of the persistent layer of `/` and the commit thread.

The writable layer of the root overlay (vfs/cow.rs) is a `SwitchFs`. At boot it forwards to
a RamFS (live ISO, no disk). `init` looks at the AETERNA partition and switches it to an
AeternaFS v2 volume:

  v2 volume present        mount it.
  old RAM snapshot present read it completely, format a v2 volume next to it, import every
                           file, commit, check, then clear the snapshot magic. The snapshot
                           area is never written before the new volume is committed, so
                           power loss at any point leaves one usable copy.
  nothing                  format a new volume inside the AETERNA partition. A disk without
                           that partition (no GPT) is left alone.

A volume that fails to mount is never formatted: persistence stays off for that boot.
*/

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{DirEntry, FileSystem};
use super::aeternafs as aefs;
use super::disk_sync;
use super::ramfs::{RamFs, RamNode};

// ─── Switchable writable layer ──────────────────────────────────────────────

pub struct SwitchFs {
    cur: spin::RwLock<&'static dyn FileSystem>,
}

impl SwitchFs {
    pub fn new(initial: &'static dyn FileSystem) -> SwitchFs {
        SwitchFs { cur: spin::RwLock::new(initial) }
    }
    fn t(&self) -> &'static dyn FileSystem {
        *self.cur.read()
    }
    pub fn switch_to(&self, fs: &'static dyn FileSystem) {
        *self.cur.write() = fs;
    }
}

impl FileSystem for SwitchFs {
    fn name(&self) -> &str { self.t().name() }
    fn read_at(&self, path: &str, offset: usize, buf: &mut [u8]) -> Option<usize> { self.t().read_at(path, offset, buf) }
    fn read_file(&self, path: &str) -> Option<Vec<u8>> { self.t().read_file(path) }
    fn write_at(&self, path: &str, offset: usize, data: &[u8]) -> bool { self.t().write_at(path, offset, data) }
    fn write_file(&self, path: &str, data: &[u8]) -> bool { self.t().write_file(path, data) }
    fn append_file(&self, path: &str, data: &[u8]) -> bool { self.t().append_file(path, data) }
    fn readdir(&self, path: &str) -> Option<Vec<DirEntry>> { self.t().readdir(path) }
    fn mkdir(&self, path: &str) -> bool { self.t().mkdir(path) }
    fn touch(&self, path: &str) -> bool { self.t().touch(path) }
    fn exists(&self, path: &str) -> bool { self.t().exists(path) }
    fn stat(&self, path: &str) -> Option<DirEntry> { self.t().stat(path) }
    fn remove(&self, path: &str) -> bool { self.t().remove(path) }
    fn rename(&self, from: &str, to: &str) -> bool { self.t().rename(from, to) }
}

// ─── Result of the boot-time setup ──────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Info,
    Warn,
}

pub struct Report {
    pub level: Level,
    pub text: String,
}

fn rep(level: Level, text: String) -> Report {
    Report { level, text }
}

fn log(s: &str) {
    crate::arch::x86_64::serial::write_str(s);
}

fn mib(blocks: u64) -> u64 {
    blocks * 4096 / (1024 * 1024)
}

/// Put an old snapshot tree into `dst`. Returns (files, directories, all ok).
fn import_tree(tree: &alloc::collections::BTreeMap<String, RamNode>, dst: &dyn FileSystem) -> (usize, usize, bool) {
    let mut files = 0;
    let mut dirs = 0;
    let mut ok = true;
    // Sorted order: a directory comes before its children.
    for (path, node) in tree {
        if path == "/" { continue; }
        match node {
            RamNode::Dir => { if dst.mkdir(path) { dirs += 1; } else { ok = false; } }
            RamNode::File(data) => { if dst.write_file(path, data) { files += 1; } else { ok = false; } }
        }
    }
    (files, dirs, ok)
}

/// Set up the persistent layer. `sw` is the writable layer of the root overlay, `ram` the
/// RamFS it forwards to until now.
pub fn init(sw: &'static SwitchFs, ram: &'static RamFs) -> Report {
    let (disk, _, _) = match disk_sync::select_disk() {
        Some(d) => d,
        None => return rep(Level::Info, String::from("no disk: changes stay in RAM")),
    };
    let area = match disk_sync::area(disk) {
        Some(a) => a,
        None => return rep(Level::Info, String::from("no AETERNA partition: changes stay in RAM")),
    };
    log(&format!("[FS] Persistence area: disk {}, v2 volume at LBA {} ({} sectors), old snapshot at LBA {}\r\n",
        disk, area.v2_lba, area.v2_sectors, area.legacy_lba));
    let ro = disk_sync::is_read_only();

    // What is on the disk?
    let legacy = disk_sync::read_from_disk().and_then(|data| {
        let bytes = data.len();
        disk_sync::deserialize_ramfs(&data).map(|t| (t, bytes))
    });
    let has_v2 = aefs::has_v2_magic(disk, area.v2_lba);

    // A disk without an AETERNA partition belongs to someone else (an empty disk the user is
    // about to install onto, another system): it is used only if it already holds our data,
    // never formatted.
    if !area.gpt && legacy.is_none() && !has_v2 {
        return rep(Level::Info, format!("disk {} has no AETERNA partition: not touching it, changes stay in RAM", disk));
    }

    if ro {
        // Read-only: look, never write. The saved files are copied into RAM.
        if let Some((tree, bytes)) = legacy {
            ram.restore_from_tree(tree);
            return rep(Level::Info, format!("read-only (persist=ro): {} files ({} bytes) from the old snapshot loaded into RAM", ram.node_count(), bytes));
        }
        if has_v2 {
            return match aefs::mount_raw(disk, area.v2_lba, area.v2_sectors) {
                Ok(vol) => {
                    let tmp = aefs::AeFs::register(vol, "aeternafs-ro", disk, false);
                    let (f, d, _) = aefs::copy_tree(tmp, ram, "/");
                    rep(Level::Info, format!("read-only (persist=ro): {} files, {} directories loaded into RAM, nothing is written", f, d))
                }
                Err(e) => rep(Level::Warn, format!("volume on disk {} does not mount ({}); read-only, changes stay in RAM", disk, e)),
            };
        }
        return rep(Level::Info, String::from("read-only (persist=ro): no saved files"));
    }

    // Migration from the old snapshot.
    if let Some((tree, bytes)) = legacy {
        log(&format!("[FS] old RAM snapshot found ({} entries, {} bytes): migrating to AeternaFS v2\r\n", tree.len(), bytes));
        if let Err(e) = aefs::mkfs(disk, area.v2_lba, area.v2_sectors, "AETERNA") {
            return rep(Level::Warn, format!("migration failed: cannot format the volume ({}); old snapshot kept, changes stay in RAM", e));
        }
        let vol = match aefs::mount_raw(disk, area.v2_lba, area.v2_sectors) {
            Ok(v) => v,
            Err(e) => return rep(Level::Warn, format!("migration failed: new volume does not mount ({}); old snapshot kept", e)),
        };
        let fs = aefs::AeFs::register(vol, "aeternafs", disk, true);
        let (files, dirs, ok) = import_tree(&tree, fs);
        let (rf, rd, _) = if ram.node_count() > 0 { aefs::copy_tree(ram, fs, "/") } else { (0, 0, true) };
        let committed = fs.commit(true);
        let check_ok = committed && matches!(fs.fsck(false), Ok(r) if r.is_ok());
        if !(ok && check_ok) {
            // Keep the snapshot: the next boot tries again. The volume stays usable now.
            sw.switch_to(fs);
            return rep(Level::Warn, format!("migration incomplete (import ok: {}, commit and check ok: {}); old snapshot kept", ok, check_ok));
        }
        // The new copy is durable and checked. Retire the old one.
        let zero = [0u8; 512];
        let cleared = crate::drivers::write(disk, area.legacy_lba, 1, &zero) && crate::drivers::flush(disk);
        sw.switch_to(fs);
        let inf = fs.info();
        log(&format!("[FS] migration done: {} files, {} directories ({} early RAM files); old snapshot {}\r\n",
            files, dirs, rf + rd, if cleared { "cleared" } else { "could not be cleared" }));
        return rep(if cleared { Level::Ok } else { Level::Warn },
            format!("migrated {} files ({} bytes) from the old snapshot to AeternaFS v2 on disk {}, {} MiB",
                files, bytes, disk, inf.map_or(0, |i| mib(i.total_blocks))));
    }

    // Existing v2 volume.
    if has_v2 {
        return match aefs::mount_raw(disk, area.v2_lba, area.v2_sectors) {
            Ok(vol) => {
                let fs = aefs::AeFs::register(vol, "aeternafs", disk, true);
                let (rf, rd, _) = if ram.node_count() > 0 { aefs::copy_tree(ram, fs, "/") } else { (0, 0, true) };
                sw.switch_to(fs);
                match fs.info() {
                    Some(i) => rep(Level::Ok, format!("AeternaFS v2 on disk {}: generation {}, {} MiB free of {} MiB, {} snapshot(s){}",
                        disk, i.generation, mib(i.free_blocks), mib(i.total_blocks), i.snapshots,
                        if rf + rd > 0 { " (early RAM files kept)" } else { "" })),
                    None => rep(Level::Ok, format!("AeternaFS v2 on disk {}", disk)),
                }
            }
            Err(e) => rep(Level::Warn, format!("AeternaFS volume on disk {} does not mount ({}); not formatting it, changes stay in RAM", disk, e)),
        };
    }

    // Nothing there: a new volume.
    match aefs::mkfs(disk, area.v2_lba, area.v2_sectors, "AETERNA") {
        Ok(()) => match aefs::mount_raw(disk, area.v2_lba, area.v2_sectors) {
            Ok(vol) => {
                let fs = aefs::AeFs::register(vol, "aeternafs", disk, true);
                if ram.node_count() > 0 { aefs::copy_tree(ram, fs, "/"); }
                sw.switch_to(fs);
                rep(Level::Ok, format!("formatted a new AeternaFS v2 volume on disk {}, {} MiB", disk, mib(area.v2_sectors / 8)))
            }
            Err(e) => rep(Level::Warn, format!("new volume does not mount ({}); changes stay in RAM", e)),
        },
        Err(e) => rep(Level::Warn, format!("cannot format the volume ({}); changes stay in RAM", e)),
    }
}

// ─── Commit thread ──────────────────────────────────────────────────────────

extern "C" fn committer() -> ! {
    loop {
        // Sleep one second (the shell is the Idle task: this thread is Waiting almost always).
        unsafe {
            core::arch::asm!("cli");
            crate::core::scheduler::park(crate::arch::x86_64::idt::timer_ticks() + 100);
            core::arch::asm!("sti");
        }
        aefs::tick();
    }
}

/// Start the thread that commits changes on a timer, so it also happens while a full-screen
/// program owns the console. The shell idle loop calls `deferred_tick` as well.
pub fn start_committer() -> bool {
    const STACK: usize = 128 * 1024;
    let stack: &'static mut [u8] = alloc::boxed::Box::leak(alloc::vec![0u8; STACK].into_boxed_slice());
    let top = (stack.as_ptr() as u64 + STACK as u64) & !0xF;
    let ok = crate::core::scheduler::spawn_named(
        "fs-commit",
        crate::core::scheduler::Priority::Normal,
        committer as usize as u64,
        top - 8,
        0,
        &[],
    ).is_some();
    log(if ok { "[FS] commit thread started\r\n" } else { "[FS] commit thread failed to start; the shell idle loop commits\r\n" });
    ok
}

/// Is the writable layer of `/` on an AeternaFS volume?
pub fn is_active() -> bool {
    aefs::root_volume().is_some()
}
