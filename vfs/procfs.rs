/*
 * ProcFs — Virtual /proc filesystem for AETERNA microkernel
 *
 * BSL 1.1 — Copyright (c) 2026 ospab
 *
 * Read-only pseudo-filesystem providing system introspection.
 * All content is generated on-the-fly from kernel state.
 */

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use super::{DirEntry, FileSystem, NodeType};

/// ZST singleton for the ProcFs implementation
pub struct ProcFsInstance;

static mut INSTANCE: ProcFsInstance = ProcFsInstance;

/// Get a static reference to the ProcFs instance for mounting
pub fn instance() -> &'static dyn FileSystem {
    unsafe { &INSTANCE }
}

unsafe impl Send for ProcFsInstance {}
unsafe impl Sync for ProcFsInstance {}

/// Known virtual files in /proc
const PROC_FILES: &[&str] = &[
    "cpuinfo",
    "meminfo",
    "uptime",
    "version",
    "tasks",
    "mounts",
    "cmdline",
];

impl ProcFsInstance {
    /// Generate content for a given proc file
    fn generate(&self, name: &str) -> Option<Vec<u8>> {
        match name {
            "cpuinfo" | "/cpuinfo" => Some(self.gen_cpuinfo()),
            "meminfo" | "/meminfo" => Some(self.gen_meminfo()),
            "uptime"  | "/uptime"  => Some(self.gen_uptime()),
            "version" | "/version" => Some(self.gen_version()),
            "tasks"   | "/tasks"   => Some(self.gen_tasks()),
            "mounts"  | "/mounts"  => Some(self.gen_mounts()),
            "cmdline" | "/cmdline" => Some(self.gen_cmdline()),
            _ => None,
        }
    }

    fn gen_cpuinfo(&self) -> Vec<u8> {
        let tsc_freq = crate::arch::x86_64::tsc::mhz();
        let mut s = String::new();
        s.push_str("processor\t: 0\n");
        s.push_str(&format!("cpu MHz\t\t: {}\n", tsc_freq));
        s.push_str("flags\t\t: fpu sse sse2 sse3 ssse3 sse4_1 sse4_2 x86-64 tsc\n");
        s.push_str("model name\t: AETERNA Compute Core\n");
        s.push_str("bogomips\t: ");
        s.push_str(&format!("{}\n", tsc_freq * 2));
        s.into_bytes()
    }

    fn gen_meminfo(&self) -> Vec<u8> {
        let phys = crate::mm::physical::stats();
        let (heap_used, heap_free) = crate::mm::heap::stats();
        let heap_total = crate::mm::heap::heap_size();

        let mut s = String::new();
        s.push_str(&format!("MemTotal:       {} kB\n", phys.total_bytes / 1024));
        s.push_str(&format!("MemUsable:      {} kB\n", phys.usable_bytes / 1024));
        s.push_str(&format!("MemReserved:    {} kB\n", phys.reserved_bytes / 1024));
        s.push_str(&format!("HeapTotal:      {} kB\n", heap_total / 1024));
        s.push_str(&format!("HeapUsed:       {} kB\n", heap_used / 1024));
        s.push_str(&format!("HeapFree:       {} kB\n", heap_free / 1024));
        s.push_str(&format!("PhysRegions:    {}\n", phys.region_count));
        s.push_str(&format!("FramesAlloc:    {}\n", crate::mm::physical::frames_allocated()));
        s.into_bytes()
    }

    fn gen_uptime(&self) -> Vec<u8> {
        let ticks = crate::arch::x86_64::idt::timer_ticks();
        let secs = ticks / 100; // PIT runs at ~100 Hz
        let frac = ticks % 100;
        format!("{}.{:02}\n", secs, frac).into_bytes()
    }

    fn gen_version(&self) -> Vec<u8> {
        b"AETERNA v1.0.0 (ospab.os) x86_64 Rust no_std microkernel\n".to_vec()
    }

    fn gen_tasks(&self) -> Vec<u8> {
        use crate::core::scheduler::{TaskSnapshot, name_from_snapshot};
        let mut buf = [core::mem::MaybeUninit::<TaskSnapshot>::uninit(); 64];
        // SAFETY: get_tasks fills the buffer with valid data up to returned count
        let snapshots: &mut [TaskSnapshot] = unsafe {
            core::mem::transmute::<&mut [core::mem::MaybeUninit<TaskSnapshot>; 64], &mut [TaskSnapshot; 64]>(&mut buf)
        };
        let count = crate::core::scheduler::get_tasks(snapshots);

        let mut s = String::new();
        s.push_str("PID  PRI   STATE     TICKS      NAME\n");
        s.push_str("---  ---   -----     -----      ----\n");
        for i in 0..count {
            let t = &snapshots[i];
            let state = match t.state {
                crate::core::scheduler::TaskState::Ready   => "Ready  ",
                crate::core::scheduler::TaskState::Running => "Running",
                crate::core::scheduler::TaskState::Waiting => "Waiting",
                crate::core::scheduler::TaskState::Dead    => "Dead   ",
            };
            let prio = match t.priority {
                crate::core::scheduler::Priority::Idle     => "IDLE",
                crate::core::scheduler::Priority::Normal   => "NORM",
                crate::core::scheduler::Priority::System   => "SYS ",
                crate::core::scheduler::Priority::RealTime => "RT  ",
                crate::core::scheduler::Priority::Compute  => "COMP",
            };
            let name = name_from_snapshot(t);
            s.push_str(&format!("{:<4} {}  {}  {:<10} {}\n",
                t.pid, prio, state, t.cpu_ticks, name));
        }
        s.into_bytes()
    }

    fn gen_mounts(&self) -> Vec<u8> {
        // We can't easily iterate the mounts table from here without exposing it,
        // so we generate a known-good static list based on boot config.
        let mut s = String::new();
        s.push_str("ramfs on / type ramfs (rw)\n");
        s.push_str("procfs on /proc type procfs (ro)\n");
        // If AeternaFS is mounted, add it
        if crate::fs::exists("/aeternafs") {
            s.push_str("aeternafs on /aeternafs type aeternafs (rw)\n");
        }
        s.into_bytes()
    }

    fn gen_cmdline(&self) -> Vec<u8> {
        b"BOOT_IMAGE=aeterna root=ramfs console=ttyS0,115200\n".to_vec()
    }
}

impl FileSystem for ProcFsInstance {
    fn name(&self) -> &str { "procfs" }

    fn read_at(&self, path: &str, offset: usize, buf: &mut [u8]) -> Option<usize> {
        let data = self.generate(path)?;
        if offset >= data.len() { return Some(0); }
        let available = &data[offset..];
        let to_copy = available.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&available[..to_copy]);
        Some(to_copy)
    }

    fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        self.generate(path)
    }

    fn write_at(&self, _path: &str, _offset: usize, _data: &[u8]) -> bool { false }
    fn write_file(&self, _path: &str, _data: &[u8]) -> bool { false }
    fn append_file(&self, _path: &str, _data: &[u8]) -> bool { false }
    fn mkdir(&self, _path: &str) -> bool { false }
    fn touch(&self, _path: &str) -> bool { false }
    fn remove(&self, _path: &str) -> bool { false }

    fn exists(&self, path: &str) -> bool {
        let name = path.trim_start_matches('/');
        if name.is_empty() { return true; } // Root /proc itself
        PROC_FILES.contains(&name)
    }

    fn stat(&self, path: &str) -> Option<DirEntry> {
        let name = path.trim_start_matches('/');
        if name.is_empty() {
            return Some(DirEntry {
                name: String::from("proc"),
                node_type: NodeType::Directory,
                size: 0,
            });
        }
        if PROC_FILES.contains(&name) {
            let data = self.generate(path)?;
            Some(DirEntry {
                name: String::from(name),
                node_type: NodeType::File,
                size: data.len(),
            })
        } else {
            None
        }
    }

    fn readdir(&self, path: &str) -> Option<Vec<DirEntry>> {
        let name = path.trim_start_matches('/');
        if !name.is_empty() { return None; } // Only root directory listing

        let mut entries = Vec::new();
        for &file in PROC_FILES {
            let size = self.generate(file).map(|d| d.len() as u64).unwrap_or(0);
            entries.push(DirEntry {
                name: String::from(file),
                node_type: NodeType::File,
                size: size as usize,
            });
        }
        Some(entries)
    }
}
