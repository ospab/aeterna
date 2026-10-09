/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 ospab
 *
 * ProcFs — virtual /proc filesystem for the AETERNA kernel.
 *
 * Read-only pseudo-filesystem. Every file is generated on read from live
 * kernel state (CPUID, physical frame allocator, heap, scheduler, timer).
 * Nothing here is a hardcoded number.
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

/// PIT tick rate that drives `idt::timer_ticks()`.
const TIMER_HZ: u64 = 100;

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

/// CPUID feature bits worth showing: (leaf, register, bit, name).
/// register: 0 = EDX of leaf 1, 1 = ECX of leaf 1, 2 = EBX of leaf 7,
///           3 = EDX of 0x8000_0001, 4 = ECX of 0x8000_0001.
const CPU_FLAGS: &[(u8, u8, &str)] = &[
    (0, 0, "fpu"), (0, 4, "tsc"), (0, 5, "msr"), (0, 6, "pae"), (0, 8, "cx8"),
    (0, 9, "apic"), (0, 11, "sep"), (0, 12, "mtrr"), (0, 13, "pge"), (0, 15, "cmov"),
    (0, 16, "pat"), (0, 19, "clflush"), (0, 23, "mmx"), (0, 24, "fxsr"),
    (0, 25, "sse"), (0, 26, "sse2"), (0, 28, "ht"),
    (1, 0, "sse3"), (1, 1, "pclmulqdq"), (1, 9, "ssse3"), (1, 12, "fma"),
    (1, 13, "cx16"), (1, 19, "sse4_1"), (1, 20, "sse4_2"), (1, 21, "x2apic"),
    (1, 22, "movbe"), (1, 23, "popcnt"), (1, 25, "aes"), (1, 26, "xsave"),
    (1, 28, "avx"), (1, 29, "f16c"), (1, 30, "rdrand"), (1, 31, "hypervisor"),
    (2, 0, "fsgsbase"), (2, 3, "bmi1"), (2, 5, "avx2"), (2, 7, "smep"),
    (2, 8, "bmi2"), (2, 9, "erms"), (2, 16, "avx512f"), (2, 18, "rdseed"),
    (2, 20, "smap"),
    (3, 11, "syscall"), (3, 20, "nx"), (3, 26, "pdpe1gb"), (3, 27, "rdtscp"),
    (3, 29, "lm"),
    (4, 0, "lahf_lm"), (4, 5, "abm"),
];

fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    // SAFETY: CPUID is available on every x86-64 CPU.
    let r = unsafe { core::arch::x86_64::__cpuid_count(leaf, sub) };
    (r.eax, r.ebx, r.ecx, r.edx)
}

fn push_reg_ascii(s: &mut String, reg: u32) {
    for b in reg.to_le_bytes() {
        if b != 0 { s.push(b as char); }
    }
}

impl ProcFsInstance {
    /// Generate content for a given proc file
    fn generate(&self, name: &str) -> Option<Vec<u8>> {
        match name.trim_start_matches('/') {
            "cpuinfo" => Some(self.gen_cpuinfo()),
            "meminfo" => Some(self.gen_meminfo()),
            "uptime"  => Some(self.gen_uptime()),
            "version" => Some(self.gen_version()),
            "tasks"   => Some(self.gen_tasks()),
            "mounts"  => Some(self.gen_mounts()),
            "cmdline" => Some(self.gen_cmdline()),
            _ => None,
        }
    }

    fn gen_cpuinfo(&self) -> Vec<u8> {
        let (max_leaf, vb, vc, vd) = cpuid(0, 0);
        let mut vendor = String::new();
        push_reg_ascii(&mut vendor, vb);
        push_reg_ascii(&mut vendor, vd);
        push_reg_ascii(&mut vendor, vc);

        let (eax1, _, ecx1, edx1) = cpuid(1, 0);
        let stepping = eax1 & 0xF;
        let base_model = (eax1 >> 4) & 0xF;
        let base_family = (eax1 >> 8) & 0xF;
        let ext_model = (eax1 >> 16) & 0xF;
        let ext_family = (eax1 >> 20) & 0xFF;
        let family = if base_family == 0xF { base_family + ext_family } else { base_family };
        let model = if base_family == 0x6 || base_family == 0xF {
            (ext_model << 4) | base_model
        } else {
            base_model
        };

        let ebx7 = if max_leaf >= 7 { cpuid(7, 0).1 } else { 0 };
        let (max_ext, _, _, _) = cpuid(0x8000_0000, 0);
        let (ecx_ext, edx_ext) = if max_ext >= 0x8000_0001 {
            let r = cpuid(0x8000_0001, 0);
            (r.2, r.3)
        } else {
            (0, 0)
        };

        let mut brand = String::new();
        if max_ext >= 0x8000_0004 {
            for leaf in 0x8000_0002u32..=0x8000_0004 {
                let (a, b, c, d) = cpuid(leaf, 0);
                push_reg_ascii(&mut brand, a);
                push_reg_ascii(&mut brand, b);
                push_reg_ascii(&mut brand, c);
                push_reg_ascii(&mut brand, d);
            }
        }
        let brand = brand.trim();

        let regs = [edx1, ecx1, ebx7, edx_ext, ecx_ext];
        let mut flags = String::new();
        for &(reg, bit, name) in CPU_FLAGS {
            if regs[reg as usize] & (1u32 << bit) != 0 {
                if !flags.is_empty() { flags.push(' '); }
                flags.push_str(name);
            }
        }

        let mhz = crate::arch::x86_64::tsc::mhz();
        let mut s = String::new();
        s.push_str("processor\t: 0\n");
        s.push_str(&format!("vendor_id\t: {}\n", vendor));
        s.push_str(&format!("cpu family\t: {}\n", family));
        s.push_str(&format!("model\t\t: {}\n", model));
        s.push_str(&format!("model name\t: {}\n", if brand.is_empty() { "unknown" } else { brand }));
        s.push_str(&format!("stepping\t: {}\n", stepping));
        if mhz > 0 {
            s.push_str(&format!("cpu MHz\t\t: {} (TSC, calibrated at boot)\n", mhz));
        } else {
            s.push_str("cpu MHz\t\t: unknown (TSC not calibrated)\n");
        }
        s.push_str(&format!("flags\t\t: {}\n", flags));
        s.push_str("cpus online\t: 1 (only the boot CPU runs; SMP is not implemented)\n");
        s.into_bytes()
    }

    fn gen_meminfo(&self) -> Vec<u8> {
        let phys = crate::mm::physical::stats();
        let frames_used = crate::mm::physical::frames_allocated();
        let frames_free = crate::mm::physical::frames_free();
        let (heap_used, heap_free) = if crate::mm::heap::is_initialized() {
            crate::mm::heap::stats()
        } else {
            (0, 0)
        };
        let heap_total = crate::mm::heap::heap_size();

        let mut s = String::new();
        s.push_str(&format!("MemTotal:       {:>10} kB\n", (frames_used + frames_free) * 4));
        s.push_str(&format!("MemFree:        {:>10} kB\n", frames_free * 4));
        s.push_str(&format!("MemUsed:        {:>10} kB\n", frames_used * 4));
        s.push_str(&format!("Usable:         {:>10} kB\n", phys.usable_bytes / 1024));
        s.push_str(&format!("MapTotal:       {:>10} kB\n", phys.total_bytes / 1024));
        s.push_str(&format!("HeapTotal:      {:>10} kB\n", heap_total / 1024));
        s.push_str(&format!("HeapUsed:       {:>10} kB\n", heap_used / 1024));
        s.push_str(&format!("HeapFree:       {:>10} kB\n", heap_free / 1024));
        s.push_str(&format!("FramesUsed:     {:>10}\n", frames_used));
        s.push_str(&format!("FramesFree:     {:>10}\n", frames_free));
        s.push_str(&format!("UsableRegions:  {:>10}\n", phys.region_count));
        s.into_bytes()
    }

    fn gen_uptime(&self) -> Vec<u8> {
        let ticks = crate::arch::x86_64::idt::timer_ticks();
        let secs = ticks / TIMER_HZ;
        let frac = (ticks % TIMER_HZ) * 100 / TIMER_HZ;
        format!("{}.{:02}\n", secs, frac).into_bytes()
    }

    fn gen_version(&self) -> Vec<u8> {
        format!(
            "AETERNA version {} (ospab.os) x86_64, Rust no_std, license AGPL-3.0-only\n",
            env!("CARGO_PKG_VERSION")
        )
        .into_bytes()
    }

    fn gen_tasks(&self) -> Vec<u8> {
        use crate::core::scheduler::{TaskSnapshot, name_from_snapshot};
        // SAFETY: TaskSnapshot is plain data (integers and field-less enums
        // whose zero value is a valid variant); get_tasks overwrites the used
        // prefix and only that prefix is read.
        let mut snapshots: [TaskSnapshot; 64] = unsafe { core::mem::zeroed() };
        let count = crate::core::scheduler::get_tasks(&mut snapshots);

        let mut s = String::new();
        s.push_str("PID   PRIO  STATE    CPU_TICKS   NAME\n");
        for t in &snapshots[..count] {
            let state = match t.state {
                crate::core::scheduler::TaskState::Ready   => "ready",
                crate::core::scheduler::TaskState::Running => "running",
                crate::core::scheduler::TaskState::Waiting => "waiting",
                crate::core::scheduler::TaskState::Dead    => "dead",
            };
            let prio = match t.priority {
                crate::core::scheduler::Priority::Idle     => "idle",
                crate::core::scheduler::Priority::Normal   => "norm",
                crate::core::scheduler::Priority::System   => "sys",
                crate::core::scheduler::Priority::RealTime => "rt",
                crate::core::scheduler::Priority::Compute  => "comp",
            };
            let name = name_from_snapshot(t);
            s.push_str(&format!("{:<5} {:<5} {:<8} {:<11} {}\n",
                t.pid, prio, state, t.cpu_ticks, name));
        }
        s.into_bytes()
    }

    fn gen_mounts(&self) -> Vec<u8> {
        // The VFS has no API to enumerate its mount table yet, so this lists
        // the two mounts made at boot (src/main.rs) and probes for the
        // optional on-disk filesystem.
        let mut s = String::new();
        s.push_str("cowfs / cowfs rw 0 0\n");
        s.push_str("procfs /proc procfs ro 0 0\n");
        if crate::fs::exists("/aeternafs") {
            s.push_str("aeternafs /aeternafs aeternafs rw 0 0\n");
        }
        s.into_bytes()
    }

    fn gen_cmdline(&self) -> Vec<u8> {
        let mut s = String::from(crate::arch::x86_64::boot::kernel_cmdline());
        s.push('\n');
        s.into_bytes()
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
            let size = self.generate(file).map(|d| d.len()).unwrap_or(0);
            entries.push(DirEntry {
                name: String::from(file),
                node_type: NodeType::File,
                size,
            });
        }
        Some(entries)
    }
}
