/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
*/
#![no_std]
// In a bare-metal kernel we intentionally access mutable statics directly;
// wrapping every site in a Mutex would require OS primitives we don't have yet.
#![allow(static_mut_refs)]

extern crate alloc;

#[path = "../arch/mod.rs"]
pub mod arch;

#[path = "../mm/mod.rs"]
pub mod mm;

// Re-export arch modules for easier access
pub use arch::x86_64::serial;

#[path = "../core/mod.rs"]
pub mod core;

// Kernel event log — used by panic handler and terminal
pub mod klog;

// System wall clock (ns since 2012-08-09 UTC)
pub mod time;

// Network and Storage moved to userspace (microkernel separation)

// ACPI tables, PCI config, and XHCI USB
pub mod acpi;
pub mod pci;
pub mod xhci;

// VFS moved to userspace (microkernel separation)

// Compatibility proxies for the monolith-to-microkernel transition
pub use userspace::fs;
pub use userspace::net;
pub use userspace::drivers_core as drivers;

// Userspace modules (kernel-integrated, VFS-only access)
pub mod userspace;

// Re-export AXON coreutils
pub use userspace::axon;

// Re-export plum for backward compatibility
pub use userspace::plum;

// DOOM engine (bare-metal port)
pub mod doom;

// AETERNA AI Model (AAM) - minimal transformer + tokenizer
// ─── ANE — Aeterna Neural Engine (no_std PyTorch replacement) ───────────────
// bench — System Latency Tax benchmark (RDTSC FMA workload)
pub mod bench;

// ─── Tiny formatting helpers (no_std, no alloc) ─────────────────────────────

/// Format a u64 as decimal ASCII into `buf` (must be ≥ 8 bytes).
/// Returns the filled sub-slice as `&str`.
pub fn format_u64<'a>(buf: &'a mut [u8; 8], val: u64) -> &'a str {
    if val == 0 {
        buf[0] = b'0';
        return ::core::str::from_utf8(&buf[..1]).unwrap_or("0");
    }
    let mut n = val;
    let mut end = 0usize;
    while n > 0 && end < buf.len() {
        buf[end] = b'0' + (n % 10) as u8;
        n /= 10;
        end += 1;
    }
    buf[..end].reverse();
    ::core::str::from_utf8(&buf[..end]).unwrap_or("?")
}