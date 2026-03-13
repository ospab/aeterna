/*
Business Source License 1.1
Copyright (c) 2026 ospab
Distributed under the Boost Software License, Version 1.1.
See LICENSE or https://www.boost.org/LICENSE_1_0.txt for details.

Capability-based security for AETERNA microkernel.
Processes request capability tokens instead of running as root.

Design:
  - No "superuser" concept. Every privileged operation requires a token.
  - Tokens are unforgeable 128-bit descriptors (kernel-managed).
  - Token set for a process is declared in its spawn manifest
    and verified at spawn time by the kernel (intersection with parent caps).
  - Granularity: per-syscall, per-path-prefix, per-device.
  - Revocation: tokens can be explicitly revoked by the owning domain.
  - Audit: all grant/revoke operations are logged to serial (audit ledger).

Current token types:
  CapFsRead    — read files under a given path prefix
  CapFsWrite   — write/create files under a given path prefix
  CapFramebuf  — write to the GOP framebuffer
  CapSerial    — emit bytes to the serial port (COM1)
  CapMemHuge   — request huge-page (2MiB) allocations via sys_mmap
  CapSpawn     — spawn child tasks
  CapNet       — send/receive network packets
  CapDevice    — direct access to I/O ports and hardware interrupts
  CapVfsServer — permission to register as a VFS filesystem provider
*/

use core::sync::atomic::{AtomicU64, Ordering};

/// Global monotonic counter for generating unique token IDs.
/// Each token gets a unique 128-bit ID composed of (counter_hi, counter_lo).
static TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a unique 128-bit token ID.
/// Uses an atomic counter to ensure uniqueness across all grant() calls.
fn next_token_id() -> (u64, u64) {
    let lo = TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    // High part encodes a fixed namespace marker for AETERNA caps.
    // In the future, this will incorporate CSPRNG entropy.
    let hi: u64 = 0xAE7E_0A00_0000_0001;
    (hi, lo)
}

/// Unforgeable capability token.
///
/// Each instance proves the caller holds the corresponding capability.
/// Cannot be constructed outside this module and is intentionally
/// **not Clone/Copy** — tokens are non-duplicatable kernel-managed objects.
///
/// The 128-bit `id` makes tokens traceable and prepares for future
/// hardware-backed capability tables (IOMMU binding).
#[derive(Debug)]
pub struct CapabilityToken {
    /// Upper 64 bits of the 128-bit token identifier.
    pub id_hi: u64,
    /// Lower 64 bits of the 128-bit token identifier.
    pub id_lo: u64,
    /// Whether this token has been revoked.
    revoked: bool,
    /// Optional path prefix this token is scoped to (for FS tokens).
    prefix: [u8; 64],
    /// Length of the prefix (0 = no prefix constraint).
    prefix_len: u8,
}

impl CapabilityToken {
    /// Create a new token (internal — only called by grant functions).
    fn new_with_prefix(prefix: &str) -> Self {
        let (hi, lo) = next_token_id();
        let mut pfx = [0u8; 64];
        let pfx_bytes = prefix.as_bytes();
        let len = pfx_bytes.len().min(64);
        pfx[..len].copy_from_slice(&pfx_bytes[..len]);
        CapabilityToken {
            id_hi: hi,
            id_lo: lo,
            revoked: false,
            prefix: pfx,
            prefix_len: len as u8,
        }
    }

    /// Create a new token without path prefix.
    fn new_no_prefix() -> Self {
        let (hi, lo) = next_token_id();
        CapabilityToken {
            id_hi: hi,
            id_lo: lo,
            revoked: false,
            prefix: [0u8; 64],
            prefix_len: 0,
        }
    }

    /// Revoke this token. After revocation, any operation
    /// that checks this token should fail.
    pub fn revoke(&mut self) {
        if !self.revoked {
            self.revoked = true;
            cap_audit_log("REVOKE", self.id_hi, self.id_lo);
        }
    }

    /// Check if this token has been revoked.
    #[inline]
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Validate that the given path falls within this token's prefix scope.
    /// Returns true if no prefix is set (wildcard) or if path starts with prefix.
    pub fn validates_path(&self, path: &str) -> bool {
        if self.revoked {
            return false;
        }
        if self.prefix_len == 0 {
            return true; // No prefix constraint
        }
        let pfx_len = self.prefix_len as usize;
        let pfx = &self.prefix[..pfx_len];
        let path_bytes = path.as_bytes();
        if path_bytes.len() < pfx_len {
            return false;
        }
        &path_bytes[..pfx_len] == pfx
    }
}

// ─── Concrete capability types ───────────────────────────────────────────────

/// Read access to VFS paths under `prefix`.
pub struct CapFsRead;
/// Write / create access to VFS paths under `prefix`.
pub struct CapFsWrite;
/// Direct framebuffer write (GOP / VRAM).
pub struct CapFramebuf;
/// Serial port output (COM1 debug console).
pub struct CapSerial;
/// Huge-page memory mapping via SyscallNumber::Mmap.
pub struct CapMemHuge;
/// Ability to spawn new kernel tasks.
pub struct CapSpawn;
/// Network packet send/receive.
pub struct CapNet;
/// Direct access to I/O ports and hardware interrupts.
pub struct CapDevice;
/// Permission to register as a VFS filesystem provider.
pub struct CapVfsServer;

// ─── Grant helpers ───────────────────────────────────────────────────────────
// Each grant() checks the current task's capability vector.
// Only tasks whose TCB contains the matching Capability enum variant
// are allowed to acquire a token. This is enforced by the scheduler.

use crate::core::scheduler::{Capability, has_capability};

impl CapFsRead  {
    pub fn grant(prefix: &str) -> CapabilityToken {
        if !has_capability(Capability::FsRead) && !has_capability(Capability::System) {
            panic!("CapFsRead: access denied for prefix");
        }
        let tok = CapabilityToken::new_with_prefix(prefix);
        cap_audit_log("GRANT FsRead", tok.id_hi, tok.id_lo);
        tok
    }
}
impl CapFsWrite {
    pub fn grant(prefix: &str) -> CapabilityToken {
        if !has_capability(Capability::FsWrite) && !has_capability(Capability::System) {
            panic!("CapFsWrite: access denied for prefix");
        }
        let tok = CapabilityToken::new_with_prefix(prefix);
        cap_audit_log("GRANT FsWrite", tok.id_hi, tok.id_lo);
        tok
    }
}
impl CapFramebuf {
    pub fn grant() -> CapabilityToken {
        if !has_capability(Capability::Framebuf) && !has_capability(Capability::System) {
            panic!("CapFramebuf: access denied");
        }
        let tok = CapabilityToken::new_no_prefix();
        cap_audit_log("GRANT Framebuf", tok.id_hi, tok.id_lo);
        tok
    }
}
impl CapSerial  {
    pub fn grant() -> CapabilityToken {
        if !has_capability(Capability::Serial) && !has_capability(Capability::System) {
            panic!("CapSerial: access denied");
        }
        let tok = CapabilityToken::new_no_prefix();
        cap_audit_log("GRANT Serial", tok.id_hi, tok.id_lo);
        tok
    }
}
impl CapMemHuge {
    pub fn grant() -> CapabilityToken {
        if !has_capability(Capability::MemHuge) && !has_capability(Capability::System) {
            panic!("CapMemHuge: access denied");
        }
        let tok = CapabilityToken::new_no_prefix();
        cap_audit_log("GRANT MemHuge", tok.id_hi, tok.id_lo);
        tok
    }
}
impl CapSpawn   {
    pub fn grant() -> CapabilityToken {
        if !has_capability(Capability::Spawn) && !has_capability(Capability::System) {
            panic!("CapSpawn: access denied");
        }
        let tok = CapabilityToken::new_no_prefix();
        cap_audit_log("GRANT Spawn", tok.id_hi, tok.id_lo);
        tok
    }
}
impl CapNet     {
    pub fn grant() -> CapabilityToken {
        if !has_capability(Capability::Net) && !has_capability(Capability::System) {
            panic!("CapNet: access denied");
        }
        let tok = CapabilityToken::new_no_prefix();
        cap_audit_log("GRANT Net", tok.id_hi, tok.id_lo);
        tok
    }
}

impl CapDevice  {
    pub fn grant() -> CapabilityToken {
        if !has_capability(Capability::Device) && !has_capability(Capability::System) {
            panic!("CapDevice: access denied");
        }
        let tok = CapabilityToken::new_no_prefix();
        cap_audit_log("GRANT Device", tok.id_hi, tok.id_lo);
        tok
    }
}

impl CapVfsServer {
    pub fn grant() -> CapabilityToken {
        if !has_capability(Capability::VfsServer) && !has_capability(Capability::System) {
            panic!("CapVfsServer: access denied");
        }
        let tok = CapabilityToken::new_no_prefix();
        cap_audit_log("GRANT VfsServer", tok.id_hi, tok.id_lo);
        tok
    }
}

// ─── Audit ledger ────────────────────────────────────────────────────────────
// All capability grant/revoke events are logged to serial as an append-only
// audit trail. In future phases this will write to a dedicated MED ledger.

fn cap_audit_log(action: &str, id_hi: u64, id_lo: u64) {
    use crate::arch::x86_64::serial;
    serial::write_str("[CAP] ");
    serial::write_str(action);
    serial::write_str(" token=0x");
    serial_hex(id_hi);
    serial::write_str("_");
    serial_hex(id_lo);
    serial::write_str(" pid=");
    serial_dec(crate::core::scheduler::current_pid() as u64);
    serial::write_str("\r\n");
}

fn serial_hex(mut val: u64) {
    const HEX: &[u8] = b"0123456789abcdef";
    if val == 0 { crate::arch::x86_64::serial::write_byte(b'0'); return; }
    let mut buf = [0u8; 16];
    let mut i = 0;
    while val > 0 { buf[i] = HEX[(val & 0xF) as usize]; val >>= 4; i += 1; }
    for j in (0..i).rev() { crate::arch::x86_64::serial::write_byte(buf[j]); }
}

fn serial_dec(mut val: u64) {
    if val == 0 { crate::arch::x86_64::serial::write_byte(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while val > 0 { buf[i] = b'0' + (val % 10) as u8; val /= 10; i += 1; }
    for j in (0..i).rev() { crate::arch::x86_64::serial::write_byte(buf[j]); }
}

// ─── Required-capability manifest helper ─────────────────────────────────────

/// Declare the capability manifest for a module at compile time.
/// Call from module init / top of main; returns a struct holding all tokens.
///
/// Example:
/// ```rust
/// let caps = AaiCaps::acquire();
/// cmd_load("/models/foo.tmt-ai", &caps.fs_read);
/// ```
pub struct AaiCaps {
    pub fs_read:  CapabilityToken,   // read /models/*, /doom/*
    pub framebuf: CapabilityToken,   // draw inference output
    pub serial:   CapabilityToken,   // log to COM1
    pub mem_huge: CapabilityToken,   // mmap huge-page weight buffers
}

impl AaiCaps {
    /// Acquire all capabilities required by the aai utility.
    /// Kernel will deny unauthorised tasks at spawn time.
    pub fn acquire() -> Self {
        AaiCaps {
            fs_read:  CapFsRead::grant("/models"),
            framebuf: CapFramebuf::grant(),
            serial:   CapSerial::grant(),
            mem_huge: CapMemHuge::grant(),
        }
    }
}
