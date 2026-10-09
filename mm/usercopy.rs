/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Safe access to user memory from the kernel.

The kernel never dereferences a pointer it got from ring 3. It copies through
`copy_from_user` / `copy_to_user`, which
  1. reject ranges that are not entirely in the lower (user) half, and
  2. survive a page fault: if the user passed an unmapped address, the #PF
     handler sees the fault inside the copy routine and resumes at a fixup
     label that reports how many bytes were left, instead of panicking.

When the CPU supports them, SMEP (kernel may not execute user pages) and SMAP
(kernel may not touch user pages except inside STAC/CLAC) are enabled, so a
forgotten raw access traps instead of silently working.
*/

use alloc::string::String;
use alloc::vec::Vec;

/// First address that is not user space (start of the non-canonical hole).
pub const USER_END: u64 = 0x0000_8000_0000_0000;

/// Set once at boot if CR4.SMAP was enabled; the copy routine then brackets
/// the access with STAC/CLAC (those instructions #UD without SMAP support).
#[no_mangle]
static mut OOS_SMAP_ENABLED: u8 = 0;

/// Copy `len` bytes from `src` to `dst`. Returns the number of bytes NOT copied:
/// 0 on success, non-zero if a page fault stopped the copy.
#[unsafe(naked)]
unsafe extern "C" fn copy_raw(_dst: *mut u8, _src: *const u8, _len: usize) -> usize {
    core::arch::naked_asm!(
        "mov rcx, rdx",
        "cmp byte ptr [rip + {smap}], 0",
        "je 2f",
        "stac",
        "2:",
        ".globl oos_usercopy_start",
        "oos_usercopy_start:",
        "rep movsb",
        ".globl oos_usercopy_end",
        "oos_usercopy_end:",
        // A fault inside [start, end) resumes here with RCX = bytes remaining.
        ".globl oos_usercopy_fixup",
        "oos_usercopy_fixup:",
        "mov rax, rcx",
        "cmp byte ptr [rip + {smap}], 0",
        "je 3f",
        "clac",
        "3:",
        "ret",
        smap = sym OOS_SMAP_ENABLED,
    );
}

extern "C" {
    static oos_usercopy_start: u8;
    static oos_usercopy_end: u8;
    static oos_usercopy_fixup: u8;
}

/// Called by the page-fault handler for faults in ring 0. If the fault happened
/// inside the user-copy routine, returns the RIP to resume at.
pub fn fixup_for(fault_rip: u64) -> Option<u64> {
    // SAFETY: only the addresses of these labels are taken.
    let (start, end, fixup) = unsafe {
        (
            &oos_usercopy_start as *const u8 as u64,
            &oos_usercopy_end as *const u8 as u64,
            &oos_usercopy_fixup as *const u8 as u64,
        )
    };
    (fault_rip >= start && fault_rip < end).then_some(fixup)
}

/// Errors returned to syscalls (they map these to negative codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserCopyError {
    /// Range is not entirely in user space, or overflows.
    BadAddress,
    /// Range is in user space but not (fully) mapped.
    Fault,
    /// Larger than the caller's limit.
    TooLarge,
}

/// True if `[addr, addr + len)` lies entirely in user space.
pub fn range_ok(addr: u64, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    match addr.checked_add(len as u64) {
        Some(end) => end <= USER_END,
        None => false,
    }
}

/// Copy `dst.len()` bytes from user address `src` into a kernel buffer.
pub fn copy_from_user(dst: &mut [u8], src: u64) -> Result<(), UserCopyError> {
    if !range_ok(src, dst.len()) {
        return Err(UserCopyError::BadAddress);
    }
    if dst.is_empty() {
        return Ok(());
    }
    // SAFETY: dst is a valid kernel buffer; src was range-checked and faults are fixed up.
    let left = unsafe { copy_raw(dst.as_mut_ptr(), src as *const u8, dst.len()) };
    if left == 0 { Ok(()) } else { Err(UserCopyError::Fault) }
}

/// Copy `src` from a kernel buffer to user address `dst`.
pub fn copy_to_user(dst: u64, src: &[u8]) -> Result<(), UserCopyError> {
    if !range_ok(dst, src.len()) {
        return Err(UserCopyError::BadAddress);
    }
    if src.is_empty() {
        return Ok(());
    }
    // SAFETY: as above, with the roles swapped.
    let left = unsafe { copy_raw(dst as *mut u8, src.as_ptr(), src.len()) };
    if left == 0 { Ok(()) } else { Err(UserCopyError::Fault) }
}

/// Copy a user buffer of `len` bytes (at most `max`) into a new kernel Vec.
pub fn read_user_bytes(src: u64, len: usize, max: usize) -> Result<Vec<u8>, UserCopyError> {
    if len > max {
        return Err(UserCopyError::TooLarge);
    }
    let mut buf = alloc::vec![0u8; len];
    copy_from_user(&mut buf, src)?;
    Ok(buf)
}

/// Copy a UTF-8 string of `len` bytes (at most `max`) from user space.
/// Invalid UTF-8 is reported as `BadAddress`.
pub fn read_user_str(src: u64, len: usize, max: usize) -> Result<String, UserCopyError> {
    let bytes = read_user_bytes(src, len, max)?;
    String::from_utf8(bytes).map_err(|_| UserCopyError::BadAddress)
}

/// Enable SMEP and SMAP if the CPU supports them. Call once, after the kernel
/// stops touching user mappings directly. Returns (SMEP on, SMAP on).
pub fn init() -> (bool, bool) {
    let serial = crate::arch::x86_64::serial::write_str;
    let rbx_out: u64;
    // SAFETY: CPUID leaf 7 subleaf 0 is always safe to query (returns zeros if unsupported).
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            tmp = out(reg) rbx_out,
            inout("eax") 7u32 => _,
            inout("ecx") 0u32 => _,
            out("edx") _,
            options(nomem, nostack, preserves_flags),
        );
    }
    let ebx = rbx_out as u32;
    let smep = ebx & (1 << 7) != 0;
    let smap = ebx & (1 << 20) != 0;
    // SAFETY: setting CR4 feature bits the CPU reports as supported.
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        if smep {
            cr4 |= 1 << 20;
        }
        if smap {
            cr4 |= 1 << 21;
        }
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
        if smap {
            OOS_SMAP_ENABLED = 1;
        }
    }
    serial("[USERCOPY] SMEP ");
    serial(if smep { "on" } else { "not supported" });
    serial(", SMAP ");
    serial(if smap { "on" } else { "not supported" });
    serial("\r\n");
    (smep, smap)
}
