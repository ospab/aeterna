/*
 * Entropy for OSTP: RDRAND only.
 *
 * The kernel's TLS RNG silently falls back to a TSC-seeded xorshift when the CPU
 * has no RDRAND. That is acceptable for a throwaway TLS nonce on a hobby kernel,
 * but not for Noise ephemeral keys, so OSTP refuses to start without RDRAND
 * unless the user explicitly opts into the weak source (`ostp connect --weak-rng`,
 * meant for QEMU's default `qemu64` CPU, which has no RDRAND; `-cpu max` has it).
 */

use core::sync::atomic::{AtomicBool, Ordering};

static WEAK_OK: AtomicBool = AtomicBool::new(false);

/// CPUID.01H:ECX bit 30.
pub fn has_rdrand() -> bool {
    let r = unsafe { core::arch::x86_64::__cpuid(1) };
    r.ecx & (1 << 30) != 0
}

pub fn allow_weak(on: bool) {
    WEAK_OK.store(on, Ordering::Relaxed);
}

fn rdrand64() -> Option<u64> {
    for _ in 0..10 {
        let v: u64;
        let ok: u8;
        unsafe {
            core::arch::asm!("rdrand {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok);
        }
        if ok != 0 {
            return Some(v);
        }
    }
    None
}

/// Fill `buf` with random bytes. Used as `ostp_core::sys` entropy hook, so it
/// cannot fail: callers check [`usable`] first.
pub fn fill(buf: &mut [u8]) {
    if !has_rdrand() {
        // Only reachable after `usable()` accepted the weak source.
        crate::net::tls::rng::random_bytes(buf);
        return;
    }
    let mut i = 0;
    while i < buf.len() {
        // RDRAND failing 10 times in a row is a hardware fault; keep trying
        // rather than ever returning predictable bytes.
        let v = loop {
            if let Some(v) = rdrand64() {
                break v;
            }
            core::hint::spin_loop();
        };
        let b = v.to_ne_bytes();
        let n = core::cmp::min(8, buf.len() - i);
        buf[i..i + n].copy_from_slice(&b[..n]);
        i += n;
    }
}

/// Can OSTP get acceptable entropy on this machine?
pub fn usable() -> bool {
    has_rdrand() || WEAK_OK.load(Ordering::Relaxed)
}

pub fn u32() -> u32 {
    let mut b = [0u8; 4];
    fill(&mut b);
    u32::from_le_bytes(b)
}
