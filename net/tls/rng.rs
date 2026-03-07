/*
 * Cryptographic RNG — RDRAND instruction (Intel Ivy Bridge+, AMD Zen+)
 *
 * Falls back to TSC-seeded xorshift128+ if RDRAND unavailable.
 * Used for TLS client_random, pre_master_secret padding, CBC IVs.
 */

use core::sync::atomic::{AtomicU64, Ordering};

static RNG_S0: AtomicU64 = AtomicU64::new(0);
static RNG_S1: AtomicU64 = AtomicU64::new(0);
static RNG_SEEDED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Check if the CPU supports RDRAND (CPUID.01H:ECX bit 30).
fn has_rdrand() -> bool {
    let ecx: u32;
    unsafe {
        // rbx is reserved by LLVM — save/restore it around cpuid
        core::arch::asm!(
            "xchg {tmp:r}, rbx",
            "mov eax, 1",
            "cpuid",
            "xchg {tmp:r}, rbx",
            tmp = out(reg) _,
            out("eax") _,
            out("ecx") ecx,
            out("edx") _,
        );
    }
    ecx & (1 << 30) != 0
}

/// Attempt one RDRAND call.  Returns None if CF=0 (retry exhausted by CPU).
fn rdrand64() -> Option<u64> {
    let val: u64;
    let ok: u8;
    unsafe {
        core::arch::asm!(
            "rdrand {v}",
            "setc {ok}",
            v = out(reg) val,
            ok = out(reg_byte) ok,
        );
    }
    if ok != 0 { Some(val) } else { None }
}

/// Try RDRAND up to 10 times (Intel recommends ≤10 retries).
fn rdrand64_retry() -> Option<u64> {
    for _ in 0..10 {
        if let Some(v) = rdrand64() {
            return Some(v);
        }
    }
    None
}

/// Seed the fallback xorshift128+ from TSC.
fn seed_xorshift() {
    if RNG_SEEDED.load(Ordering::Relaxed) {
        return;
    }
    let tsc = crate::arch::x86_64::tsc::read();
    let ticks = crate::arch::x86_64::idt::timer_ticks();
    let s0 = tsc ^ 0x5DEECE66D_u64;
    let s1 = (ticks.wrapping_mul(6364136223846793005)) ^ 0xCAFEBABE_u64;
    RNG_S0.store(s0, Ordering::Relaxed);
    RNG_S1.store(if s1 != 0 { s1 } else { 1 }, Ordering::Relaxed);
    RNG_SEEDED.store(true, Ordering::Relaxed);
}

/// xorshift128+ (not cryptographically secure, but usable as last resort).
fn xorshift128plus() -> u64 {
    let mut s1 = RNG_S0.load(Ordering::Relaxed);
    let s0 = RNG_S1.load(Ordering::Relaxed);
    RNG_S0.store(s0, Ordering::Relaxed);
    s1 ^= s1 << 23;
    s1 ^= s1 >> 17;
    s1 ^= s0;
    s1 ^= s0 >> 26;
    RNG_S1.store(s1, Ordering::Relaxed);
    s0.wrapping_add(s1)
}

/// Generate a single random u64.  Prefers RDRAND, falls back to xorshift.
pub fn random_u64() -> u64 {
    if has_rdrand() {
        if let Some(v) = rdrand64_retry() {
            return v;
        }
    }
    seed_xorshift();
    xorshift128plus()
}

/// Fill buffer with random bytes.
pub fn random_bytes(buf: &mut [u8]) {
    let use_hw = has_rdrand();
    let mut i = 0;
    while i < buf.len() {
        let val = if use_hw {
            rdrand64_retry().unwrap_or_else(|| { seed_xorshift(); xorshift128plus() })
        } else {
            seed_xorshift();
            xorshift128plus()
        };
        let bytes = val.to_ne_bytes();
        let take = core::cmp::min(8, buf.len() - i);
        buf[i..i + take].copy_from_slice(&bytes[..take]);
        i += take;
    }
}
