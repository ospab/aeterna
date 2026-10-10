/*
 * TSC — Time Stamp Counter  (x86_64)
 *
 * Provides sub-microsecond wall-clock reads after one-time calibration
 * against the PIT channel 0's known 100 Hz tick rate.
 *
 * API
 * ───
 *   calibrate()        → call once after PIT has been programmed (in init())
 *   read() -> u64      → raw RDTSC value
 *   tsc_us() -> u64    → microseconds since calibration
 *   tsc_ns() -> u64    → nanoseconds  since calibration  (≈ ±1 ns)
 *   busy_wait_us(n)    → spin for exactly n microseconds using RDTSC
 *
 * Calibration method
 * ──────────────────
 * Wait for a 100 Hz PIT edge (rising TIMER_TICKS), then count RDTSC cycles
 * for exactly 10 consecutive ticks (100 ms).  Gives TSC MHz with < 0.5 %
 * error on QEMU, VMware, and bare metal (invariant TSCs assumed).
 */

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

/// TSC cycles per microsecond  (set by calibrate()).
static TSC_MHZ: AtomicU64 = AtomicU64::new(0);
/// TSC value at the moment calibrate() finished.
static TSC_BASE: AtomicU64 = AtomicU64::new(0);

// ─────────────────────────────────────────────────────────────
// Low-level RDTSC
// ─────────────────────────────────────────────────────────────
#[inline(always)]
pub fn read() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)); }
    ((hi as u64) << 32) | lo as u64
}

/// RDTSCP — serialising read (waits for in-flight instructions).
#[inline(always)]
pub fn read_serialised() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe { asm!("rdtscp", out("eax") lo, out("edx") hi, out("ecx") _, options(nomem, nostack)); }
    ((hi as u64) << 32) | lo as u64
}

// ─────────────────────────────────────────────────────────────
// Calibration (call once, from arch init, after PIT is live)
// ─────────────────────────────────────────────────────────────
/// TSC frequency reported by the CPU: leaf 0x15 (TSC/crystal ratio × crystal Hz), else
/// leaf 0x16 (base frequency in MHz). None when the CPU reports neither.
fn cpuid_tsc_mhz() -> Option<u64> {
    use core::arch::x86_64::__cpuid;
    let max = unsafe { __cpuid(0) }.eax;
    if max >= 0x15 {
        let l = unsafe { __cpuid(0x15) };
        if l.eax != 0 && l.ebx != 0 && l.ecx != 0 {
            return Some(l.ecx as u64 * l.ebx as u64 / l.eax as u64 / 1_000_000);
        }
    }
    if max >= 0x16 {
        let base = unsafe { __cpuid(0x16) }.eax & 0xFFFF;
        if base != 0 { return Some(base as u64); }
    }
    None
}

/// Calibrate TSC against the 100 Hz PIT timer.
/// Blocks for ~100 ms (10 PIT ticks) — call early in boot before any UI.
pub fn calibrate() {
    use crate::arch::x86_64::idt::timer_ticks;

    // Every wait is bounded by TSC cycles: on some machines PIT interrupts never arrive
    // (8254 gated off, legacy routing disabled), and an unbounded wait hung the boot.
    // 2^33 cycles is ~3 s at 3 GHz and ~9 s at 1 GHz: far longer than 100 ms of ticks.
    const LIMIT: u64 = 1 << 33;
    let begin = read();
    let expired = || read().wrapping_sub(begin) > LIMIT;

    // Wait for a clean tick edge so we start at a boundary
    let t0 = timer_ticks();
    let mut start_tick = t0;
    while start_tick == t0 && !expired() {
        unsafe { asm!("pause"); }
        start_tick = timer_ticks();
    }

    let tsc0 = read();

    // Wait for 10 more ticks  (= 100 ms at 100 Hz)
    while start_tick != t0 && timer_ticks().wrapping_sub(start_tick) < 10 && !expired() {
        unsafe { asm!("pause"); }
    }

    let tsc1 = read();
    let mhz = if start_tick != t0 && !expired() {
        // 10 ticks = 100 ms = 100_000 µs  → MHz = cycles / 100_000
        tsc1.wrapping_sub(tsc0) / 100_000
    } else {
        crate::arch::x86_64::idt::PIT_ALIVE.store(false, Ordering::Relaxed);
        crate::arch::x86_64::serial::write_str("[TSC] No PIT ticks: frequency from CPUID; ticks will come from the APIC timer\r\n");
        cpuid_tsc_mhz().unwrap_or(2000)
    };
    let mhz = if mhz == 0 { 1 } else { mhz };  // safety: never divide-by-zero

    TSC_MHZ.store(mhz, Ordering::Relaxed);
    TSC_BASE.store(tsc1, Ordering::Relaxed);

    crate::arch::x86_64::serial::write_str("[TSC] Calibrated: ");
    {
        let mut n = mhz;
        let mut buf = [0u8; 10]; let mut i = 0;
        while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
        if i == 0 { buf[i] = b'0'; i = 1; }
        for j in (0..i).rev() { crate::arch::x86_64::serial::write_byte(buf[j]); }
    }
    crate::arch::x86_64::serial::write_str(" MHz\r\n");
}

// ─────────────────────────────────────────────────────────────
// Public time accessors
// ─────────────────────────────────────────────────────────────

/// Microseconds elapsed since TSC calibration.
#[inline]
pub fn tsc_us() -> u64 {
    let mhz = TSC_MHZ.load(Ordering::Relaxed);
    if mhz == 0 {
        // Not yet calibrated — fall back to 10 ms PIT ticks converted to µs
        return crate::arch::x86_64::idt::timer_ticks() * 10_000;
    }
    let base = TSC_BASE.load(Ordering::Relaxed);
    read().wrapping_sub(base) / mhz
}

/// Nanoseconds elapsed since TSC calibration.
#[inline]
pub fn tsc_ns() -> u64 {
    let mhz = TSC_MHZ.load(Ordering::Relaxed);
    if mhz == 0 {
        return crate::arch::x86_64::idt::timer_ticks() * 10_000_000;
    }
    let base = TSC_BASE.load(Ordering::Relaxed);
    // cycles * 1000 / MHz = nanoseconds  (avoids floating point)
    read().wrapping_sub(base).wrapping_mul(1000) / mhz
}

/// Absolute TSC timestamp in µs — use for interval measurement.
/// `start = tsc_stamp_us();  …work…  elapsed = tsc_stamp_us() - start;`
#[inline]
pub fn tsc_stamp_us() -> u64 {
    let mhz = TSC_MHZ.load(Ordering::Relaxed);
    if mhz == 0 { return crate::arch::x86_64::idt::timer_ticks() * 10_000; }
    // Absolute TSC / MHz gives µs from any epoch; fine for interval arithmetic.
    read() / mhz
}

// ─────────────────────────────────────────────────────────────
// Busy-wait
// ─────────────────────────────────────────────────────────────

/// Spin for exactly `us` microseconds using RDTSC.
/// Does NOT rely on PIT or interrupts — safe inside ISRs.
pub fn busy_wait_us(us: u64) {
    let mhz = TSC_MHZ.load(Ordering::Relaxed);
    if mhz == 0 {
        // Pre-calibration: rough spin based on ~1 GHz guess
        for _ in 0..us.saturating_mul(1000) {
            unsafe { asm!("pause", options(nomem, nostack)); }
        }
        return;
    }
    let start  = read();
    let target = start.wrapping_add(us.wrapping_mul(mhz));
    loop {
        let now = read();
        if now.wrapping_sub(start) >= target.wrapping_sub(start) { break; }
        unsafe { asm!("pause", options(nomem, nostack)); }
    }
}

/// Returns calibrated TSC MHz (0 if not yet calibrated).
pub fn mhz() -> u64 { TSC_MHZ.load(Ordering::Relaxed) }
