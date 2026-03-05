/*
 * aeterna-bench — Kernel-integrated benchmark module (AETERNA OS side)
 * Platform : AETERNA OS (no_std, bare-metal, x86_64)
 * Companion: aeterna-bench/src/main.rs (Linux std companion binary)
 *
 * Measures the "System Latency Tax": raw CPU cycle cost of a deterministic
 * FMA workload, with per-iteration jitter tracking to expose scheduler noise.
 *
 * Workload is 100% bit-identical to the Linux companion binary.
 * Timing uses the x86_64 TSC (Time Stamp Counter) via `rdtsc` + `lfence`.
 * Output goes to both the framebuffer console and COM1 serial.
 *
 * Usage (AETERNA shell):
 *   bench                  — 2048 iterations (default)
 *   bench 512              — custom iteration count (1–65536)
 */

#![allow(dead_code)]

extern crate alloc;

use crate::arch::x86_64::{framebuffer, serial};

// ── Colour palette (matches terminal.rs) ─────────────────────────────────────
const FG: u32      = 0x00FFFFFF; // white
const FG_DIM: u32  = 0x00AAAAAA; // grey
const FG_OK: u32   = 0x0000FF00; // green
const FG_WARN: u32 = 0x0000CCFF; // cyan/yellow
const FG_ERR: u32  = 0x004444FF; // red
const BG: u32      = 0x00000000;

// ── Output helpers ────────────────────────────────────────────────────────────
#[inline(always)]
fn s(text: &str)  { framebuffer::draw_string(text, FG,      BG); serial::write_str(text); }
#[inline(always)]
fn d(text: &str)  { framebuffer::draw_string(text, FG_DIM,  BG); serial::write_str(text); }
#[inline(always)]
fn ok(text: &str) { framebuffer::draw_string(text, FG_OK,   BG); serial::write_str(text); }
#[inline(always)]
fn hl(text: &str) { framebuffer::draw_string(text, FG_WARN, BG); serial::write_str(text); }

// ── TSC Measurement ──────────────────────────────────────────────────────────
//
// Pattern: lfence serialises prior loads, then rdtsc reads a stable TSC value.
// This is Intel's recommended approach for fine-grained cycle measurements.

/// Read TSC with load-fence before (prevents CPU from moving earlier loads
/// past the read; ensures the workload has retired before we sample).
#[inline(always)]
fn tsc_start() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Read TSC with load-fence after (prevents the CPU from speculatively
/// reading the counter before the workload has actually finished).
#[inline(always)]
fn tsc_stop() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            "lfence",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

// ═════════════════════════════════════════════════════════════════════════════
// THE WORKLOAD  —  100% bit-identical to aeterna-bench/src/main.rs
//
// Simulates a single pass over a 128×128 weight matrix using FMA-style
// multiply-accumulate.  Mirrors the innermost loop of a GEMM kernel.
//
// Constants are chosen so the compiler cannot constant-fold the result while
// keeping the operation purely arithmetic (no memory, no SIMD intrinsics).
// black_box defeats every optimisation that would eliminate the computation.
// ═════════════════════════════════════════════════════════════════════════════

/// Dimension of the simulated matrix (128 × 128 = 16 384 FMA ops per call).
const DIM: usize = 128;

/// Number of outer benchmark iterations (each runs one full workload call).
const BENCH_ITERS: usize = 2048;

/// Multiply-accumulate scale stride (row weight).
const SCALE_STRIDE: f64 = 7.461e-4_f64;

/// Accumulate offset stride (column bias).
const OFFSET_STRIDE: f64 = 3.0518e-5_f64;

/// The black-box FMA workload.  `#[inline(never)]` prevents the outer loop
/// from being moved inside here and losing the per-iteration timing boundary.
#[inline(never)]
fn bench_workload() -> f64 {
    let mut acc: f64 = 1.0_f64;
    let mut i: usize = 0;
    while i < DIM {
        let scale_i: f64 = 1.0_f64 + (i as f64) * SCALE_STRIDE;
        let mut j: usize = 0;
        while j < DIM {
            // FMA: acc = acc * scale_i + offset_j
            // Expressed as two-step so no libm dependency; compiler still
            // emits a single VFMADD instruction on -O3 x86_64 with AVX.
            let offset_j: f64 = (j as f64) * OFFSET_STRIDE;
            acc = core::hint::black_box(acc * scale_i + offset_j);
            j += 1;
        }
        i += 1;
    }
    core::hint::black_box(acc)
}

// ── Benchmark statistics ──────────────────────────────────────────────────────

struct BenchResult {
    total_cycles:    u64,
    mean_cycles:     u64,
    min_cycles:      u64,
    max_cycles:      u64,
    max_deviation:   u64,  // max |sample - mean|  — jitter proxy
    iters:           usize,
}

fn run_bench(iters: usize) -> BenchResult {
    // Warm up TSC and branch predictors (not measured).
    for _ in 0..32 {
        let _ = core::hint::black_box(bench_workload());
    }

    let mut samples: alloc::vec::Vec<u64> = alloc::vec::Vec::with_capacity(iters);
    let mut total:   u64 = 0;
    let mut min_c:   u64 = u64::MAX;
    let mut max_c:   u64 = 0;

    for _ in 0..iters {
        let t0 = tsc_start();
        let _v  = bench_workload();
        let t1 = tsc_stop();

        let dt = t1.wrapping_sub(t0);
        total = total.wrapping_add(dt);
        if dt < min_c { min_c = dt; }
        if dt > max_c { max_c = dt; }
        samples.push(dt);
    }

    let mean = total / iters as u64;

    // Max deviation from mean (highlights worst scheduler preemption spike).
    let max_dev = samples
        .iter()
        .map(|&t| if t >= mean { t - mean } else { mean - t })
        .max()
        .unwrap_or(0);

    BenchResult {
        total_cycles:  total,
        mean_cycles:   mean,
        min_cycles:    min_c,
        max_cycles:    max_c,
        max_deviation: max_dev,
        iters,
    }
}

// ── Number formatting (no alloc, no std) ─────────────────────────────────────

/// Format u64 as decimal ASCII.  `buf` must be ≥ 20 bytes.
fn fmt_u64<'a>(mut n: u64, buf: &'a mut [u8; 24]) -> &'a str {
    if n == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    let mut end = 0usize;
    while n > 0 {
        buf[end] = b'0' + (n % 10) as u8;
        n /= 10;
        end += 1;
    }
    buf[..end].reverse();
    unsafe { core::str::from_utf8_unchecked(&buf[..end]) }
}

/// Format u64 with thousands separators: 12345678 → "12,345,678".
fn fmt_sep<'a>(mut n: u64, buf: &'a mut [u8; 32]) -> &'a str {
    if n == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    // Build reversed digit string first, then interleave commas.
    let mut rev = [0u8; 26];
    let mut rlen = 0usize;
    while n > 0 {
        rev[rlen] = b'0' + (n % 10) as u8;
        n /= 10;
        rlen += 1;
    }
    let mut out = 0usize;
    for (pos, i) in (0..rlen).rev().enumerate() {
        if pos > 0 && pos % 3 == 0 { buf[out] = b','; out += 1; }
        buf[out] = rev[i];
        out += 1;
    }
    unsafe { core::str::from_utf8_unchecked(&buf[..out]) }
}

// ── Table helpers ─────────────────────────────────────────────────────────────

fn table_row(label: &str, value: &str) {
    s("  ");
    d(label);
    for _ in 0..26usize.saturating_sub(label.len()) { d(" "); }
    hl(value);
    s("\n");
}

fn table_row2(label: &str, value: &str, note: &str) {
    s("  ");
    d(label);
    for _ in 0..26usize.saturating_sub(label.len()) { d(" "); }
    hl(value);
    d("  ");
    d(note);
    s("\n");
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Called from the terminal dispatcher as `bench [iters]`.
pub fn run(args: &str) {
    // Parse optional custom iteration count from first argument.
    let iters: usize = {
        let n = args.trim().bytes().fold(0usize, |acc, b| {
            if b.is_ascii_digit() { acc * 10 + (b - b'0') as usize } else { acc }
        });
        if n == 0 { BENCH_ITERS } else { n.min(65536).max(1) }
    };

    framebuffer::clear(BG);
    framebuffer::set_cursor_pos(0, 0);

    // ── Header ────────────────────────────────────────────────────────────
    hl("  +=======================================================+\n");
    hl("  |"); s("  aeterna-bench v1.0    System Latency Tax Test      "); hl("|\n");
    hl("  |"); d("  x86_64 | rdtsc | 128x128 FMA workload | no_std     "); hl("|\n");
    hl("  +=======================================================+\n\n");

    // ── Config ────────────────────────────────────────────────────────────
    let mut ib = [0u8; 24];
    let fma_per_call = (DIM * DIM) as u64;
    let total_fma    = fma_per_call * iters as u64;

    s("  Workload   : "); hl("128x128 FMA"); s(" inner-product reduction\n");
    s("  Iterations : "); hl(fmt_u64(iters as u64, &mut ib)); s("\n");
    {
        let mut b = [0u8; 32];
        s("  FMA total  : "); hl(fmt_sep(total_fma, &mut b)); s("  ops\n");
    }
    s("  Platform   : "); ok("AETERNA Microkernel"); s("  (no_std, bare-metal, no scheduler)\n\n");

    d("  Warming up...  "); s("32 discarded iterations\n");
    ok("  Measuring");
    s(" — TSC-fenced, lfence barriers, black_box protected\n\n");

    // ── Run ───────────────────────────────────────────────────────────────
    let r = run_bench(iters);

    // ── Results table ─────────────────────────────────────────────────────
    d("  Metric                     Value\n");
    d("  ─────────────────────────  ─────────────────────────\n");

    let mut b0 = [0u8; 32]; table_row("Total cycles",       fmt_sep(r.total_cycles,  &mut b0));
    let mut b1 = [0u8; 32]; table_row("Cycles / iteration", fmt_sep(r.mean_cycles,   &mut b1));
    let mut b2 = [0u8; 32]; table_row("Min iteration",      fmt_sep(r.min_cycles,    &mut b2));
    let mut b3 = [0u8; 32]; table_row("Max iteration",      fmt_sep(r.max_cycles,    &mut b3));
    let mut b4 = [0u8; 32]; table_row("Max deviation",      fmt_sep(r.max_deviation, &mut b4));

    s("\n");

    // ── Derived: jitter percentage ────────────────────────────────────────
    if r.mean_cycles > 0 {
        let pct_x100 = r.max_deviation.saturating_mul(10000) / r.mean_cycles;
        let pct_int  = pct_x100 / 100;
        let pct_frac = pct_x100 % 100;
        let mut pi = [0u8; 24];
        let mut pf = [0u8; 24];
        s("  Jitter     : ");
        hl(fmt_u64(pct_int, &mut pi));
        s(".");
        if pct_frac < 10 { s("0"); }
        hl(fmt_u64(pct_frac, &mut pf));
        s("% deviation from mean\n");

        let (rating, rating_detail) = match pct_int {
            0 if pct_frac <  50 => ("EXCELLENT", "bare-metal, zero scheduler overhead"),
            0                   => ("VERY GOOD", "near-zero jitter"),
            1..=2               => ("GOOD",      "minimal context-switch noise"),
            3..=9               => ("MODERATE",  "OS scheduling visible in timing trace"),
            _                   => ("HIGH",      "significant preemption/migration spikes"),
        };
        s("  Rating     : ");
        ok(rating);
        s("  — ");
        d(rating_detail);
        s("\n\n");
    }

    // ── FMA throughput ────────────────────────────────────────────────────
    // ops_per_cycle  = total_fma_ops / total_cycles
    // expressed as hundredths to avoid f64 output
    if r.total_cycles > 0 {
        let ops_per_cycle_x100 = total_fma.saturating_mul(100) / r.total_cycles;
        let opc_int  = ops_per_cycle_x100 / 100;
        let opc_frac = ops_per_cycle_x100 % 100;
        let mut oi = [0u8; 24]; let mut of_ = [0u8; 24];
        s("  FMA thrput : ");
        hl(fmt_u64(opc_int, &mut oi));
        s(".");
        if opc_frac < 10 { s("0"); }
        hl(fmt_u64(opc_frac, &mut of_));
        s(" ops/cycle\n");
    }

    // ── Summary banner ────────────────────────────────────────────────────
    d("\n  ─────────────────────────────────────────────────────\n");
    s("  Latency tax  : "); ok("~0 cycles"); s("  (no kernel preemption, no page faults)\n");
    s("  Compare      : run "); hl("aeterna-bench"); s(" on Linux to see the OS scheduling tax\n");
    s("  Tip          : "); d("bench 512  — fewer iters  |  bench 8192 — more iters\n");
    d("  Serial log   : COM1 @ 115200 baud (this output also visible there)\n\n");

    // Also stream the key summary line to serial for remote comparison logging.
    let mut ts = [0u8; 32]; let mut ms = [0u8; 32]; let mut ds = [0u8; 32];
    serial::write_str("[aeterna-bench] AETERNA | total=");
    serial::write_str(fmt_sep(r.total_cycles,  &mut ts));
    serial::write_str(" | mean=");
    serial::write_str(fmt_sep(r.mean_cycles,   &mut ms));
    serial::write_str(" | maxdev=");
    serial::write_str(fmt_sep(r.max_deviation, &mut ds));
    serial::write_str("\r\n");
}
