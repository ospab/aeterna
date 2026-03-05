// aeterna-bench — System Latency Tax benchmark
// Linux x86_64 companion binary (std)
//
// Identical workload to the AETERNA no_std module (src/bench.rs) so that
// cycle counts are directly comparable across environments.
//
// Build:   cd aeterna-bench && cargo build --release
// Run:     ./target/release/aeterna-bench [iters]
//          Default iters = 2048, warmup = 32.

use std::arch::x86_64;

// ─── Workload constants — MUST match src/bench.rs exactly ────────────────────
const DIM: usize           = 128;
const BENCH_ITERS: usize   = 2048;
const WARMUP_ITERS: usize  = 32;
const SCALE_STRIDE: f64    = 7.461e-4_f64;
const OFFSET_STRIDE: f64   = 3.0518e-5_f64;

// FMA operations per bench_workload() call
const FMA_PER_CALL: u64 = (DIM * DIM) as u64;   // 16 384

// Platform label (resolved at compile time)
#[cfg(target_os = "windows")]
const PLATFORM: &str = "Windows x86_64 (std)";
#[cfg(target_os = "linux")]
const PLATFORM: &str = "Linux x86_64 (std)";
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
const PLATFORM: &str = "Host x86_64 (std)";

// ─── TSC timing (serialised with LFENCE) ─────────────────────────────────────

#[inline(always)]
fn tsc_start() -> u64 {
    // LFENCE drains the out-of-order pipeline, then RDTSC.
    unsafe {
        x86_64::_mm_lfence();
        x86_64::_rdtsc()
    }
}

#[inline(always)]
fn tsc_stop() -> u64 {
    // RDTSC first, then LFENCE so later instructions don't retire early.
    unsafe {
        let t = x86_64::_rdtsc();
        x86_64::_mm_lfence();
        t
    }
}

// ─── Benchmark workload — 100 % identical to src/bench.rs ────────────────────

#[inline(never)]
fn bench_workload() -> f64 {
    let mut acc: f64 = 1.0_f64;
    let mut i: usize = 0;
    while i < DIM {
        let scale_i: f64 = 1.0_f64 + (i as f64) * SCALE_STRIDE;
        let mut j: usize = 0;
        while j < DIM {
            let offset_j: f64 = (j as f64) * OFFSET_STRIDE;
            // Manual FMA — matches the AETERNA no_std bench exactly
            acc = std::hint::black_box(acc * scale_i + offset_j);
            j += 1;
        }
        i += 1;
    }
    std::hint::black_box(acc)
}

// ─── Result struct ────────────────────────────────────────────────────────────

struct BenchResult {
    total:        u64,
    mean:         u64,
    min:          u64,
    max:          u64,
    max_deviation: u64,
    iters:        usize,
}

// ─── Bench runner ─────────────────────────────────────────────────────────────

fn run_bench(iters: usize) -> BenchResult {
    // Warm up — not measured
    for _ in 0..WARMUP_ITERS {
        std::hint::black_box(bench_workload());
    }

    let mut samples: Vec<u64> = Vec::with_capacity(iters);

    for _ in 0..iters {
        let t0 = tsc_start();
        std::hint::black_box(bench_workload());
        let t1 = tsc_stop();
        if t1 > t0 {
            samples.push(t1 - t0);
        }
    }

    if samples.is_empty() {
        return BenchResult { total: 0, mean: 0, min: 0, max: 0, max_deviation: 0, iters: 0 };
    }

    let total: u64       = samples.iter().sum();
    let mean:  u64       = total / samples.len() as u64;
    let min:   u64       = *samples.iter().min().unwrap();
    let max:   u64       = *samples.iter().max().unwrap();
    let max_deviation: u64 = max.saturating_sub(min);

    BenchResult { total, mean, min, max, max_deviation, iters: samples.len() }
}

// ─── Formatting helpers ────────────────────────────────────────────────────────

/// Format u64 with thousands separators, e.g. 16384 → "16,384"
fn fmt_sep(n: u64) -> String {
    let s = n.to_string();
    let len = s.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, c) in s.chars().enumerate() {
        // Insert a comma before every group of 3 digits counted from the right.
        let digits_from_right = len - i;
        if i > 0 && digits_from_right % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

// ─── Display ─────────────────────────────────────────────────────────────────

// ANSI colour codes
const C_RESET: &str  = "\x1b[0m";
const C_BOLD:  &str  = "\x1b[1m";
const C_CYAN:  &str  = "\x1b[36m";
const C_GREEN: &str  = "\x1b[32m";
const C_YELLOW:&str  = "\x1b[33m";
const C_DIM:   &str  = "\x1b[2m";

fn header(text: &str) {
    println!("{C_BOLD}{C_CYAN}{text}{C_RESET}");
}

fn row(label: &str, value: &str, unit: &str) {
    println!("  {C_DIM}{label:<22}{C_RESET}{C_BOLD}{value}{C_RESET}  {C_DIM}{unit}{C_RESET}");
}

fn row_hl(label: &str, value: &str, unit: &str) {
    println!("  {C_DIM}{label:<22}{C_RESET}{C_GREEN}{C_BOLD}{value}{C_RESET}  {C_DIM}{unit}{C_RESET}");
}

fn row_warn(label: &str, value: &str, unit: &str) {
    println!("  {C_DIM}{label:<22}{C_RESET}{C_YELLOW}{C_BOLD}{value}{C_RESET}  {C_DIM}{unit}{C_RESET}");
}

fn separator() {
    println!("{C_DIM}  {}{C_RESET}", "─".repeat(50));
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() {
    // Parse optional [iters] argument
    let iters: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 1 && n <= 1_000_000)
        .unwrap_or(BENCH_ITERS);

    println!();
    // Dynamically sized box header — adapts to PLATFORM string width
    let title   = format!("  aeterna-bench  v1.0.0  —  {PLATFORM}  ");
    let bars: String = "═".repeat(title.len());
    let top    = format!("╔{bars}╗");
    let mid    = format!("║{title}║");
    let bottom = format!("╚{bars}╝");
    header(&top);
    header(&mid);
    header(&bottom);
    println!();
    header("  [ Workload Configuration ]");
    row("Platform",       PLATFORM,  "");
    row("Dimensions",     "128 × 128",            "FMA / call");
    row("FMA ops / call", &fmt_sep(FMA_PER_CALL), "ops");
    row("Iterations",     &fmt_sep(iters as u64), "samples");
    row("Warmup",         &fmt_sep(WARMUP_ITERS as u64), "discarded");
    separator();

    println!("  Running benchmark… ({iters} iterations)");
    let r = run_bench(iters);
    println!("  Done.");
    println!();

    // Metrics
    header("  [ Cycle Counts ]");
    row(    "Total cycles",    &fmt_sep(r.total),         "cycles");
    row_hl( "Mean  cycles/iter", &fmt_sep(r.mean),        "cycles");
    row(    "Min   cycles/iter", &fmt_sep(r.min),         "cycles");
    row(    "Max   cycles/iter", &fmt_sep(r.max),         "cycles");
    separator();

    header("  [ Jitter Analysis ]");
    let jitter_pct: u64 = if r.mean > 0 { r.max_deviation * 100 / r.mean } else { 0 };
    let jitter_str = format!("{jitter_pct}%");
    if jitter_pct <= 5 {
        row_hl("Max deviation",   &fmt_sep(r.max_deviation), "cycles");
        row_hl("Jitter",          &jitter_str,               "");
    } else {
        row_warn("Max deviation", &fmt_sep(r.max_deviation), "cycles");
        row_warn("Jitter",        &jitter_str,               "");
    }
    separator();

    header("  [ Throughput ]");
    let total_fma: u64 = FMA_PER_CALL * r.iters as u64;
    row("FMA ops total",   &fmt_sep(total_fma),  "ops");

    let fma_per_cycle: u64 = if r.mean > 0 { FMA_PER_CALL * 1000 / r.mean } else { 0 };
    let fpc_int  = fma_per_cycle / 1000;
    let fpc_frac = fma_per_cycle % 1000;
    let fpc_str  = format!("{fpc_int}.{fpc_frac:03}");
    row_hl("FMA ops / cycle", &fpc_str, "ops/cycle");
    separator();

    // Rating
    let rating = match r.mean {
        0..=600    => ("EXCELLENT",     C_GREEN),
        601..=1200 => ("VERY GOOD",     C_GREEN),
        1201..=2400=> ("GOOD",          C_GREEN),
        2401..=4800=> ("MODERATE",      C_YELLOW),
        _          => ("HIGH LATENCY",  C_YELLOW),
    };
    println!("  {C_BOLD}Rating:  {}{}{C_RESET}", rating.1, rating.0);
    println!();

    // One-liner summary for easy cross-platform comparison
    println!("{C_DIM}[aeterna-bench] {PLATFORM} | total={} | mean={} | maxdev={} | jitter={}%{C_RESET}",
        fmt_sep(r.total), fmt_sep(r.mean), fmt_sep(r.max_deviation), jitter_pct);
    println!();
}
