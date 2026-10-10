/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Memory test entry for the UEFI loader: picks the free RAM, runs the shared tester
(boot/common/memtest.rs) over it chunk by chunk, shows progress and a result screen.

UEFI owns all memory that is in use. The tester only touches pages it allocated itself
(AllocateAddress on EfiConventionalMemory above 1 MiB, at most 32 MiB at a time, freed
again right after), so firmware and loader memory is never overwritten. Memory held by
the firmware or the loader at that moment is not tested.
*/
use alloc::string::String;
use alloc::vec::Vec;

use crate::config::{cmdline_get, Config};
use crate::console::{alloc_pages, bs, PAGE};
use crate::efi::*;
use crate::memtest::{Progress, Sink, Tester};
use crate::menu::{Key, Palette, Term};

const CHUNK: u64 = 32 << 20;
const MIB: u64 = 1 << 20;

fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    ((hi as u64) << 32) | lo as u64
}

/// Free RAM above 1 MiB as (start, bytes), page aligned.
fn free_ranges() -> Vec<(u64, u64)> {
    let mut size = 0usize;
    let (mut key, mut dsize, mut ver) = (0usize, 0usize, 0u32);
    unsafe { (bs().get_memory_map)(&mut size, core::ptr::null_mut(), &mut key, &mut dsize, &mut ver) };
    let pages = ((size + 32 * dsize.max(48)) as u64).div_ceil(PAGE) as usize;
    let buf = alloc_pages(pages, LOADER_DATA);
    size = pages * PAGE as usize;
    let s = unsafe { (bs().get_memory_map)(&mut size, buf as *mut MemoryDescriptor, &mut key, &mut dsize, &mut ver) };
    let mut out = Vec::new();
    if !is_error(s) {
        for i in 0..size / dsize {
            let d = unsafe { core::ptr::read_unaligned((buf as usize + i * dsize) as *const MemoryDescriptor) };
            if d.typ != CONVENTIONAL_MEMORY {
                continue;
            }
            let (mut a, b) = (d.physical_start, d.physical_start + d.number_of_pages * PAGE);
            a = a.max(MIB);
            if a < b {
                out.push((a, b - a));
            }
        }
    }
    unsafe { (bs().free_pages)(buf, pages) };
    out
}

struct Screen<'a> {
    t: &'a mut dyn Term,
    pal: Palette,
    tsc_per_ms: u64,
    start: u64,
    last_draw: u64,
}

impl Sink for Screen<'_> {
    fn progress(&mut self, p: &Progress) -> bool {
        let now = rdtsc();
        // Redraw at most 5 times a second; poll Esc each time.
        if now.wrapping_sub(self.last_draw) < self.tsc_per_ms * 200 {
            return true;
        }
        self.last_draw = now;
        let pct = if p.total == 0 { 100 } else { (p.done as u128 * 100 / p.total as u128) as usize };
        let (cols, _) = self.t.size();
        let barw = cols.saturating_sub(12).min(60);
        let fill = barw * pct / 100;
        let bar: String = (0..barw).map(|i| if i < fill { '#' } else { '-' }).collect();
        let pal = self.pal;
        self.t.put(4, 2, &alloc::format!("[{}] {:>3}%", bar, pct), pal.normal);
        self.t.put(6, 2, &alloc::format!("Test:   {:<24}", p.test), pal.normal);
        self.t.put(7, 2, &alloc::format!("Pass:   {} of {}   ", p.pass, p.passes), pal.normal);
        let secs = now.wrapping_sub(self.start) / (self.tsc_per_ms * 1000).max(1);
        self.t.put(8, 2, &alloc::format!("Time:   {}:{:02}   ", secs / 60, secs % 60), pal.normal);
        let a = if p.errors > 0 { pal.error } else { pal.ok };
        self.t.put(9, 2, &alloc::format!("Errors: {}   ", p.errors), a);
        !matches!(self.t.poll_key(), Some(Key::Esc))
    }
}

pub fn run(t: &mut dyn Term, pal: &Palette, _cfg: &Config, cmdline: &str) {
    let passes = cmdline_get(cmdline, "passes").and_then(|v| v.parse::<u32>().ok()).unwrap_or(1).clamp(1, 99);
    let limit = cmdline_get(cmdline, "limit").and_then(|v| v.parse::<u64>().ok()).map(|m| m * MIB);
    let inject = cmdline_get(cmdline, "inject") == Some("1");

    // Chunk list within the limit.
    let mut chunks: Vec<(u64, u64)> = Vec::new();
    let mut total = 0u64;
    'outer: for (start, len) in free_ranges() {
        let mut off = 0;
        while off < len {
            let n = CHUNK.min(len - off) & !(PAGE - 1);
            if n == 0 {
                break;
            }
            let n = match limit {
                Some(l) if total + n > l => l.saturating_sub(total) & !(PAGE - 1),
                _ => n,
            };
            if n == 0 {
                break 'outer;
            }
            chunks.push((start + off, n));
            total += n;
            off += n;
        }
    }

    t.clear(pal.normal);
    t.set_cursor(0, 0, false);
    t.put(1, 2, "ospab memory test", pal.title);
    t.put(2, 2, &alloc::format!("{} MiB free RAM selected, {} pass(es). Esc aborts.", total / MIB, passes), pal.dim);
    if total == 0 {
        crate::menu::message(t, pal, "ospab memory test", &[String::from("No free memory found to test.")]);
        return;
    }

    // TSC calibration against the firmware timer (50 ms).
    let t0 = rdtsc();
    unsafe { (bs().stall)(50_000) };
    let tsc_per_ms = (rdtsc().wrapping_sub(t0) / 50).max(1);

    let start = rdtsc();
    let mut screen = Screen { t: &mut *t, pal: *pal, tsc_per_ms, start, last_draw: 0 };
    let mut tester = Tester::new(&mut screen, total, passes, inject);
    let (mut tested, mut skipped) = (0u64, 0u64);
    'run: for pass in 1..=passes {
        tester.pass = pass;
        for &(addr, len) in &chunks {
            let mut a = addr;
            let s = unsafe { (bs().allocate_pages)(ALLOCATE_ADDRESS, LOADER_DATA, (len / PAGE) as usize, &mut a) };
            if is_error(s) {
                // The firmware took this range meanwhile: not testable, do not count it.
                tester.total = tester.total.saturating_sub(len * crate::memtest::WORK_PER_WORD);
                if pass == 1 {
                    skipped += len;
                }
                continue;
            }
            tester.run_range(addr, len);
            unsafe { (bs().free_pages)(addr, (len / PAGE) as usize) };
            if pass == 1 && !tester.aborted {
                tested += len;
            }
            if tester.aborted {
                break 'run;
            }
        }
    }
    tester.report();
    let aborted = tester.aborted;
    let errors = tester.errors;
    let records: Vec<_> = tester.records[..tester.nrecords].to_vec();
    let secs = rdtsc().wrapping_sub(start) / (tsc_per_ms * 1000);

    let mut lines: Vec<String> = Vec::new();
    lines.push(if aborted {
        alloc::format!("ABORTED after {}:{:02}. Errors so far: {}.", secs / 60, secs % 60, errors)
    } else if errors == 0 {
        alloc::format!("PASSED: no errors found.")
    } else {
        alloc::format!("FAILED: {} error(s).", errors)
    });
    lines.push(alloc::format!(
        "Tested {} MiB x {} pass(es) in {}:{:02}.{}",
        tested / MIB, passes, secs / 60, secs % 60,
        if skipped > 0 { alloc::format!(" {} MiB held by the firmware were skipped.", skipped / MIB) } else { String::new() }
    ));
    lines.push(String::from("Tests: walking ones/zeros, address in address, moving inversions, random pattern."));
    if !records.is_empty() {
        lines.push(String::new());
        lines.push(String::from("Address            Expected           Actual             Test"));
        for r in &records {
            lines.push(alloc::format!("{:#018x} {:#018x} {:#018x} {}", r.addr, r.expected, r.actual, r.test));
        }
        if errors > records.len() as u64 {
            lines.push(alloc::format!("... {} more", errors - records.len() as u64));
        }
    }
    for l in &lines {
        println!("memtest: {}", l);
    }
    crate::menu::message(t, pal, "ospab memory test: result", &lines);
}
