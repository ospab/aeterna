/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Memory test entry of the BIOS front-end: runs the shared tester (boot/common/memtest.rs)
over the free RAM above the loader's own memory, chunk by chunk, with a progress screen
and a result screen.

The BIOS front-end owns the whole machine, so it tests the E820 usable ranges directly.
Not tested: the first 5 MiB (BIOS data, the loader itself) and RAM the loader has
allocated. RAM above 4 GiB is tested too: the page tables are extended for it first.
*/
use alloc::string::String;
use alloc::vec::Vec;

use crate::config::{cmdline_get, Config};
use crate::hw::{rdtsc, tsc_per_ms};
use crate::mem::PAGE;
use crate::memtest::{Progress, Sink, Tester};
use crate::menu::{Key, Palette, Term};
use crate::paging::{PageTables, W};

const CHUNK: u64 = 32 << 20;
const MIB: u64 = 1 << 20;
const GIB4: u64 = 4 << 30;

extern "C" {
    static __pagetables: u8;
}

/// Identity map RAM above 4 GiB (2 MiB pages) so the tester can reach it.
fn map_high_ram() {
    let top = crate::pmem::ram_top();
    if top <= GIB4 {
        return;
    }
    let mut pt = PageTables { pml4: unsafe { &__pagetables as *const u8 as u64 } };
    let end = top.next_multiple_of(2 << 20);
    pt.map_2m_range(GIB4, GIB4, end - GIB4, W);
    unsafe { core::arch::asm!("mov {t}, cr3", "mov cr3, {t}", t = out(reg) _) };
}

struct Screen<'a> {
    t: &'a mut dyn Term,
    pal: Palette,
    per_ms: u64,
    start: u64,
    last_draw: u64,
}

impl Sink for Screen<'_> {
    fn progress(&mut self, p: &Progress) -> bool {
        let now = rdtsc();
        // Redraw at most 5 times a second; poll Esc each time.
        if now.wrapping_sub(self.last_draw) < self.per_ms * 200 {
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
        let secs = now.wrapping_sub(self.start) / (self.per_ms * 1000).max(1);
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

    map_high_ram();
    let mut chunks: Vec<(u64, u64)> = Vec::new();
    let mut total = 0u64;
    'outer: for (start, len) in crate::pmem::test_ranges() {
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

    let per_ms = tsc_per_ms();
    let start = rdtsc();
    let mut screen = Screen { t: &mut *t, pal: *pal, per_ms, start, last_draw: 0 };
    let mut tester = Tester::new(&mut screen, total, passes, inject);
    let mut tested = 0u64;
    'run: for pass in 1..=passes {
        tester.pass = pass;
        for &(addr, len) in &chunks {
            tester.run_range(addr, len);
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
    let secs = rdtsc().wrapping_sub(start) / (per_ms * 1000);

    let mut lines: Vec<String> = Vec::new();
    lines.push(if aborted {
        alloc::format!("ABORTED after {}:{:02}. Errors so far: {}.", secs / 60, secs % 60, errors)
    } else if errors == 0 {
        alloc::format!("PASSED: no errors found.")
    } else {
        alloc::format!("FAILED: {} error(s).", errors)
    });
    lines.push(alloc::format!("Tested {} MiB x {} pass(es) in {}:{:02}.", tested / MIB, passes, secs / 60, secs % 60));
    lines.push(String::from("Not tested: the first 5 MiB (BIOS data and this loader)."));
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
