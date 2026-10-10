/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
ospab-boot memory tester: the test algorithms.

Platform independent and allocation free. The front-end hands over physical ranges it
owns exclusively and which are directly addressable (UEFI: identity mapped pages it
allocated; BIOS: identity mapped RAM). Each range gets, per pass:

  1. walking ones and walking zeros (8 sweeps each, the bit position shifts by 8 per sweep)
  2. address in address (word = its own address, then the complement)
  3. moving inversions (patterns 0x5555.. and 0x00FF00FF.., up then down)
  4. random pattern (xorshift64, then the complement)

All accesses are 64-bit and volatile. Errors are counted; the first MAX_RECORDS are kept.
*/
use core::ptr::{read_volatile, write_volatile};

pub const MAX_RECORDS: usize = 16;
/// Work units (words read or written) per word of memory and pass, see `WORK_PER_WORD`.
pub const WORK_PER_WORD: u64 = 46;

#[derive(Clone, Copy)]
pub struct ErrorRec {
    pub addr: u64,
    pub expected: u64,
    pub actual: u64,
    pub test: &'static str,
}

pub struct Progress {
    pub test: &'static str,
    pub pass: u32,
    pub passes: u32,
    /// Work done and total work, in bytes visited.
    pub done: u64,
    pub total: u64,
    pub errors: u64,
}

pub trait Sink {
    /// Called about once per MiB of work. Return false to abort.
    fn progress(&mut self, p: &Progress) -> bool;
}

pub struct Tester<'a> {
    sink: &'a mut dyn Sink,
    pub errors: u64,
    pub records: [ErrorRec; MAX_RECORDS],
    pub nrecords: usize,
    pub done: u64,
    pub total: u64,
    pub pass: u32,
    pub passes: u32,
    pub aborted: bool,
    test: &'static str,
    since_report: u64,
    /// Simulate one bad bit after the first walking-ones write (self-check of the report).
    pub inject: bool,
    seed: u64,
}

const REPORT_EVERY: u64 = 1 << 20; // bytes of work

impl<'a> Tester<'a> {
    pub fn new(sink: &'a mut dyn Sink, total_bytes: u64, passes: u32, inject: bool) -> Self {
        Tester {
            sink,
            errors: 0,
            records: [ErrorRec { addr: 0, expected: 0, actual: 0, test: "" }; MAX_RECORDS],
            nrecords: 0,
            done: 0,
            total: total_bytes * WORK_PER_WORD * passes as u64,
            pass: 1,
            passes,
            aborted: false,
            test: "",
            since_report: 0,
            inject,
            seed: 0x9E37_79B9_7F4A_7C15,
        }
    }

    fn tick(&mut self, bytes: u64) {
        self.done += bytes;
        self.since_report += bytes;
        if self.since_report >= REPORT_EVERY {
            self.since_report = 0;
            self.report();
        }
    }

    pub fn report(&mut self) {
        let p = Progress {
            test: self.test,
            pass: self.pass,
            passes: self.passes,
            done: self.done.min(self.total),
            total: self.total,
            errors: self.errors,
        };
        if !self.sink.progress(&p) {
            self.aborted = true;
        }
    }

    fn fail(&mut self, addr: u64, expected: u64, actual: u64) {
        self.errors += 1;
        if self.nrecords < MAX_RECORDS {
            self.records[self.nrecords] = ErrorRec { addr, expected, actual, test: self.test };
            self.nrecords += 1;
        }
    }

    /// Write `f(index, address)` to every word.
    fn fill(&mut self, base: *mut u64, words: usize, f: impl Fn(usize, u64) -> u64) {
        let mut i = 0;
        while i < words && !self.aborted {
            let end = (i + 131_072).min(words);
            while i < end {
                unsafe { write_volatile(base.add(i), f(i, base.add(i) as u64)) };
                i += 1;
            }
            self.tick(131_072 * 8);
        }
    }

    /// Check every word against `f(index, address)`.
    fn check(&mut self, base: *mut u64, words: usize, f: impl Fn(usize, u64) -> u64) {
        let mut i = 0;
        while i < words && !self.aborted {
            let end = (i + 131_072).min(words);
            while i < end {
                let a = unsafe { base.add(i) };
                let want = f(i, a as u64);
                let got = unsafe { read_volatile(a) };
                if got != want {
                    self.fail(a as u64, want, got);
                }
                i += 1;
            }
            self.tick(131_072 * 8);
        }
    }

    fn walking(&mut self, base: *mut u64, words: usize) {
        for ones in [true, false] {
            self.test = if ones { "walking ones" } else { "walking zeros" };
            for shift in (0..64usize).step_by(8) {
                let pat = move |i: usize, _a: u64| {
                    let v = 1u64 << ((i + shift) % 64);
                    if ones { v } else { !v }
                };
                self.fill(base, words, pat);
                if self.inject && ones && shift == 0 && words > 6 {
                    self.inject = false;
                    unsafe {
                        let p = base.add(5);
                        write_volatile(p, read_volatile(p) ^ (1 << 3));
                    }
                }
                self.check(base, words, pat);
                if self.aborted {
                    return;
                }
            }
        }
    }

    fn address(&mut self, base: *mut u64, words: usize) {
        self.test = "address in address";
        self.fill(base, words, |_, a| a);
        self.check(base, words, |_, a| a);
        self.fill(base, words, |_, a| !a);
        self.check(base, words, |_, a| !a);
    }

    fn moving_inversions(&mut self, base: *mut u64, words: usize) {
        self.test = "moving inversions";
        for p in [0x5555_5555_5555_5555u64, 0x00FF_00FF_00FF_00FFu64] {
            self.fill(base, words, move |_, _| p);
            // Up: expect p, write !p.
            let mut i = 0;
            while i < words && !self.aborted {
                let end = (i + 131_072).min(words);
                while i < end {
                    let a = unsafe { base.add(i) };
                    let got = unsafe { read_volatile(a) };
                    if got != p {
                        self.fail(a as u64, p, got);
                    }
                    unsafe { write_volatile(a, !p) };
                    i += 1;
                }
                self.tick(131_072 * 8);
            }
            // Down: expect !p, write p.
            let mut i = words;
            while i > 0 && !self.aborted {
                let end = i.saturating_sub(131_072);
                while i > end {
                    i -= 1;
                    let a = unsafe { base.add(i) };
                    let got = unsafe { read_volatile(a) };
                    if got != !p {
                        self.fail(a as u64, !p, got);
                    }
                    unsafe { write_volatile(a, p) };
                }
                self.tick(131_072 * 8);
            }
            if self.aborted {
                return;
            }
        }
    }

    fn random(&mut self, base: *mut u64, words: usize) {
        self.test = "random pattern";
        let seed = self.seed ^ (base as u64);
        for invert in [false, true] {
            // The generator state is carried through the closure by a Cell.
            let st = core::cell::Cell::new(seed);
            let next = || {
                let mut x = st.get();
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                st.set(x);
                x
            };
            self.fill(base, words, |_, _| if invert { !next() } else { next() });
            st.set(seed);
            self.check(base, words, |_, _| if invert { !next() } else { next() });
            if self.aborted {
                return;
            }
        }
        self.seed = self.seed.rotate_left(7) ^ 0xA5A5;
    }

    /// Run the whole battery over one range (`base` 8-byte aligned, `bytes` a multiple of 8).
    pub fn run_range(&mut self, base: u64, bytes: u64) {
        let (p, words) = (base as *mut u64, (bytes / 8) as usize);
        if words == 0 || self.aborted {
            return;
        }
        self.walking(p, words);
        if !self.aborted {
            self.address(p, words);
        }
        if !self.aborted {
            self.moving_inversions(p, words);
        }
        if !self.aborted {
            self.random(p, words);
        }
    }
}
