// SPDX-License-Identifier: AGPL-3.0-only
//! hello — the first program built for ospab.os. Exercises the ELF loader
//! (text/rodata/data/bss), arguments, the heap and printing.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use liboos::println;

liboos::entry!(main);

/// Initialised data (.data) and zeroed data (.bss) must both come out right.
static mut COUNTER: u32 = 41;
static mut ZEROED: [u8; 8192] = [0; 8192];

fn main(args: liboos::Args) -> i32 {
    println!("hello from ring 3: pid {}, {} argument(s)", liboos::getpid(), args.len());
    for (i, a) in args.iter().enumerate() {
        println!("  argv[{}] = {}", i, a);
    }

    // SAFETY: single-threaded program.
    let (data_ok, bss_ok) = unsafe {
        COUNTER += 1;
        let zeroed = &*core::ptr::addr_of!(ZEROED);
        (COUNTER == 42, zeroed.iter().all(|&b| b == 0))
    };

    let squares: Vec<u64> = (1..=100u64).map(|x| x * x).collect();
    let sum: u64 = squares.iter().sum();
    let heap_ok = sum == 338_350;

    println!("data {} / bss {} / heap {}",
        if data_ok { "ok" } else { "BAD" },
        if bss_ok { "ok" } else { "BAD" },
        if heap_ok { "ok" } else { "BAD" });

    if data_ok && bss_ok && heap_ok { 0 } else { 1 }
}
