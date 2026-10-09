// SPDX-License-Identifier: AGPL-3.0-only
//! hello-tmt — the smallest useful package: greets, shows its pid, arguments and uptime.
#![no_std]
#![no_main]

use liboos::println;

liboos::entry!(main);

fn main(args: liboos::Args) -> i32 {
    println!("hello from a tomato package! (pid {})", liboos::getpid());
    println!("arguments: {}", args.len().saturating_sub(1));
    for (i, a) in args.iter().enumerate().skip(1) {
        println!("  arg {}: {}", i, a);
    }
    let ticks = liboos::uptime_ticks();
    println!("uptime: {}.{:02} s", ticks / 100, ticks % 100);
    0
}
