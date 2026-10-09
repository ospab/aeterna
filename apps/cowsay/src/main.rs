// SPDX-License-Identifier: AGPL-3.0-only
//! cowsay — a cow says what you tell it. `cowsay hello world`
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use liboos::{print, println};

liboos::entry!(main);

const WIDTH: usize = 40;

/// Greedy word wrap to at most `WIDTH` columns.
fn wrap(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        // Break words longer than a line.
        let mut w = word;
        while w.chars().count() > WIDTH {
            let cut = w.char_indices().nth(WIDTH).map(|(i, _)| i).unwrap_or(w.len());
            if !cur.is_empty() {
                lines.push(core::mem::take(&mut cur));
            }
            lines.push(String::from(&w[..cut]));
            w = &w[cut..];
        }
        if !cur.is_empty() && cur.chars().count() + 1 + w.chars().count() > WIDTH {
            lines.push(core::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(w);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

fn main(args: liboos::Args) -> i32 {
    let mut text = String::new();
    for a in args.iter().skip(1) {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(a);
    }
    if text.is_empty() {
        text.push_str("moo! (usage: cowsay <text>)");
    }
    let lines = wrap(&text);
    let width = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);

    print!(" ");
    for _ in 0..width + 2 {
        print!("_");
    }
    println!();
    let n = lines.len();
    for (i, l) in lines.iter().enumerate() {
        let (open, close) = match (n, i) {
            (1, _) => ('<', '>'),
            (_, 0) => ('/', '\\'),
            (_, k) if k == n - 1 => ('\\', '/'),
            _ => ('|', '|'),
        };
        print!("{} {}", open, l);
        for _ in l.chars().count()..width {
            print!(" ");
        }
        println!(" {}", close);
    }
    print!(" ");
    for _ in 0..width + 2 {
        print!("-");
    }
    println!();
    println!("        \\   ^__^");
    println!("         \\  (oo)\\_______");
    println!("            (__)\\       )\\/\\");
    println!("                ||----w |");
    println!("                ||     ||");
    0
}
