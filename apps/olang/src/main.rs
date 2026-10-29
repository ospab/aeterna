// SPDX-License-Identifier: AGPL-3.0-only
//! ol — the olang interpreter for ospab.os. Ported from the olang project (src/main.rs is
//! rewritten: no tokio, no JIT, no bundling). See docs/en/olang.md.
//!
//!   ol file.ol [args]   run a script
//!   ol -e "code"        evaluate a string
//!   ol                  REPL (reads stdin)
#![no_std]
#![no_main]
#![allow(unused_imports)]

extern crate alloc;

mod ast;
mod evaluator;
mod lexer;
mod parser;
mod sys;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use evaluator::env::Environment;
use evaluator::eval::eval_program_at;
use evaluator::object::Object;
use lexer::scanner::Scanner;
use liboos::{print, println};
use parser::parser::Parser;

liboos::entry!(main);

const USAGE: &str = "usage: ol [file.ol [args...]] | ol -e \"code\" | ol (REPL)";

/// Parse and run `src`. Errors are printed; returns false on a syntax or runtime error.
fn run_source(src: &str, name: &str, env: &mut Environment, repl: bool) -> bool {
    let scanner = Scanner::new(src);
    let mut parser = Parser::new(scanner);
    let program = parser.parse_program();
    if !parser.errors.is_empty() {
        println!("Syntax errors in '{}':", name);
        for err in &parser.errors {
            println!(" - {}", err);
        }
        return false;
    }
    let (result, line) = eval_program_at(&program, env);
    if let Object::Error(msg) = result {
        if line > 0 {
            println!("Runtime Error [Line {}] in '{}': {}", line, name, msg);
        } else {
            println!("Runtime Error: {}", msg);
        }
        return false;
    }
    if repl {
        if let Some(ast::Statement::Expression(_)) = program.statements.last() {
            let shown = match result {
                Object::ReturnValue(v) => *v,
                other => other,
            };
            if shown != Object::Null {
                println!("{}", shown);
            }
        }
    }
    true
}

/// True when brackets/braces opened in `s` (outside strings and comments) are still open.
fn needs_more(s: &str) -> bool {
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if in_str {
            if c == '\\' {
                chars.next();
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '#' => {
                while let Some(&n) = chars.peek() {
                    if n == '\n' {
                        break;
                    }
                    chars.next();
                }
            }
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth -= 1,
            _ => {}
        }
    }
    depth > 0 || in_str
}

fn repl() -> i32 {
    println!("olang REPL (ospab.os). Type exit() or press Ctrl+D to quit.");
    let mut env = Environment::new();
    loop {
        print!(">>> ");
        let mut buf = match sys::read_line() {
            Some(l) => l,
            None => {
                println!();
                return 0;
            }
        };
        while needs_more(&buf) {
            print!("... ");
            match sys::read_line() {
                Some(l) => {
                    buf.push('\n');
                    buf.push_str(&l);
                }
                None => break,
            }
        }
        if buf.trim().is_empty() {
            continue;
        }
        run_source(&buf, "<repl>", &mut env, true);
    }
}

/// Size of the interpreter stack (the default 64 KiB ring-3 stack is far too small for a
/// tree-walking evaluator).
const STACK_SIZE: usize = 2 * 1024 * 1024;

fn main(args: liboos::Args) -> i32 {
    match liboos::mmap(STACK_SIZE) {
        Ok(base) => {
            evaluator::eval::set_stack_floor(base as usize + 128 * 1024);
            let top = (base as usize + STACK_SIZE) & !15;
            let mut a = args;
            // SAFETY: `top` is the end of a fresh private mapping, 16-byte aligned; `tramp`
            // is an ordinary extern "C" function that returns normally.
            unsafe { call_on_stack(top, tramp, &mut a as *mut liboos::Args as usize) }
        }
        Err(_) => {
            // Fall back to the normal stack: allow about 40 KiB of the 64 KiB.
            let here = 0u8;
            evaluator::eval::set_stack_floor((&here as *const u8 as usize).saturating_sub(40 * 1024));
            real_main(args)
        }
    }
}

extern "C" fn tramp(arg: usize) -> i32 {
    // SAFETY: `arg` points to the Args that `main` keeps alive across the call.
    let args = unsafe { *(arg as *const liboos::Args) };
    real_main(args)
}

unsafe fn call_on_stack(top: usize, f: extern "C" fn(usize) -> i32, arg: usize) -> i32 {
    let ret: i32;
    core::arch::asm!(
        "mov r12, rsp",
        "mov rsp, {top}",
        "call {f}",
        "mov rsp, r12",
        top = in(reg) top,
        f = in(reg) f,
        in("rdi") arg,
        out("r12") _,
        lateout("rax") ret,
        clobber_abi("C"),
    );
    ret
}

fn real_main(args: liboos::Args) -> i32 {
    let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    match argv.get(1).map(|s| s.as_str()) {
        None => repl(),
        Some("-h") | Some("--help") => {
            println!("{}", USAGE);
            0
        }
        Some("-V") | Some("--version") => {
            println!("ol 0.1.0 (olang for ospab.os, interpreter only)");
            0
        }
        Some("-e") => {
            let code = match argv.get(2) {
                Some(c) => c,
                None => {
                    println!("ol: -e needs code");
                    return 2;
                }
            };
            evaluator::builtins::set_args(argv[3.min(argv.len())..].to_vec());
            let mut env = Environment::new();
            if run_source(code, "<-e>", &mut env, false) { 0 } else { 1 }
        }
        Some(path) => {
            let src = match sys::read_file(path) {
                Ok(s) => s,
                Err(e) => {
                    println!("ol: cannot read '{}': {}", path, e);
                    return 1;
                }
            };
            evaluator::builtins::set_args(argv[2..].to_vec());
            let mut env = Environment::new();
            if run_source(&src, path, &mut env, false) { 0 } else { 1 }
        }
    }
}
