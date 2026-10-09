/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

plum/bash — script entry points.

Scripts are parsed and executed by the same interpreter as interactive
lines (parse.rs + exec.rs), so every construct that works at the prompt
works in a script and vice versa.  The language is a POSIX sh subset, not
full bash (no arrays, no here-documents, no job control).
*/

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Execute shell code inline (`bash -c 'code'`). Returns the exit status.
pub fn execute_code(code: &str) -> i32 {
    let args = [String::from("-c"), String::from(code)];
    super::run_argv(&[String::from("bash"), args[0].clone(), args[1].clone()])
}

/// Execute a script file from the VFS. Returns the exit status.
pub fn execute_script(path: &str) -> i32 {
    let args: Vec<String> = Vec::new();
    super::builtins::run_script(path, &args)
}
