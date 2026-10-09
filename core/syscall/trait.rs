/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Syscall trait definitions for AETERNA.
*/

/// Trait for syscall handler implementations
pub trait SyscallHandler {
    /// Handle a syscall with given number and arguments
    fn handle(&self, number: u64, args: &[u64]) -> i64;
}