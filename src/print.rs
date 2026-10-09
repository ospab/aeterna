/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Simple print macros for kernel debugging
*/

/// Simple println macro that writes to serial
#[macro_export]
macro_rules! println {
    ($($arg:expr) => {
        $crate::arch::x86_64::serial::write_str(concat!($arg, "\r\n"));
    };
}

/// Simple print macro without newline
#[macro_export]
macro_rules! print {
    ($($arg:expr) => {
        $crate::arch::x86_64::serial::write_str($($arg));
    };
}
