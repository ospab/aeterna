/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Central version constants for ospab.os / AETERNA kernel.
The version number comes from Cargo.toml, so there is one place to bump it.
*/

/// "1.1.0" (from Cargo.toml)
pub const VERSION_STR: &str = env!("CARGO_PKG_VERSION");

/// "ospab.os v1.1.0"
pub const OS_VERSION: &str = concat!("ospab.os v", env!("CARGO_PKG_VERSION"));

/// "AETERNA 1.1.0"
pub const KERNEL_VERSION: &str = concat!("AETERNA ", env!("CARGO_PKG_VERSION"));

/// uname -a style string: kernel name, hostname placeholder, release, machine.
pub const UNAME_FULL: &str = concat!("AETERNA ospab ", env!("CARGO_PKG_VERSION"), " x86_64");

/// Date the version number was last set by hand (not the build time;
/// the build does not stamp a date).
pub const BUILD_DATE: &str = "2026-03-07";

/// Architecture
pub const ARCH: &str = "x86_64";

/// License of the kernel and everything in this repository.
pub const LICENSE: &str = "AGPL-3.0-only";
