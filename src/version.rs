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

/// Build number: the ISO/image number from build.sh, or "dev" (see build.rs).
pub const BUILD: &str = env!("OSPAB_BUILD");

/// Short git commit the kernel was built from; "+" means uncommitted changes.
pub const COMMIT: &str = env!("OSPAB_COMMIT");

/// UTC date of the build.
pub const BUILD_DATE: &str = env!("OSPAB_BUILD_DATE");

/// `uname -v` style: "#181 a956bbf 2026-10-10"
pub const KERNEL_BUILD: &str = concat!("#", env!("OSPAB_BUILD"), " ", env!("OSPAB_COMMIT"), " ", env!("OSPAB_BUILD_DATE"));

/// uname -a style string: kernel name, hostname placeholder, release, build, machine.
pub const UNAME_FULL: &str = concat!("AETERNA ospab ", env!("CARGO_PKG_VERSION"), " #", env!("OSPAB_BUILD"),
    " ", env!("OSPAB_COMMIT"), " ", env!("OSPAB_BUILD_DATE"), " x86_64");

/// Architecture
pub const ARCH: &str = "x86_64";

/// License of the kernel and everything in this repository.
pub const LICENSE: &str = "AGPL-3.0-only";
