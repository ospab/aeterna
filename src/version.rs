/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Central version constants for ospab.os / AETERNA kernel.
Major and minor come from Cargo.toml; build.rs adds the patch number, which grows by one
with every numbered ISO (see VERSION_BASE_BUILD there).
*/

/// "1.1.3" (OSPAB_VERSION from build.rs; "1.1-dev" for unnumbered builds)
pub const VERSION_STR: &str = env!("OSPAB_VERSION");

/// "ospab.os v1.1.3"
pub const OS_VERSION: &str = concat!("ospab.os v", env!("OSPAB_VERSION"));

/// "AETERNA 1.1.3"
pub const KERNEL_VERSION: &str = concat!("AETERNA ", env!("OSPAB_VERSION"));

/// Build number: the ISO/image number from build.sh, or "dev" (see build.rs).
pub const BUILD: &str = env!("OSPAB_BUILD");

/// Short git commit the kernel was built from; "+" means uncommitted changes.
pub const COMMIT: &str = env!("OSPAB_COMMIT");

/// UTC date of the build.
pub const BUILD_DATE: &str = env!("OSPAB_BUILD_DATE");

/// `uname -v` style: "#181 a956bbf 2026-10-10"
pub const KERNEL_BUILD: &str = concat!("#", env!("OSPAB_BUILD"), " ", env!("OSPAB_COMMIT"), " ", env!("OSPAB_BUILD_DATE"));

/// uname -a style string: kernel name, hostname placeholder, release, build, machine.
pub const UNAME_FULL: &str = concat!("AETERNA ospab ", env!("OSPAB_VERSION"), " #", env!("OSPAB_BUILD"),
    " ", env!("OSPAB_COMMIT"), " ", env!("OSPAB_BUILD_DATE"), " x86_64");

/// Architecture
pub const ARCH: &str = "x86_64";

/// License of the kernel and everything in this repository.
pub const LICENSE: &str = "AGPL-3.0-only";
