/*
Business Source License 1.1
Copyright (c) 2026 ospab

userspace — Kernel-integrated userland modules.

These modules will eventually run in ring-3 userspace once memory
protection and syscall ABI are finalized.  Until then they execute
inside the kernel but access the outside world exclusively through
the VFS syscall layer (crate::fs::*).
*/

pub mod plum;
pub mod axon;
pub mod ivs;

// Microkernel Services (previously monolith)
#[path = "../../net/mod.rs"]
pub mod net;

#[path = "../../drivers/mod.rs"]
pub mod drivers_core;

#[path = "../../vfs/mod.rs"]
pub mod fs;

pub mod drivers;

#[path = "../../userland/grape/src/lib.rs"]
pub mod grape;

#[path = "../../userland/tomato/src/lib.rs"]
pub mod tomato;

#[path = "../../userland/seed/src/lib.rs"]
pub mod seed;

#[path = "../../userland/aai/src/lib.rs"]
pub mod aai;
