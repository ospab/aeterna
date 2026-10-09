/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

seed — init / service overview for ospab.os (AETERNA)

Honest current state: there are no user-space services yet.  Every
"service" (VFS, scheduler, console, network, storage, audio, the shell) is
a subsystem compiled into the kernel and started by the boot sequence in
src/main.rs.  seed therefore does not spawn anything; `seed status`
reports whether each subsystem actually came up, by asking the subsystem
itself.  Starting/stopping individual services will become possible when
drivers and servers move to ring 3 (see ROADMAP.md).

Earlier versions registered placeholder tasks (entry = 0) in the scheduler
so that `ps` showed "services"; those never ran any code and were removed.
*/

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::userspace::plum::io;

static mut BOOT_TICKS: u64 = 0;
static mut INIT_DONE: bool = false;

/// Called once during boot (src/main.rs). Records the boot time; nothing
/// is spawned.
pub fn init() {
    unsafe {
        if INIT_DONE { return; }
        INIT_DONE = true;
        BOOT_TICKS = crate::arch::x86_64::idt::timer_ticks();
    }
    crate::arch::x86_64::serial::write_str("[seed] subsystem overview ready (no user-space services yet)\r\n");
}

struct Sub {
    name: &'static str,
    up: bool,
    detail: String,
}

fn subsystems() -> Vec<Sub> {
    let mut v = Vec::new();
    v.push(Sub { name: "scheduler", up: crate::core::scheduler::is_initialized(), detail: String::from("preemptive task scheduler") });
    v.push(Sub { name: "vfs", up: crate::fs::is_initialized(), detail: alloc::format!("CowFs (RamFS overlay) at /, {} nodes in the writable layer", crate::fs::node_count()) });
    v.push(Sub { name: "console", up: crate::arch::x86_64::framebuffer::is_initialized(), detail: alloc::format!("framebuffer terminal {}x{}", crate::arch::x86_64::framebuffer::screen_cols(), crate::arch::x86_64::framebuffer::screen_rows()) });
    let disks = crate::drivers::disk_count();
    v.push(Sub { name: "storage", up: disks > 0, detail: alloc::format!("{} disk(s) detected", disks) });
    let net_up = crate::net::is_up();
    v.push(Sub { name: "network", up: net_up, detail: if net_up { alloc::format!("NIC: {}", crate::net::nic_name()) } else { String::from("no supported NIC") } });
    let audio = crate::drivers::audio::is_ready();
    v.push(Sub { name: "audio", up: audio, detail: String::from(if audio { "audio driver ready" } else { "no audio device initialized" }) });
    v.push(Sub { name: "plum", up: true, detail: String::from("shell interpreter (runs inside the console)") });
    v
}

fn usage() {
    io::out("seed - subsystem overview (init)\n\n");
    io::out("  seed status      show which kernel subsystems are up\n");
    io::out("  seed log         show the kernel event log\n");
    io::out("  seed help        this help\n\n");
    io::out("All services are currently compiled into the kernel; they cannot be\n");
    io::out("started, stopped or restarted individually yet.\n");
}

/// `seed <subcommand>`
pub fn run(args: &str) {
    let args = args.trim();
    let (cmd, rest) = match args.find(' ') {
        Some(p) => (&args[..p], args[p + 1..].trim()),
        None => (args, ""),
    };
    match cmd {
        "" | "status" => status(),
        "log" => log(),
        "help" | "--help" | "-h" => usage(),
        "start" | "stop" | "restart" | "enable" | "disable" => {
            io::err("seed: ");
            io::err(cmd);
            io::err(" ");
            io::err(rest);
            io::err(": not supported - all services are kernel subsystems started at boot;\n");
            io::err("      there are no separately running service processes yet\n");
        }
        _ => {
            io::err("seed: unknown command '");
            io::err(args);
            io::err("' (try: seed help)\n");
        }
    }
}

fn status() {
    io::out_c("SUBSYSTEM   STATE  DETAIL\n", io::FG_WARN);
    let subs = subsystems();
    let mut up = 0;
    for s in &subs {
        let mut name = String::from(s.name);
        while name.len() < 12 { name.push(' '); }
        io::out_c(&name, io::FG_OK);
        if s.up {
            up += 1;
            io::out_c("up     ", io::FG_OK);
        } else {
            io::out_c("down   ", io::FG_ERR);
        }
        io::out(&s.detail);
        io::out("\n");
    }
    let secs = (crate::arch::x86_64::idt::timer_ticks() - unsafe { BOOT_TICKS }) / 100;
    io::out_c(&alloc::format!("\n{} of {} subsystems up; uptime since seed init {}s\n", up, subs.len(), secs), io::FG_DIM);
    io::out_c("(all in-kernel; no user-space services exist yet)\n", io::FG_DIM);
}

fn log() {
    let mut buf = [crate::klog::Event::empty_pub(); 32];
    let n = crate::klog::last_events(&mut buf, 32);
    if n == 0 {
        io::out_c("(no log entries)\n", io::FG_DIM);
        return;
    }
    for ev in buf.iter().take(n) {
        io::out("[");
        io::out_c(ev.source.label(), io::FG_DIM);
        io::out("] ");
        io::out(ev.message());
        io::out("\n");
    }
}
