/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
testmode — preview screens you normally only see when something goes wrong,
and run the built-in self-tests with results on screen.

Nothing here halts, reboots or changes system state: the panic and fault
screens are drawn by the same renderer the real handlers use, in preview
mode. Every screen stays until Enter is pressed; the caller then clears the
screen and shows the prompt again.
*/

use core::arch::asm;
use alloc::format;
use ospab_os::arch::x86_64::{framebuffer, keyboard, panic};

const FG: u32 = 0x00FFFFFF;
const FG_DIM: u32 = 0x00A0A0A0;
const FG_OK: u32 = 0x0055DD55;
const FG_ERR: u32 = 0x00FF5555;
const FG_WARN: u32 = 0x00FFCC44;
const FG_HL: u32 = 0x0055CCFF;
const BG: u32 = 0x00000000;

struct Item {
    name: &'static str,
    desc: &'static str,
    run: fn(),
}

const ITEMS: &[Item] = &[
    Item { name: "panic",     desc: "kernel panic screen",                         run: show_panic },
    Item { name: "exception", desc: "CPU exception in the kernel (#PF register dump)", run: show_exception },
    Item { name: "procfault", desc: "ring-3 process killed for a fault",           run: show_process_fault },
    Item { name: "oom",       desc: "kernel heap allocation failure",              run: show_oom },
    Item { name: "bootfail",  desc: "boot step failure line",                      run: show_boot_fail },
    Item { name: "selftest",  desc: "frame allocator + ring-3 self-tests",         run: run_selftests },
];

fn puts(s: &str) { framebuffer::draw_string(s, FG, BG); }
fn dim(s: &str) { framebuffer::draw_string(s, FG_DIM, BG); }

fn wait_key() -> char {
    loop {
        if let Some(k) = keyboard::try_read_key() {
            return k;
        }
        unsafe { asm!("hlt"); }
    }
}

fn wait_enter() {
    loop {
        if wait_key() == '\n' { return; }
    }
}

/// Entry point for the `testmode` command. Returns after the user pressed
/// Enter on the chosen screen (or left the menu); the caller restores the
/// terminal.
pub fn run(args: &str) {
    let arg = args.trim();
    if !arg.is_empty() {
        let found = ITEMS.iter().enumerate().find(|(i, it)| {
            it.name == arg || format!("{}", i + 1) == arg
        });
        match found {
            Some((_, it)) => (it.run)(),
            None => {
                framebuffer::draw_string("testmode: unknown item '", FG_ERR, BG);
                framebuffer::draw_string(arg, FG_ERR, BG);
                framebuffer::draw_string("'\n", FG_ERR, BG);
                list();
                return;
            }
        }
        restore();
        return;
    }

    framebuffer::clear(BG);
    framebuffer::draw_string("testmode", FG_OK, BG);
    dim("  preview failure screens and run self-tests. Nothing here halts or\n");
    dim("          reboots; each screen returns here after Enter.\n\n");
    list();
    puts("\nChoose 1-");
    puts(&format!("{}", ITEMS.len()));
    puts(", or q to leave: ");
    loop {
        let k = wait_key();
        if k == 'q' || k == 'Q' || k == '\x1B' || k == '\x03' {
            puts("\n");
            restore();
            return;
        }
        if let Some(d) = k.to_digit(10) {
            let d = d as usize;
            if d >= 1 && d <= ITEMS.len() {
                (ITEMS[d - 1].run)();
                restore();
                return;
            }
        }
    }
}

fn list() {
    for (i, it) in ITEMS.iter().enumerate() {
        puts("  ");
        framebuffer::draw_string(&format!("{}", i + 1), FG_HL, BG);
        puts("  ");
        framebuffer::draw_string(it.name, FG_HL, BG);
        for _ in it.name.len()..11 { puts(" "); }
        dim(it.desc);
        puts("\n");
    }
    dim("Usage: testmode [number | name]\n");
}

fn restore() {
    framebuffer::clear(BG);
    framebuffer::set_cursor_pos(0, 0);
}

fn footer() {
    puts("\n");
    framebuffer::draw_string("TEST PREVIEW", FG_WARN, BG);
    dim(" - the system is still running. Press Enter to return.");
    wait_enter();
}

// ─── Items ──────────────────────────────────────────────────────────────────

fn show_panic() {
    panic::render_panic_screen(
        Some(("src/example.rs", 42, 13)),
        &"TEST: called `Option::unwrap()` on a `None` value",
        None,
        true,
    );
    wait_enter();
}

fn show_exception() {
    // Plausible values for a kernel write to an unmapped page.
    let info = panic::ExceptionInfo {
        name: "Page Fault (#PF)",
        vector: 14,
        error_code: 0x2,
        rip: 0xFFFF_FFFF_8001_2345,
        rsp: 0xFFFF_8000_0FF7_FE58,
        cs: 0x08,
        cr2: 0x0000_0000_DEAD_B000,
    };
    panic::render_panic_screen(
        Some(("arch/x86_64/idt.rs", 572, 5)),
        &"CPU Exception",
        Some(&info),
        true,
    );
    wait_enter();
}

fn show_process_fault() {
    framebuffer::clear(BG);
    framebuffer::draw_string("TEST", FG_WARN, BG);
    dim(": what the console shows when a ring-3 process faults.\n\n");
    dim("The kernel kills only that process and keeps running. Real path:\n");
    dim("arch/x86_64/idt.rs exception_dispatch (ring-3 branch). It logs\n");
    dim("\"[CRITICAL] Process N <exception> at 0x... Terminating.\" to serial COM1\n");
    dim("and, once wired, calls panic::report_process_fault() for this line:\n\n");
    panic::report_process_fault(42, "Page Fault (#PF)", 0x0000_0000_0000_0008);
    footer();
}

fn show_oom() {
    // With no custom alloc error handler, a failed heap allocation panics
    // with this message from the alloc crate.
    panic::render_panic_screen(
        None,
        &"memory allocation of 1048576 bytes failed",
        None,
        true,
    );
    wait_enter();
}

fn show_boot_fail() {
    framebuffer::clear(BG);
    framebuffer::draw_string("TEST", FG_WARN, BG);
    dim(": a boot step that fails prints a line like this in the boot log\n");
    dim("(src/main.rs boot_fail), and boot continues without that part:\n\n");
    framebuffer::draw_string("[ ", FG_DIM, BG);
    framebuffer::draw_string("FAIL", FG_ERR, BG);
    framebuffer::draw_string(" ] ", FG_DIM, BG);
    framebuffer::draw_string("Kernel heap allocation failed\n", FG_ERR, BG);
    framebuffer::draw_string("[ ", FG_DIM, BG);
    framebuffer::draw_string(" OK ", FG_OK, BG);
    framebuffer::draw_string(" ] ", FG_DIM, BG);
    puts("Virtual memory manager (4-level page tables)\n");
    footer();
}

fn result(ok: bool, what: &str) {
    if ok {
        framebuffer::draw_string("  PASS  ", FG_OK, BG);
    } else {
        framebuffer::draw_string("  FAIL  ", FG_ERR, BG);
    }
    puts(what);
    puts("\n");
}

fn run_selftests() {
    use ospab_os::arch::x86_64::ring;
    use ospab_os::core::scheduler;

    framebuffer::clear(BG);
    framebuffer::draw_string("Self-tests\n\n", FG_OK, BG);

    let free_before = ospab_os::mm::physical::frames_free();
    let pmm = ospab_os::mm::physical::self_test();
    result(pmm, "physical frame allocator: alloc, zeroing, free, accounting");

    dim("  running ring-3 smoke test...\n");
    match ring::launch_ring3_smoke_test() {
        Some(pid) => {
            scheduler::wait_pid(pid);
            result(true, &format!("ring-3 smoke task pid {} finished (expected exit code {})", pid, pid));
        }
        None => result(false, "ring-3 smoke task could not be started"),
    }

    dim("  running ring-3 stress test (two tasks)...\n");
    match ring::launch_ring3_stress_test() {
        Some((a, b)) => {
            scheduler::wait_pid(a);
            scheduler::wait_pid(b);
            let sw = scheduler::USER_TO_USER_SWITCHES.load(core::sync::atomic::Ordering::Relaxed);
            result(true, &format!(
                "ring-3 stress tasks {} and {} finished (expected exit codes {} and {}, 0xBAD = failure); ring3<->ring3 switches so far: {}",
                a, b, a, b, sw));
        }
        None => result(false, "ring-3 stress tasks could not be started"),
    }

    dim("  running ring-3 user-copy test...\n");
    match ring::launch_ring3_usercopy_test() {
        Some(pid) => {
            scheduler::wait_pid(pid);
            result(true, &format!("ring-3 user-copy task pid {} finished (expected exit code 0x600D)", pid));
        }
        None => result(false, "ring-3 user-copy task could not be started"),
    }

    let free_after = ospab_os::mm::physical::frames_free();
    puts("\n");
    dim(&format!("Free frames before: {}, after: {} (dead tasks are reaped lazily).\n",
        free_before, free_after));
    framebuffer::draw_string("Note: ", FG_WARN, BG);
    dim("ring-3 exit codes are only printed on serial COM1 as \"[SYSCALL] exit(N)\";\n");
    dim("PASS above means the task ran and exited, not that its exit code was checked.\n");
    footer();
}
