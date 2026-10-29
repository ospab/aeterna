/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Boot-time self-tests for the synchronization layer (run with kernel parameter selftest=sched
or selftest=all):

  sync_basic    spinlock: IRQs off while held, restored after; try_lock; OnceCell.
  sched_stress  Several kernel threads create and reap tasks at the same time while using
                their own file descriptor tables. Before the SCHED lock, concurrent spawns
                picked the same table slot, and a timer interrupt could switch to a control
                block that was only half written (RIP 0).
*/

use crate::core::scheduler::{self, Priority, TaskId};
use crate::core::sync::{self, IrqSpinLock, Mutex, OnceCell};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

const WORKERS: usize = 6;
const ROUNDS: usize = 16;
const STACK: usize = 32 * 1024;

static DONE_WORKERS: AtomicUsize = AtomicUsize::new(0);
static LEAVES: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static FD_CHECKS: AtomicUsize = AtomicUsize::new(0);

/// Pid and stack of every thread the test created; stacks are freed after the pid is reaped.
static THREADS: Mutex<Vec<(TaskId, Vec<u8>)>> = Mutex::new(Vec::new());

fn serial(s: &str) {
    crate::arch::x86_64::serial::write_str(s);
}

/// Lock and OnceCell behavior that does not need other tasks.
pub fn sync_basic() -> bool {
    let mut ok = true;
    static L: IrqSpinLock<u32> = IrqSpinLock::new("TEST", sync::rank::DEV, 7);
    let before = sync::irq_enabled();
    {
        let mut g = L.lock();
        if sync::irq_enabled() { ok = false; }
        *g += 1;
        if L.try_lock().is_some() { ok = false; }
        if !L.is_locked() { ok = false; }
    }
    if sync::irq_enabled() != before { ok = false; }
    if *L.lock() != 8 { ok = false; }
    if L.is_locked() { ok = false; }
    // nested locks in rank order, released out of order
    static A: IrqSpinLock<()> = IrqSpinLock::new("TEST.a", sync::rank::DEV, ());
    static B: IrqSpinLock<()> = IrqSpinLock::new("TEST.b", sync::rank::VMM, ());
    {
        let ga = A.lock();
        let gb = B.lock();
        drop(ga);
        drop(gb);
    }
    if sync::irq_enabled() != before { ok = false; }

    static C: OnceCell<u32> = OnceCell::new();
    if C.get().is_some() || C.set(5).is_err() || C.set(6).is_ok() || C.get() != Some(&5) { ok = false; }

    let m: Mutex<u32> = Mutex::new(1);
    {
        let mut g = m.lock();
        *g += 1;
        if m.try_lock().is_some() { ok = false; }
    }
    if *m.lock() != 2 { ok = false; }
    ok
}

/// Create a kernel thread; retries while the task table is full (slots free up as dead
/// tasks are reaped). The stack is kept until the thread is gone.
fn spawn_thread(name: &str, entry: extern "C" fn() -> !) -> Option<TaskId> {
    let stack = alloc::vec![0u8; STACK];
    let top = (stack.as_ptr() as u64 + STACK as u64) & !0xF;
    for _ in 0..2000 {
        if let Some(pid) = scheduler::spawn_named(name, Priority::Normal, entry as usize as u64, top - 8, 0, &[]) {
            THREADS.lock().push((pid, stack));
            return Some(pid);
        }
        scheduler::sys_yield();
    }
    None
}

fn finish() -> ! {
    scheduler::exit_current(0);
    loop {
        scheduler::sys_yield();
    }
}

extern "C" fn leaf() -> ! {
    LEAVES.fetch_add(1, Ordering::Relaxed);
    finish()
}

extern "C" fn worker() -> ! {
    // File descriptors are per task: every worker's first file is fd 3, whatever the others do.
    let a = crate::fs::sys_open("/etc/hostname", 0);
    let b = crate::fs::sys_open("/etc/os-release", 0);
    let mut buf = [0u8; 6];
    let n = crate::fs::sys_read(a as usize, &mut buf);
    let mut ok = a == 3 && b == 4 && n == 6 && &buf == b"ospab\n";
    ok &= crate::fs::sys_seek(a as usize, 1, 0) == 1;
    ok &= crate::fs::sys_close(a as usize) == 0;
    ok &= crate::fs::sys_close(a as usize) == -1; // already closed
    ok &= crate::fs::sys_close(1) == -1; // std streams stay
    FD_CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }

    for _ in 0..ROUNDS {
        if spawn_thread("stress-leaf", leaf).is_none() {
            ERRORS.fetch_add(1, Ordering::Relaxed);
        }
        scheduler::sys_yield();
    }
    // fd 4 is still open: it must go away with the task.
    DONE_WORKERS.fetch_add(1, Ordering::Relaxed);
    finish()
}

/// Run the stress test. True when every check passed.
pub fn sched_stress() -> bool {
    DONE_WORKERS.store(0, Ordering::Relaxed);
    LEAVES.store(0, Ordering::Relaxed);
    ERRORS.store(0, Ordering::Relaxed);
    FD_CHECKS.store(0, Ordering::Relaxed);

    let frames_before = crate::mm::physical::frames_free();
    let tasks_before = scheduler::task_count();
    let heap_before = crate::mm::heap::stats().0;

    let mut workers: Vec<TaskId> = Vec::new();
    for _ in 0..WORKERS {
        match spawn_thread("stress-worker", worker) {
            Some(p) => workers.push(p),
            None => {
                ERRORS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    serial("[SELFTEST] sched: workers spawned
");
    for &p in &workers {
        if scheduler::wait_pid_timeout(p, 3000).is_none() {
            serial("[SELFTEST] sched: worker timed out
");
            ERRORS.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Let the reaper catch up: every thread must disappear from the table.
    let deadline = crate::arch::x86_64::idt::timer_ticks() + 3000;
    loop {
        let all_gone = THREADS.lock().iter().all(|(pid, _)| scheduler::task_state(*pid).is_none());
        if all_gone {
            break;
        }
        if crate::arch::x86_64::idt::timer_ticks() >= deadline {
            ERRORS.fetch_add(1, Ordering::Relaxed);
            // Kill what is left; leak its stack rather than free memory still in use.
            let left: Vec<(TaskId, Vec<u8>)> = core::mem::take(&mut *THREADS.lock());
            for (pid, st) in left {
                scheduler::exit_pid(pid);
                core::mem::forget(st);
            }
            break;
        }
        scheduler::sys_yield();
    }
    THREADS.lock().clear(); // frees the stacks

    let leaves = LEAVES.load(Ordering::Relaxed);
    let done = DONE_WORKERS.load(Ordering::Relaxed);
    let fd_checks = FD_CHECKS.load(Ordering::Relaxed);
    let errors = ERRORS.load(Ordering::Relaxed);
    let frames_after = crate::mm::physical::frames_free();
    let tasks_after = scheduler::task_count();
    let heap_after = crate::mm::heap::stats().0;
    serial("[SELFTEST] sched: workers done ");
    crate::arch::x86_64::init::serial_dec(done as u64);
    serial("/");
    crate::arch::x86_64::init::serial_dec(WORKERS as u64);
    serial(", leaves ");
    crate::arch::x86_64::init::serial_dec(leaves as u64);
    serial("/");
    crate::arch::x86_64::init::serial_dec((WORKERS * ROUNDS) as u64);
    serial(", fd checks ");
    crate::arch::x86_64::init::serial_dec(fd_checks as u64);
    serial(", errors ");
    crate::arch::x86_64::init::serial_dec(errors as u64);
    serial(", frames leaked ");
    crate::arch::x86_64::init::serial_dec(frames_before.saturating_sub(frames_after));
    serial(", heap delta ");
    crate::arch::x86_64::init::serial_dec(heap_after.abs_diff(heap_before) as u64);
    serial("\r\n");

    errors == 0
        && done == WORKERS
        && leaves == WORKERS * ROUNDS
        && fd_checks == WORKERS
        && tasks_after == tasks_before
        && frames_after >= frames_before
        // Open files and table entries were freed with their tasks (slack for allocator metadata).
        && heap_after.abs_diff(heap_before) < 64 * 1024
}
