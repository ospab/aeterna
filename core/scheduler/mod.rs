/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Preemptive Task Scheduler for AETERNA microkernel.
*/

/// Task state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Waiting,
    Dead,
}

/// Task priority levels (Compute-First policy)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Priority {
    Idle = 0,
    Normal = 1,
    System = 2,
    RealTime = 3,
    Compute = 4,
}

/// Capabilities for AETERNA security model.
/// Tasks possess a subset of these, verified by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    FsRead,
    FsWrite,
    Framebuf,
    Serial,
    MemHuge,
    Spawn,
    Net,
    System,
    Device,
    VfsServer,
    IoPort,
    /// Permission to revoke capabilities from child processes.
    Revoke,
}

pub type TaskId = u32;

const MAX_TASKS: usize = 64;
const FRAME_WORDS: usize = 21; // r15..rax, err, rip, cs, rflags, rsp, ss

/// Kernel stack given to every ring-3 task (syscalls and interrupts from ring 3 run on it).
const KSTACK_FRAMES: u64 = 4; // 16 KiB

/// Per-task FPU/SIMD image, saved on every context switch: XSAVE (x87 + SSE + AVX) when the
/// CPU has it, else the 512-byte FXSAVE layout. 64-byte aligned as XSAVE requires.
#[derive(Clone)]
#[repr(C, align(64))]
pub struct FxArea([u8; crate::arch::x86_64::init::XSAVE_AREA_MAX]);

impl core::fmt::Debug for FxArea {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FxArea")
    }
}

impl FxArea {
    /// State after FNINIT with default MXCSR, all vector registers zero. For XSAVE the
    /// header (XSTATE_BV at 512, zero) says every component is in its init state.
    fn initial() -> alloc::boxed::Box<FxArea> {
        let mut a = FxArea([0; crate::arch::x86_64::init::XSAVE_AREA_MAX]);
        a.0[0..2].copy_from_slice(&0x037Fu16.to_le_bytes()); // FCW
        a.0[24..28].copy_from_slice(&0x1F80u32.to_le_bytes()); // MXCSR
        alloc::boxed::Box::new(a)
    }
}

#[derive(Debug, Clone)]
pub struct TaskControlBlock {
    pub pid: TaskId,
    pub priority: Priority,
    pub state: TaskState,
    pub cr3: u64,
    pub cpu_ticks: u64,
    pub memory_bytes: u64,
    pub stack_pointer: u64,
    pub instruction_pointer: u64,
    pub frame: [u64; FRAME_WORDS],
    pub has_frame: bool,
    pub name: [u8; 24],
    pub name_len: u8,
    pub capabilities: alloc::vec::Vec<Capability>,
    pub preemption_disabled: bool,
    pub med_id: Option<u64>,
    /// Saved x87/SSE state.
    pub fx: alloc::boxed::Box<FxArea>,
    /// Physical base of this task's kernel stack (0 = none: a kernel thread on the stack it was given).
    pub kstack_phys: u64,
    /// Top of the kernel stack (HHDM address), loaded into TSS.RSP0 and the syscall stack on switch-in.
    pub kstack_top: u64,
    /// Next free virtual address for mmap in this task's address space (0 = not started).
    pub mmap_next: u64,
    /// Kernel-object handles of this process (see core/object.rs).
    pub handles: crate::core::object::HandleTable,
    /// Reply object (+1) this task is blocked on inside `ipc_call`; 0 = none.
    pub ipc_wait: u32,
    /// Timer tick at which a Waiting task wakes up on its own; 0 = no deadline.
    pub wake_at: u64,
    /// I/O permission bitmap (bit set = denied) for the ports this process enabled through
    /// IoPortRange handles; loaded into the TSS when it is switched in. Empty = no ports.
    pub io_bitmap: alloc::vec::Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct TaskSnapshot {
    pub pid: TaskId,
    pub priority: Priority,
    pub state: TaskState,
    pub cr3: u64,
    pub cpu_ticks: u64,
    pub memory_bytes: u64,
    pub name: [u8; 24],
    pub name_len: u8,
}

static EMPTY_NAME: [u8; 24] = [0; 24];

static mut TASKS: [Option<TaskControlBlock>; MAX_TASKS] = [const { None }; MAX_TASKS];
static mut CURRENT_SLOT: usize = 0;
static mut NEXT_PID: TaskId = 1;
static mut SCHEDULER_INITIALIZED: bool = false;

fn current_cr3() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

fn write_cr3(value: u64) {
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) value, options(nomem, nostack, preserves_flags));
    }
}

fn fill_name(dst: &mut [u8; 24], src: &str) -> u8 {
    let bytes = src.as_bytes();
    let n = bytes.len().min(dst.len());
    for i in 0..n {
        dst[i] = bytes[i];
    }
    n as u8
}

pub fn init() {
    unsafe {
        let mut idle_name = EMPTY_NAME;
        let idle_len = fill_name(&mut idle_name, "idle");

        TASKS[0] = Some(TaskControlBlock {
            pid: 0,
            priority: Priority::Idle,
            state: TaskState::Running,
            cr3: current_cr3(),
            cpu_ticks: 0,
            memory_bytes: 0,
            stack_pointer: 0,
            instruction_pointer: 0,
            frame: [0; FRAME_WORDS],
            has_frame: false,
            name: idle_name,
            name_len: idle_len,
            capabilities: alloc::vec![Capability::Serial, Capability::System],
            preemption_disabled: false,
            med_id: None,
            fx: FxArea::initial(),
            kstack_phys: 0,
            kstack_top: 0,
            mmap_next: 0,
            handles: crate::core::object::HandleTable::new(),
            ipc_wait: 0,
            wake_at: 0,
            io_bitmap: alloc::vec::Vec::new(),
        });
        CURRENT_SLOT = 0;
        NEXT_PID = 1;
        SCHEDULER_INITIALIZED = true;
    }
    crate::arch::x86_64::serial::write_str("[SCHED] TCB scheduler initialized\r\n");
}

pub fn is_initialized() -> bool {
    unsafe { SCHEDULER_INITIALIZED }
}

pub fn create_task(priority: Priority, entry_point: u64, stack_pointer: u64) -> Option<TaskId> {
    spawn_named("task", priority, entry_point, stack_pointer, 0, &[])
}

/// Spawn a new task with an explicit capability manifest.
///
/// **Least-privilege enforcement**: the new task receives only those
/// capabilities that appear in BOTH `manifest` AND the parent task's
/// capability set (intersection). If `manifest` is empty, the task
/// gets only `Capability::Serial` (minimum for debug output).
///
/// This prevents privilege escalation: a parent cannot grant caps
/// it does not itself possess.
pub fn spawn_named(
    name: &str,
    priority: Priority,
    entry_point: u64,
    stack_pointer: u64,
    memory_bytes: u64,
    manifest: &[Capability],
) -> Option<TaskId> {
    use crate::arch::x86_64::gdt_simple;
    unsafe {
        if !SCHEDULER_INITIALIZED {
            return None;
        }

        for i in 1..MAX_TASKS {
            if TASKS[i].is_none() {
                let pid = NEXT_PID;
                NEXT_PID = NEXT_PID.wrapping_add(1);

                let mut task_name = EMPTY_NAME;
                let name_len = fill_name(&mut task_name, name);

                // Initialize task stack frame for iretq
                let mut frame = [0u64; FRAME_WORDS];
                frame[16] = entry_point;                   // RIP
                frame[18] = 0x202;                         // RFLAGS (IF=1)
                frame[19] = stack_pointer;                 // RSP

                // Always a kernel thread: ring-3 tasks are created only by spawn_user_task.
                frame[17] = gdt_simple::KERNEL_CS as u64; // CS
                frame[20] = gdt_simple::KERNEL_DS as u64; // SS

                // Capability manifest enforcement (least-privilege intersection).
                // Base: every task gets Serial for debug output.
                let mut caps = alloc::vec![Capability::Serial];

                if manifest.is_empty() {
                    // Empty manifest = minimal rights (Serial only).
                    // This is the backwards-compatible path for placeholder tasks.
                } else {
                    // Intersection: grant only caps that are in manifest AND
                    // possessed by the current (parent) task.
                    let parent_caps = TASKS[CURRENT_SLOT]
                        .as_ref()
                        .map(|t| t.capabilities.as_slice())
                        .unwrap_or(&[]);

                    for &requested_cap in manifest {
                        // Skip Serial — already granted above.
                        if requested_cap == Capability::Serial { continue; }
                        // Parent must possess the cap (or System which grants all).
                        let parent_has = parent_caps.contains(&requested_cap)
                            || parent_caps.contains(&Capability::System);
                        if parent_has && !caps.contains(&requested_cap) {
                            caps.push(requested_cap);
                        }
                    }
                }

                // Allocate a fresh address space for this task.
                let task_cr3 = if crate::mm::r#virtual::is_initialized() {
                    crate::mm::r#virtual::create_address_space()
                        .unwrap_or_else(|| current_cr3())
                } else {
                    current_cr3()
                };

                TASKS[i] = Some(TaskControlBlock {
                    pid,
                    priority,
                    state: TaskState::Ready,
                    cr3: task_cr3,
                    cpu_ticks: 0,
                    memory_bytes,
                    stack_pointer,
                    instruction_pointer: entry_point,
                    frame,
                    has_frame: entry_point != 0 && stack_pointer != 0,
                    name: task_name,
                    name_len,
                    capabilities: caps,
                    preemption_disabled: false,
                    med_id: None,
                    fx: FxArea::initial(),
                    kstack_phys: 0,
                    kstack_top: 0,
                    mmap_next: 0,
                    handles: crate::core::object::HandleTable::new(),
                    ipc_wait: 0,
                    wake_at: 0,
                    io_bitmap: alloc::vec::Vec::new(),
                });
                return Some(pid);
            }
        }
    }
    None
}

/// Spawn a Ring 3 user task from a *pre-built* address space.
///
/// Unlike [`spawn_named`], this does NOT allocate a fresh address space — the
/// caller has already created `cr3` and mapped the user code + stack pages with
/// `FLAG_USER` into it (see `arch::x86_64::ring`). We only build the iretq frame
/// (with USER_CS/USER_DS so the first scheduler context-switch drops to ring 3)
/// and register the TCB as `Ready`.
///
/// The task starts with the given `capabilities` manifest verbatim (no parent
/// intersection) — callers are kernel code setting up trusted bootstrap tasks.
pub fn spawn_user_task(
    name: &str,
    priority: Priority,
    cr3: u64,
    entry: u64,
    user_stack: u64,
    capabilities: alloc::vec::Vec<Capability>,
) -> Option<TaskId> {
    use crate::arch::x86_64::gdt_simple;
    unsafe {
        if !SCHEDULER_INITIALIZED {
            return None;
        }
        // Own kernel stack: syscalls and interrupts from ring 3 land here, so this task
        // can block inside the kernel without trampling anyone else's stack.
        let kstack_phys = crate::mm::physical::alloc_frames(KSTACK_FRAMES)?;
        let hhdm = crate::arch::x86_64::boot::hhdm_offset().unwrap_or(0);
        let kstack_top = kstack_phys + hhdm + KSTACK_FRAMES * crate::mm::physical::FRAME_SIZE;
        for i in 1..MAX_TASKS {
            if TASKS[i].is_none() {
                let pid = NEXT_PID;
                NEXT_PID = NEXT_PID.wrapping_add(1);

                let mut task_name = EMPTY_NAME;
                let name_len = fill_name(&mut task_name, name);

                // Build the iretq frame the scheduler restores on first switch-in.
                // Frame layout: [0..14]=r15..rax, 15=err, 16=rip, 17=cs,
                // 18=rflags, 19=rsp, 20=ss.
                let mut frame = [0u64; FRAME_WORDS];
                frame[16] = entry;                       // RIP → user entry
                frame[17] = gdt_simple::USER_CS as u64;  // CS  (RPL 3 → ring 3)
                frame[18] = 0x202;                       // RFLAGS (IF=1)
                frame[19] = user_stack;                  // RSP → user stack
                frame[20] = gdt_simple::USER_DS as u64;  // SS  (RPL 3)

                TASKS[i] = Some(TaskControlBlock {
                    pid,
                    priority,
                    state: TaskState::Ready,
                    cr3,
                    cpu_ticks: 0,
                    memory_bytes: 0,
                    stack_pointer: user_stack,
                    instruction_pointer: entry,
                    frame,
                    has_frame: true,
                    name: task_name,
                    name_len,
                    capabilities,
                    preemption_disabled: false,
                    med_id: None,
                    fx: FxArea::initial(),
                    kstack_phys,
                    kstack_top,
                    mmap_next: 0,
                    handles: crate::core::object::HandleTable::new(),
                    ipc_wait: 0,
                    wake_at: 0,
                    io_bitmap: alloc::vec::Vec::new(),
                });
                return Some(pid);
            }
        }
        crate::mm::physical::free_frames(kstack_phys, KSTACK_FRAMES);
    }
    None
}

pub fn has_capability(cap: Capability) -> bool {
    unsafe {
        if let Some(ref tcb) = TASKS[CURRENT_SLOT] {
            return tcb.capabilities.contains(&cap);
        }
    }
    false
}

/// Grant a capability to a task by PID. (Privileged operation)
pub fn grant_capability(pid: TaskId, cap: Capability) -> bool {
    if !has_capability(Capability::System) {
        return false;
    }
    unsafe {
        for i in 0..MAX_TASKS {
            if let Some(ref mut tcb) = TASKS[i] {
                if tcb.pid == pid {
                    if !tcb.capabilities.contains(&cap) {
                        tcb.capabilities.push(cap);
                    }
                    return true;
                }
            }
        }
    }
    false
}

pub fn add_memory_usage(pid: TaskId, bytes: u64) {
    unsafe {
        for i in 0..MAX_TASKS {
            if let Some(ref mut tcb) = TASKS[i] {
                if tcb.pid == pid {
                    tcb.memory_bytes = tcb.memory_bytes.saturating_add(bytes);
                    break;
                }
            }
        }
    }
}

pub fn sub_memory_usage(pid: TaskId, bytes: u64) {
    unsafe {
        for i in 0..MAX_TASKS {
            if let Some(ref mut tcb) = TASKS[i] {
                if tcb.pid == pid {
                    tcb.memory_bytes = tcb.memory_bytes.saturating_sub(bytes);
                    break;
                }
            }
        }
    }
}

/// Exit code recorded for a task killed by the kernel (fault, signal) rather than exit().
pub const EXIT_KILLED: i64 = -1;

/// Exit codes of recently finished tasks, so `wait_pid` can report them after the
/// TCB has been reaped. Small ring; oldest entries are overwritten.
const EXIT_LOG_LEN: usize = 32;
static mut EXIT_LOG: [(TaskId, i64); EXIT_LOG_LEN] = [(0, 0); EXIT_LOG_LEN];
static mut EXIT_LOG_NEXT: usize = 0;

fn record_exit(pid: TaskId, code: i64) {
    unsafe {
        EXIT_LOG[EXIT_LOG_NEXT] = (pid, code);
        EXIT_LOG_NEXT = (EXIT_LOG_NEXT + 1) % EXIT_LOG_LEN;
    }
}

/// Exit code of a finished task, if it is still remembered.
pub fn exit_code(pid: TaskId) -> Option<i64> {
    unsafe {
        // Newest first, so a recycled pid reports its latest run.
        (0..EXIT_LOG_LEN)
            .map(|k| EXIT_LOG[(EXIT_LOG_NEXT + EXIT_LOG_LEN - 1 - k) % EXIT_LOG_LEN])
            .find(|&(p, _)| p == pid && pid != 0)
            .map(|(_, c)| c)
    }
}

pub fn exit_current(code: u64) {
    unsafe {
        if let Some(ref mut tcb) = TASKS[CURRENT_SLOT] {
            if tcb.state != TaskState::Dead {
                record_exit(tcb.pid, code as i64);
            }
            tcb.state = TaskState::Dead;
        }
    }
}

pub fn exit_pid(pid: TaskId) -> bool {
    unsafe {
        for i in 0..MAX_TASKS {
            if let Some(ref mut tcb) = TASKS[i] {
                if tcb.pid == pid {
                    if tcb.state != TaskState::Dead {
                        record_exit(pid, EXIT_KILLED);
                    }
                    tcb.state = TaskState::Dead;
                    return true;
                }
            }
        }
    }
    false
}

/// Block until the task with the given PID exits (its state becomes Dead or it
/// no longer exists in the table). Yields on each iteration so we don't spin.
/// Returns its exit code (`EXIT_KILLED` if the kernel killed it), or None if unknown.
pub fn wait_pid(pid: TaskId) -> Option<i64> {
    loop {
        let alive = unsafe {
            TASKS.iter().flatten().any(|t| t.pid == pid && t.state != TaskState::Dead)
        };
        if !alive {
            return exit_code(pid);
        }
        sys_yield();
    }
}

pub fn current_task_id() -> TaskId {
    unsafe { TASKS[CURRENT_SLOT].as_ref().map(|t| t.pid).unwrap_or(0) }
}

pub fn current_pid() -> TaskId {
    current_task_id()
}

pub fn task_count() -> usize {
    unsafe {
        TASKS
            .iter()
            .filter(|t| t.as_ref().map(|x| x.state != TaskState::Dead).unwrap_or(false))
            .count()
    }
}

pub fn thread_count() -> usize {
    task_count()
}

// Static buffer for task names (since we can't return refs to local data)
static mut NAME_BUFFER: [u8; 64] = [0u8; 64];

pub fn thread_name(slot: usize) -> &'static str {
    unsafe {
        match TASKS.get(slot) {
            Some(Some(task)) => {
                let len = task.name_len as usize;
                if len > 0 && len < 63 {
                    core::ptr::copy_nonoverlapping(
                        task.name.as_ptr(),
                        NAME_BUFFER.as_mut_ptr(),
                        len,
                    );
                    NAME_BUFFER[len] = 0;
                    core::str::from_utf8_unchecked(&NAME_BUFFER[..len])
                } else if len == 0 {
                    "[task]"
                } else {
                    "[toolong]"
                }
            }
            _ => "[unknown]",
        }
    }
}

pub fn signal_thread(slot: usize, signal: u32) {
    unsafe {
        if let Some(Some(task)) = TASKS.get_mut(slot) {
            if task.pid > 1 {
                match signal {
                    18 => { // SIGCONT: resume a stopped task
                        if task.state == TaskState::Waiting {
                            task.state = TaskState::Ready;
                        }
                    }
                    19 => { // SIGSTOP: suspend the task
                        task.state = TaskState::Waiting;
                    }
                    _ => { // SIGKILL (9), SIGTERM (15), and all others: terminate
                        task.state = TaskState::Dead;
                    }
                }
            }
        }
    }
}

pub fn signal_pid(pid: TaskId, signal: u32) -> bool {
    unsafe {
        for i in 0..MAX_TASKS {
            if let Some(ref mut tcb) = TASKS[i] {
                if tcb.pid == pid && pid > 1 {
                    match signal {
                        18 => { // SIGCONT: resume a stopped task
                            if tcb.state == TaskState::Waiting {
                                tcb.state = TaskState::Ready;
                            }
                        }
                        19 => { // SIGSTOP: suspend the task
                            tcb.state = TaskState::Waiting;
                        }
                        _ => { // SIGKILL (9), SIGTERM (15), and all others: terminate
                            tcb.state = TaskState::Dead;
                        }
                    }
                    return true;
                }
            }
        }
    }
    false
}

fn next_ready_slot() -> Option<usize> {
    unsafe {
        let mut best: Option<usize> = None;
        let mut best_prio = Priority::Idle;

        for offset in 1..=MAX_TASKS {
            let idx = (CURRENT_SLOT + offset) % MAX_TASKS;
            if let Some(ref task) = TASKS[idx] {
                // Reap dead tasks (except kernel idle task at idx 0, and not the currently running slot)
                if task.state == TaskState::Dead {
                    if idx != 0 && idx != CURRENT_SLOT {
                        // Freeing may take the heap lock; if the interrupted code holds it,
                        // try again on the next tick instead of deadlocking.
                        if crate::mm::heap::is_locked() {
                            continue;
                        }
                        let (pid, kstack_phys, cr3) = (task.pid, task.kstack_phys, task.cr3);
                        let (handles, ipc_wait) = match TASKS[idx].as_mut() {
                            Some(t) => (core::mem::take(&mut t.handles), t.ipc_wait),
                            None => continue,
                        };
                        // Safe to free the kernel stack: only the current task's stack is in use.
                        if kstack_phys != 0 {
                            crate::mm::physical::free_frames(kstack_phys, KSTACK_FRAMES);
                            // Ring-3 tasks own their address space: page tables and owned
                            // pages go back to the allocator (the CR3 is no longer active).
                            crate::mm::r#virtual::destroy_address_space(cr3);
                        }
                        TASKS[idx] = None;
                        // Close its handles (frees its kernel objects) and wake waiters.
                        crate::core::object::task_reaped(pid, handles, ipc_wait);
                    }
                    continue;
                }

                // Skip "phantom" bookkeeping tasks: ones that have never run
                // (`!has_frame`) and carry no entry point (`instruction_pointer == 0`),
                // such as the seed service placeholders. They have no code to
                // execute, so switching to them is a no-op that would instead
                // resume whatever context was last interrupted — breaking a clean
                // return to the kernel after a real task exits. They remain in the
                // table for `ps`/IPC bookkeeping; we just never schedule them.
                if !task.has_frame && task.instruction_pointer == 0 {
                    continue;
                }

                if task.state == TaskState::Ready || task.state == TaskState::Running {
                    // Strictly greater: among equal priorities the first one after the
                    // current slot wins, which gives round-robin. (With >= the current
                    // task, scanned last, always won ties and nothing else ever ran.)
                    if best.is_none() || task.priority > best_prio {
                        best_prio = task.priority;
                        best = Some(idx);
                    }
                }
            }
        }
        best
    }
}

pub fn schedule_next() -> Option<usize> {
    next_ready_slot()
}

pub fn tick() {
    unsafe {
        if !SCHEDULER_INITIALIZED {
            return;
        }
        if let Some(ref mut current) = TASKS[CURRENT_SLOT] {
            current.cpu_ticks = current.cpu_ticks.saturating_add(1);
        }
    }
}

/// Cooperative yield: sets current task to Ready and sleeps until next interrupt.
/// Call from polling loops (ping wait, keyboard read) to avoid busy-spinning.
pub fn sys_yield() {
    unsafe {
        if SCHEDULER_INITIALIZED {
            if let Some(ref mut task) = TASKS[CURRENT_SLOT] {
                if task.state == TaskState::Running {
                    task.state = TaskState::Ready;
                }
            }
        }
        // Sleep until next interrupt (timer, NIC, keyboard, etc.)
        core::arch::asm!("sti; hlt");
    }
}

// ─── Blocking primitives for kernel objects (core/object.rs) ─────────────────────────

/// Run `f` with interrupts disabled, restoring the previous interrupt state afterwards.
pub fn without_interrupts<R>(f: impl FnOnce() -> R) -> R {
    let flags: u64;
    unsafe { core::arch::asm!("pushfq; pop {}; cli", out(reg) flags) };
    let r = f();
    if flags & 0x200 != 0 {
        unsafe { core::arch::asm!("sti", options(nostack)) };
    }
    r
}

/// Put the current task to sleep until `wake(pid)`, a timer deadline (`deadline`, in
/// `timer_ticks`; 0 = none) or any interrupt that ends HLT. Callers loop on their condition.
/// Interrupts must be off on entry and are off again on return.
pub fn park(deadline: u64) {
    unsafe {
        if let Some(ref mut t) = TASKS[CURRENT_SLOT] {
            t.state = TaskState::Waiting;
            t.wake_at = deadline;
        }
        // The timer interrupt that follows switches to another task; this one resumes here
        // once it is Ready again.
        // No `nomem`: this asm is a compiler barrier. The timer interrupt that ends the HLT
        // reads and writes the task table, so the state stores above must not be delayed
        // past it and the loads below must not be hoisted before it.
        core::arch::asm!("sti; hlt; cli", options(nostack));
        if let Some(ref mut t) = TASKS[CURRENT_SLOT] {
            t.wake_at = 0;
            if t.state == TaskState::Waiting {
                t.state = TaskState::Running;
            }
        }
    }
}

/// Make a Waiting task runnable again.
pub fn wake(pid: TaskId) {
    unsafe {
        for t in TASKS.iter_mut().flatten() {
            if t.pid == pid {
                if t.state == TaskState::Waiting {
                    t.state = TaskState::Ready;
                    t.wake_at = 0;
                }
                return;
            }
        }
    }
}

/// Wake tasks whose park deadline has passed. Called from the timer interrupt.
fn wake_expired() {
    let now = crate::arch::x86_64::idt::timer_ticks();
    unsafe {
        for t in TASKS.iter_mut().flatten() {
            if t.state == TaskState::Waiting && t.wake_at != 0 && now >= t.wake_at {
                t.state = TaskState::Ready;
                t.wake_at = 0;
            }
        }
    }
}

/// Does a task with this pid exist and not yet exited?
pub fn task_alive(pid: TaskId) -> bool {
    unsafe { TASKS.iter().flatten().any(|t| t.pid == pid && t.state != TaskState::Dead) }
}

/// Scheduler state of a task, if it exists.
pub fn task_state(pid: TaskId) -> Option<TaskState> {
    unsafe { TASKS.iter().flatten().find(|t| t.pid == pid).map(|t| t.state) }
}

/// Handle table of the running task.
pub fn current_handles() -> &'static mut crate::core::object::HandleTable {
    unsafe { &mut TASKS[CURRENT_SLOT].as_mut().expect("current task").handles }
}

/// Handle table of task `pid`, if it exists.
pub fn handles_of(pid: TaskId) -> Option<&'static mut crate::core::object::HandleTable> {
    unsafe { TASKS.iter_mut().flatten().find(|t| t.pid == pid).map(|t| &mut t.handles) }
}

/// Record the Reply object (+1) the running task is blocked on (0 = none), so the reaper
/// can release it if the task dies while waiting.
pub fn set_ipc_wait(v: u32) {
    unsafe {
        if let Some(ref mut t) = TASKS[CURRENT_SLOT] {
            t.ipc_wait = v;
        }
    }
}

/// Replace the running task's I/O permission bitmap and load it into the TSS now.
/// Interrupts must be off (syscall path).
pub fn set_current_io_bitmap(bm: alloc::vec::Vec<u8>) {
    unsafe {
        if let Some(ref mut t) = TASKS[CURRENT_SLOT] {
            t.io_bitmap = bm;
            crate::arch::x86_64::gdt_simple::load_io_bitmap(t.pid, &t.io_bitmap, true);
        }
    }
}

/// Like `wait_pid`, but gives up after `ticks` (100 Hz) and kills the task, so a broken
/// test cannot hang the boot. Returns None on timeout.
pub fn wait_pid_timeout(pid: TaskId, ticks: u64) -> Option<i64> {
    let deadline = crate::arch::x86_64::idt::timer_ticks() + ticks;
    loop {
        if !task_alive(pid) {
            return exit_code(pid);
        }
        if crate::arch::x86_64::idt::timer_ticks() >= deadline {
            exit_pid(pid);
            return None;
        }
        sys_yield();
    }
}

/// Preempt the current task. Called from the timer ISRs and from the ring-3 fault path.
///
/// `saved_state` points at the interrupted GPR + iretq frame. `fx_area` points at the
/// XSAVE/FXSAVE image the ISR stub will restore on return, or is null when the stub does not
/// save FPU state (the exception path), in which case the next task's state is loaded here.
pub fn on_timer_irq(saved_state: *mut u8, fx_area: *mut u8) {
    unsafe {
        if !SCHEDULER_INITIALIZED {
            return;
        }

        wake_expired();
        let cur_slot = CURRENT_SLOT;
        if let Some(ref mut cur) = TASKS[cur_slot] {
            cur.cpu_ticks = cur.cpu_ticks.saturating_add(1);
            
            // Jitter Elimination: Compute tasks are not preempted by timer
            // unless they've exceeded their massive quantum (1000 ticks)
            let is_compute = cur.priority == Priority::Compute;
            let quantum_exceeded = (cur.cpu_ticks % 1000) == 0;
            let force_preempt = !is_compute || quantum_exceeded;
            
            if !force_preempt || cur.preemption_disabled {
                // Skip context switch: just return and continue execution
                return;
            }

            cur.stack_pointer = saved_state as u64;
            let src = saved_state as *const u64;
            for i in 0..FRAME_WORDS {
                cur.frame[i] = *src.add(i);
            }
            cur.has_frame = true;
            if !fx_area.is_null() {
                core::ptr::copy_nonoverlapping(fx_area, cur.fx.0.as_mut_ptr(), crate::arch::x86_64::init::xsave_area_size());
            }
            if cur.state == TaskState::Running {
                cur.state = TaskState::Ready;
            }
        }

        let next_slot = match next_ready_slot() {
            Some(n) => n,
            None => {
                if let Some(ref mut cur) = TASKS[cur_slot] {
                    cur.state = TaskState::Running;
                }
                return;
            }
        };

        if next_slot == cur_slot {
            if let Some(ref mut cur) = TASKS[cur_slot] {
                cur.state = TaskState::Running;
            }
            return;
        }

        let from_user = TASKS[cur_slot].as_ref().map_or(false, |t| t.kstack_phys != 0);
        if let Some(ref mut next) = TASKS[next_slot] {
            if from_user && next.kstack_phys != 0 {
                USER_TO_USER_SWITCHES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            next.state = TaskState::Running;
            CURRENT_SLOT = next_slot;

            if next.cr3 != 0 && next.cr3 != current_cr3() {
                // Refresh kernel upper-half entries in the target PML4 so that
                // any dynamic kernel mappings (heap growth, new VFS pages, etc.)
                // added after this task was spawned are visible immediately.
                // Without this, a stale PML4 causes #PF 0x0 (not-present, kernel).
                if crate::mm::r#virtual::is_initialized() {
                    crate::mm::r#virtual::sync_kernel_mappings(next.cr3);
                }
                write_cr3(next.cr3);
            }

            if next.has_frame {
                let dst = saved_state as *mut u64;
                for i in 0..FRAME_WORDS {
                    *dst.add(i) = next.frame[i];
                }
            }

            if next.kstack_top != 0 {
                crate::arch::x86_64::gdt_simple::set_tss_rsp0(next.kstack_top);
                crate::core::syscall::set_kernel_stack(next.kstack_top);
                // Ring-3 task: its own I/O permissions (none for most tasks).
                crate::arch::x86_64::gdt_simple::load_io_bitmap(next.pid, &next.io_bitmap, false);
            }

            if fx_area.is_null() {
                // The exception stub does no restore on the way out: load the state now.
                crate::arch::x86_64::init::restore_fpu_state(next.fx.0.as_ptr());
            } else {
                core::ptr::copy_nonoverlapping(next.fx.0.as_ptr(), fx_area, crate::arch::x86_64::init::xsave_area_size());
            }
        }
    }
}

/// Start of the mmap area in every user address space.
const MMAP_BASE: u64 = 0x0000_1000_0000_0000;
/// mmap area ends here (well below the top of user space, leaving room for stacks).
const MMAP_LIMIT: u64 = 0x0000_7000_0000_0000;

/// The current task's address space, if it is a ring-3 task with its own one.
pub fn current_user_cr3() -> Option<u64> {
    unsafe {
        TASKS[CURRENT_SLOT]
            .as_ref()
            .filter(|t| t.kstack_phys != 0)
            .map(|t| t.cr3)
    }
}

/// Reserve `pages` pages of virtual address space for mmap in the current ring-3 task.
/// Leaves an unmapped guard page after each reservation.
pub fn reserve_user_range(pages: u64) -> Option<u64> {
    unsafe {
        let t = TASKS[CURRENT_SLOT].as_mut().filter(|t| t.kstack_phys != 0)?;
        if t.mmap_next == 0 {
            t.mmap_next = MMAP_BASE;
        }
        let start = t.mmap_next;
        let end = start.checked_add((pages + 1) * crate::mm::physical::FRAME_SIZE)?;
        if end > MMAP_LIMIT {
            return None;
        }
        t.mmap_next = end;
        Some(start)
    }
}

/// Context switches directly between two ring-3 tasks (for diagnostics and tests).
pub static USER_TO_USER_SWITCHES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn set_preemption_disabled(disabled: bool) {
    unsafe {
        if let Some(ref mut task) = TASKS[CURRENT_SLOT] {
            task.preemption_disabled = disabled;
        }
    }
}

pub fn set_is_vfs_server(is_server: bool) {
    if !is_server { return; }
    grant_capability(current_pid(), Capability::VfsServer);
}

pub fn set_med_id(med_id: u64) {
    unsafe {
        if let Some(ref mut task) = TASKS[CURRENT_SLOT] {
            task.med_id = Some(med_id);
        }
    }
}

pub fn get_tasks(out: &mut [TaskSnapshot]) -> usize {
    let mut n = 0usize;
    unsafe {
        for i in 0..MAX_TASKS {
            if n >= out.len() {
                break;
            }
            if let Some(ref task) = TASKS[i] {
                if task.state == TaskState::Dead {
                    continue;
                }
                out[n] = TaskSnapshot {
                    pid: task.pid,
                    priority: task.priority,
                    state: task.state,
                    cr3: task.cr3,
                    cpu_ticks: task.cpu_ticks,
                    memory_bytes: task.memory_bytes,
                    name: task.name,
                    name_len: task.name_len,
                };
                n += 1;
            }
        }
    }
    n
}

pub fn name_from_snapshot(s: &TaskSnapshot) -> &str {
    let len = s.name_len as usize;
    if len == 0 {
        "task"
    } else {
        core::str::from_utf8(&s.name[..len]).unwrap_or("task")
    }
}