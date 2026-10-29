/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Preemptive Task Scheduler for AETERNA microkernel.

Locking: the task table is behind the IRQ-safe spinlock SCHED (lock order and rules:
docs/en/kernel.md). Nothing under SCHED may take OBJ or sleep. The reaper runs without
SCHED: a dead task's control block is removed under the lock, then torn down.
*/
use crate::core::sync::IrqSpinLock;

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
    /// Open files (fd 3 and up); closed when the task is reaped (see core/fd.rs).
    pub fds: crate::core::fd::FdTable,
    /// The address space was created for this task (not the kernel's): free it on reaping.
    pub own_cr3: bool,
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

/// Everything the scheduler owns, behind one lock.
struct SchedState {
    tasks: [Option<TaskControlBlock>; MAX_TASKS],
    current: usize,
    next_pid: TaskId,
    /// Exit codes of recently finished tasks, so `wait_pid` can report them after the
    /// TCB has been reaped. Small ring; oldest entries are overwritten.
    exit_log: [(TaskId, i64); EXIT_LOG_LEN],
    exit_log_next: usize,
}

const EXIT_LOG_LEN: usize = 32;

static SCHED: IrqSpinLock<SchedState> = IrqSpinLock::new("SCHED", crate::core::sync::rank::SCHED, SchedState {
    tasks: [const { None }; MAX_TASKS],
    current: 0,
    next_pid: 1,
    exit_log: [(0, 0); EXIT_LOG_LEN],
    exit_log_next: 0,
});
static SCHEDULER_INITIALIZED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

impl SchedState {
    fn cur(&mut self) -> Option<&mut TaskControlBlock> {
        let c = self.current;
        self.tasks[c].as_mut()
    }

    fn find(&mut self, pid: TaskId) -> Option<&mut TaskControlBlock> {
        self.tasks.iter_mut().flatten().find(|t| t.pid == pid)
    }

    fn record_exit(&mut self, pid: TaskId, code: i64) {
        let n = self.exit_log_next;
        self.exit_log[n] = (pid, code);
        self.exit_log_next = (n + 1) % EXIT_LOG_LEN;
    }

    /// Put `tcb` in a free slot (never slot 0) and give it a pid. On failure hands it back.
    fn insert(&mut self, mut tcb: TaskControlBlock) -> Result<TaskId, TaskControlBlock> {
        for i in 1..MAX_TASKS {
            if self.tasks[i].is_none() {
                let pid = self.next_pid;
                self.next_pid = self.next_pid.wrapping_add(1).max(1);
                tcb.pid = pid;
                self.tasks[i] = Some(tcb);
                return Ok(pid);
            }
        }
        Err(tcb)
    }
}

fn current_cr3() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

fn write_cr3(value: u64) {
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) value, options(nostack, preserves_flags));
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

/// A control block with defaults; callers fill in what differs.
fn new_tcb(name: &str, priority: Priority) -> TaskControlBlock {
    let mut task_name = EMPTY_NAME;
    let name_len = fill_name(&mut task_name, name);
    TaskControlBlock {
        pid: 0,
        priority,
        state: TaskState::Ready,
        cr3: 0,
        cpu_ticks: 0,
        memory_bytes: 0,
        stack_pointer: 0,
        instruction_pointer: 0,
        frame: [0; FRAME_WORDS],
        has_frame: false,
        name: task_name,
        name_len,
        capabilities: alloc::vec::Vec::new(),
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
        fds: crate::core::fd::FdTable::new(),
        own_cr3: false,
    }
}

pub fn init() {
    let mut idle = new_tcb("idle", Priority::Idle);
    idle.state = TaskState::Running;
    idle.cr3 = current_cr3();
    idle.capabilities = alloc::vec![Capability::Serial, Capability::System];
    {
        let mut s = SCHED.lock();
        s.tasks[0] = Some(idle);
        s.current = 0;
        s.next_pid = 1;
    }
    SCHEDULER_INITIALIZED.store(true, core::sync::atomic::Ordering::Release);
    crate::arch::x86_64::serial::write_str("[SCHED] TCB scheduler initialized\r\n");
}

pub fn is_initialized() -> bool {
    SCHEDULER_INITIALIZED.load(core::sync::atomic::Ordering::Acquire)
}

pub fn create_task(priority: Priority, entry_point: u64, stack_pointer: u64) -> Option<TaskId> {
    spawn_named("task", priority, entry_point, stack_pointer, 0, &[])
}

/// Spawn a new kernel thread with an explicit capability manifest.
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
    if !is_initialized() {
        return None;
    }
    // Everything that allocates is prepared before the table lock is taken, and the
    // control block is complete before it becomes visible to the timer interrupt.
    let mut tcb = new_tcb(name, priority);
    tcb.frame[16] = entry_point; // RIP
    tcb.frame[18] = 0x202; // RFLAGS (IF=1)
    tcb.frame[19] = stack_pointer; // RSP
    // Always a kernel thread: ring-3 tasks are created only by spawn_user_task.
    tcb.frame[17] = gdt_simple::KERNEL_CS as u64;
    tcb.frame[20] = gdt_simple::KERNEL_DS as u64;
    tcb.memory_bytes = memory_bytes;
    tcb.stack_pointer = stack_pointer;
    tcb.instruction_pointer = entry_point;
    tcb.has_frame = entry_point != 0 && stack_pointer != 0;
    tcb.capabilities.push(Capability::Serial);

    let own = if crate::mm::r#virtual::is_initialized() {
        crate::mm::r#virtual::create_address_space()
    } else {
        None
    };
    tcb.cr3 = own.unwrap_or_else(current_cr3);
    tcb.own_cr3 = own.is_some();

    let mut s = SCHED.lock();
    // Capability manifest enforcement (least-privilege intersection). An empty manifest
    // means minimal rights (Serial only).
    for &requested in manifest {
        if requested == Capability::Serial || tcb.capabilities.contains(&requested) {
            continue;
        }
        let parent_has = s.cur().map_or(false, |p| {
            p.capabilities.contains(&requested) || p.capabilities.contains(&Capability::System)
        });
        if parent_has {
            tcb.capabilities.push(requested);
        }
    }
    match s.insert(tcb) {
        Ok(pid) => Some(pid),
        Err(tcb) => {
            drop(s);
            if tcb.own_cr3 {
                crate::mm::r#virtual::destroy_address_space(tcb.cr3);
            }
            None
        }
    }
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
    if !is_initialized() {
        return None;
    }
    // Own kernel stack: syscalls and interrupts from ring 3 land here, so this task
    // can block inside the kernel without trampling anyone else's stack.
    let kstack_phys = crate::mm::physical::alloc_frames(KSTACK_FRAMES)?;
    let hhdm = crate::arch::x86_64::boot::hhdm_offset().unwrap_or(0);
    let kstack_top = kstack_phys + hhdm + KSTACK_FRAMES * crate::mm::physical::FRAME_SIZE;

    let mut tcb = new_tcb(name, priority);
    // Frame layout: [0..14]=r15..rax, 15=err, 16=rip, 17=cs, 18=rflags, 19=rsp, 20=ss.
    tcb.frame[16] = entry;
    tcb.frame[17] = gdt_simple::USER_CS as u64;
    tcb.frame[18] = 0x202; // RFLAGS (IF=1)
    tcb.frame[19] = user_stack;
    tcb.frame[20] = gdt_simple::USER_DS as u64;
    tcb.cr3 = cr3;
    tcb.stack_pointer = user_stack;
    tcb.instruction_pointer = entry;
    tcb.has_frame = true;
    tcb.capabilities = capabilities;
    tcb.kstack_phys = kstack_phys;
    tcb.kstack_top = kstack_top;

    let r = SCHED.lock().insert(tcb);
    match r {
        Ok(pid) => Some(pid),
        Err(_) => {
            crate::mm::physical::free_frames(kstack_phys, KSTACK_FRAMES);
            None
        }
    }
}

pub fn has_capability(cap: Capability) -> bool {
    SCHED.lock().cur().map_or(false, |t| t.capabilities.contains(&cap))
}

/// Grant a capability to a task by PID. (Privileged operation)
pub fn grant_capability(pid: TaskId, cap: Capability) -> bool {
    let mut s = SCHED.lock();
    let allowed = s.cur().map_or(false, |t| t.capabilities.contains(&Capability::System));
    if !allowed {
        return false;
    }
    match s.find(pid) {
        Some(t) => {
            if !t.capabilities.contains(&cap) {
                t.capabilities.push(cap);
            }
            true
        }
        None => false,
    }
}

pub fn add_memory_usage(pid: TaskId, bytes: u64) {
    if let Some(t) = SCHED.lock().find(pid) {
        t.memory_bytes = t.memory_bytes.saturating_add(bytes);
    }
}

pub fn sub_memory_usage(pid: TaskId, bytes: u64) {
    if let Some(t) = SCHED.lock().find(pid) {
        t.memory_bytes = t.memory_bytes.saturating_sub(bytes);
    }
}

/// Exit code recorded for a task killed by the kernel (fault, signal) rather than exit().
pub const EXIT_KILLED: i64 = -1;

/// Exit code of a finished task, if it is still remembered.
pub fn exit_code(pid: TaskId) -> Option<i64> {
    let s = SCHED.lock();
    // Newest first, so a recycled pid reports its latest run.
    (0..EXIT_LOG_LEN)
        .map(|k| s.exit_log[(s.exit_log_next + EXIT_LOG_LEN - 1 - k) % EXIT_LOG_LEN])
        .find(|&(p, _)| p == pid && pid != 0)
        .map(|(_, c)| c)
}

pub fn exit_current(code: u64) {
    let mut s = SCHED.lock();
    let c = s.current;
    if let Some(t) = s.tasks[c].as_mut() {
        let (pid, was_dead) = (t.pid, t.state == TaskState::Dead);
        t.state = TaskState::Dead;
        if !was_dead {
            s.record_exit(pid, code as i64);
        }
    }
}

pub fn exit_pid(pid: TaskId) -> bool {
    let mut s = SCHED.lock();
    let was_dead = match s.find(pid) {
        Some(t) => {
            let d = t.state == TaskState::Dead;
            t.state = TaskState::Dead;
            d
        }
        None => return false,
    };
    if !was_dead {
        s.record_exit(pid, EXIT_KILLED);
    }
    true
}

/// Block until the task with the given PID exits (its state becomes Dead or it
/// no longer exists in the table). Yields on each iteration so we don't spin.
/// Returns its exit code (`EXIT_KILLED` if the kernel killed it), or None if unknown.
pub fn wait_pid(pid: TaskId) -> Option<i64> {
    loop {
        if !task_alive(pid) {
            return exit_code(pid);
        }
        sys_yield();
    }
}

pub fn current_task_id() -> TaskId {
    SCHED.lock().cur().map_or(0, |t| t.pid)
}

pub fn current_pid() -> TaskId {
    current_task_id()
}

pub fn task_count() -> usize {
    SCHED.lock().tasks.iter().filter(|t| t.as_ref().map_or(false, |x| x.state != TaskState::Dead)).count()
}

pub fn thread_count() -> usize {
    task_count()
}

/// Name of the task in table slot `slot`.
pub fn thread_name(slot: usize) -> alloc::string::String {
    let s = SCHED.lock();
    match s.tasks.get(slot) {
        Some(Some(t)) if t.name_len > 0 => {
            alloc::string::String::from_utf8_lossy(&t.name[..t.name_len as usize]).into_owned()
        }
        Some(Some(_)) => alloc::string::String::from("[task]"),
        _ => alloc::string::String::from("[unknown]"),
    }
}

fn apply_signal(task: &mut TaskControlBlock, signal: u32) {
    match signal {
        18 => {
            // SIGCONT: resume a stopped task
            if task.state == TaskState::Waiting {
                task.state = TaskState::Ready;
            }
        }
        19 => task.state = TaskState::Waiting, // SIGSTOP: suspend the task
        _ => task.state = TaskState::Dead,     // SIGKILL (9), SIGTERM (15), and all others
    }
}

pub fn signal_thread(slot: usize, signal: u32) {
    let mut s = SCHED.lock();
    if let Some(Some(task)) = s.tasks.get_mut(slot) {
        if task.pid > 1 {
            apply_signal(task, signal);
        }
    }
}

pub fn signal_pid(pid: TaskId, signal: u32) -> bool {
    if pid <= 1 {
        return false;
    }
    let mut s = SCHED.lock();
    let newly_dead = match s.find(pid) {
        Some(t) => {
            let was_dead = t.state == TaskState::Dead;
            apply_signal(t, signal);
            !was_dead && t.state == TaskState::Dead
        }
        None => return false,
    };
    // A signal that kills records the exit like exit_pid does, so wait_pid reports it.
    if newly_dead {
        s.record_exit(pid, EXIT_KILLED);
    }
    true
}

/// Remove one dead task (not the running one, never the idle task) from the table.
fn take_dead_task() -> Option<TaskControlBlock> {
    let mut s = SCHED.try_lock()?;
    let cur = s.current;
    for idx in 1..MAX_TASKS {
        if idx != cur && s.tasks[idx].as_ref().map_or(false, |t| t.state == TaskState::Dead) {
            return s.tasks[idx].take();
        }
    }
    None
}

/// Free everything a reaped task owned. Runs without the SCHED lock (it takes PMM, VMM,
/// OBJ and HEAP). Safe because the task is off the table and was not the running one: its
/// kernel stack and address space are not in use.
fn teardown(t: TaskControlBlock) {
    let TaskControlBlock { pid, kstack_phys, cr3, own_cr3, handles, ipc_wait, .. } = t;
    if kstack_phys != 0 {
        crate::mm::physical::free_frames(kstack_phys, KSTACK_FRAMES);
    }
    // Ring-3 tasks and kernel threads with a private space: page tables and owned pages go
    // back to the allocator (the CR3 is no longer active).
    if kstack_phys != 0 || own_cr3 {
        crate::mm::r#virtual::destroy_address_space(cr3);
    }
    // Close its handles (frees its kernel objects) and wake waiters. The rest of the block
    // (open files, FPU image, ...) is dropped on return.
    crate::core::syscall::screen::process_gone(pid);
    crate::core::object::task_reaped(pid, handles, ipc_wait);
}

/// Reap up to a few dead tasks. Called at the start of every preemption pass.
fn reap_dead() {
    for _ in 0..4 {
        match take_dead_task() {
            Some(t) => teardown(t),
            None => break,
        }
    }
}

fn next_ready_slot(s: &SchedState) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut best_prio = Priority::Idle;

    for offset in 1..=MAX_TASKS {
        let idx = (s.current + offset) % MAX_TASKS;
        if let Some(ref task) = s.tasks[idx] {
            if task.state == TaskState::Dead {
                continue;
            }

            // Skip "phantom" bookkeeping tasks: ones that have never run
            // (`!has_frame`) and carry no entry point (`instruction_pointer == 0`),
            // such as the seed service placeholders. They have no code to
            // execute, so switching to them would resume whatever context was last
            // interrupted. They stay in the table for `ps`/IPC bookkeeping.
            if !task.has_frame && task.instruction_pointer == 0 {
                continue;
            }

            if task.state == TaskState::Ready || task.state == TaskState::Running {
                // Strictly greater: among equal priorities the first one after the
                // current slot wins, which gives round-robin.
                if best.is_none() || task.priority > best_prio {
                    best_prio = task.priority;
                    best = Some(idx);
                }
            }
        }
    }
    best
}

pub fn schedule_next() -> Option<usize> {
    let s = SCHED.lock();
    next_ready_slot(&s)
}

pub fn tick() {
    if !is_initialized() {
        return;
    }
    if let Some(c) = SCHED.lock().cur() {
        c.cpu_ticks = c.cpu_ticks.saturating_add(1);
    }
}

/// Cooperative yield: sets current task to Ready and sleeps until next interrupt.
/// Call from polling loops (ping wait, keyboard read) to avoid busy-spinning.
/// Interrupts are enabled when it returns. No spinlock may be held (checked).
pub fn sys_yield() {
    crate::core::sync::assert_no_locks("sys_yield");
    if is_initialized() {
        if let Some(task) = SCHED.lock().cur() {
            if task.state == TaskState::Running {
                task.state = TaskState::Ready;
            }
        }
    }
    // Sleep until next interrupt (timer, NIC, keyboard, etc.). Not `nomem`: the interrupt
    // that ends the HLT reads and writes memory this function touched.
    unsafe { core::arch::asm!("sti; hlt", options(nostack)) };
}

// ─── Blocking primitives for kernel objects (core/object.rs) ─────────────────────────

/// Run `f` with interrupts disabled, restoring the previous interrupt state afterwards.
pub fn without_interrupts<R>(f: impl FnOnce() -> R) -> R {
    crate::core::sync::without_interrupts(f)
}

/// Put the current task to sleep until `wake(pid)`, a timer deadline (`deadline`, in
/// `timer_ticks`; 0 = none) or any interrupt that ends HLT. Callers loop on their condition.
/// Interrupts must be off on entry and are off again on return. No lock may be held
/// (release it with `IrqSpinLockGuard::unlock_keep_irq_off` and take it again afterwards).
pub fn park(deadline: u64) {
    crate::core::sync::assert_no_locks("park");
    {
        let mut s = SCHED.lock();
        if let Some(t) = s.cur() {
            t.state = TaskState::Waiting;
            t.wake_at = deadline;
        }
    }
    // The timer interrupt that follows switches to another task; this one resumes here
    // once it is Ready again. No `nomem`: the interrupt that ends the HLT reads and writes
    // the task table, so the state stores above must not be delayed past it and the loads
    // below must not be hoisted before it.
    unsafe { core::arch::asm!("sti; hlt; cli", options(nostack)) };
    let mut s = SCHED.lock();
    if let Some(t) = s.cur() {
        t.wake_at = 0;
        if t.state == TaskState::Waiting {
            t.state = TaskState::Running;
        }
    }
}

/// Make a Waiting task runnable again.
pub fn wake(pid: TaskId) {
    if let Some(t) = SCHED.lock().find(pid) {
        if t.state == TaskState::Waiting {
            t.state = TaskState::Ready;
            t.wake_at = 0;
        }
    }
}

/// Wake tasks whose park deadline has passed. Called from the timer interrupt.
fn wake_expired(s: &mut SchedState) {
    let now = crate::arch::x86_64::idt::timer_ticks();
    for t in s.tasks.iter_mut().flatten() {
        if t.state == TaskState::Waiting && t.wake_at != 0 && now >= t.wake_at {
            t.state = TaskState::Ready;
            t.wake_at = 0;
        }
    }
}

/// Does a task with this pid exist and not yet exited?
pub fn task_alive(pid: TaskId) -> bool {
    SCHED.lock().tasks.iter().flatten().any(|t| t.pid == pid && t.state != TaskState::Dead)
}

/// Scheduler state of a task, if it exists.
pub fn task_state(pid: TaskId) -> Option<TaskState> {
    SCHED.lock().tasks.iter().flatten().find(|t| t.pid == pid).map(|t| t.state)
}

/// Handle table of the running task.
///
/// The reference outlives the SCHED lock. It is valid because the running task's control
/// block cannot be reaped, and the table is only touched under the OBJ lock (core/object.rs).
pub fn current_handles() -> &'static mut crate::core::object::HandleTable {
    let mut s = SCHED.lock();
    let t = s.cur().expect("current task");
    // SAFETY: see above; the slot is a fixed address inside the static table.
    unsafe { &mut *(&mut t.handles as *mut crate::core::object::HandleTable) }
}

/// Handle table of task `pid`, if it exists. Same rules as `current_handles`.
pub fn handles_of(pid: TaskId) -> Option<&'static mut crate::core::object::HandleTable> {
    let mut s = SCHED.lock();
    let t = s.find(pid)?;
    // SAFETY: as in `current_handles`; the caller holds OBJ and the task is not being reaped
    // (reaping needs SCHED and OBJ, and the table is taken out before OBJ is used).
    Some(unsafe { &mut *(&mut t.handles as *mut crate::core::object::HandleTable) })
}

/// Run `f` on the running task's file descriptor table. SCHED is held and interrupts are
/// off: `f` must only touch the table (no I/O, no other locks).
pub fn with_current_fds<R>(f: impl FnOnce(&mut crate::core::fd::FdTable) -> R) -> R {
    let mut s = SCHED.lock();
    let t = s.cur().expect("current task");
    f(&mut t.fds)
}

/// Record the Reply object (+1) the running task is blocked on (0 = none), so the reaper
/// can release it if the task dies while waiting.
pub fn set_ipc_wait(v: u32) {
    if let Some(t) = SCHED.lock().cur() {
        t.ipc_wait = v;
    }
}

/// Replace the running task's I/O permission bitmap and load it into the TSS now.
pub fn set_current_io_bitmap(bm: alloc::vec::Vec<u8>) {
    let mut s = SCHED.lock();
    if let Some(t) = s.cur() {
        t.io_bitmap = bm;
        crate::arch::x86_64::gdt_simple::load_io_bitmap(t.pid, &t.io_bitmap, true);
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
    if !is_initialized() {
        return;
    }

    // Dead tasks are torn down before the table lock is taken (teardown takes other locks).
    reap_dead();

    // A holder of SCHED always has interrupts off, so this only fails when a kernel fault
    // path comes here with the lock held: skip the pass instead of deadlocking.
    let mut guard = match SCHED.try_lock() {
        Some(g) => g,
        None => return,
    };
    let s = &mut *guard;

    wake_expired(s);
    let cur_slot = s.current;
    if let Some(cur) = s.tasks[cur_slot].as_mut() {
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
            // SAFETY: the ISR stub saved FRAME_WORDS words at saved_state.
            cur.frame[i] = unsafe { *src.add(i) };
        }
        cur.has_frame = true;
        if !fx_area.is_null() {
            // SAFETY: fx_area is the XSAVE image the stub saved; fx is large enough.
            unsafe {
                core::ptr::copy_nonoverlapping(fx_area, cur.fx.0.as_mut_ptr(), crate::arch::x86_64::init::xsave_area_size());
            }
        }
        if cur.state == TaskState::Running {
            cur.state = TaskState::Ready;
        }
    }

    let next_slot = match next_ready_slot(s) {
        Some(n) => n,
        None => {
            if let Some(cur) = s.tasks[cur_slot].as_mut() {
                cur.state = TaskState::Running;
            }
            return;
        }
    };

    if next_slot == cur_slot {
        if let Some(cur) = s.tasks[cur_slot].as_mut() {
            cur.state = TaskState::Running;
        }
        return;
    }

    let from_user = s.tasks[cur_slot].as_ref().map_or(false, |t| t.kstack_phys != 0);
    s.current = next_slot;
    if let Some(next) = s.tasks[next_slot].as_mut() {
        if from_user && next.kstack_phys != 0 {
            USER_TO_USER_SWITCHES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        next.state = TaskState::Running;

        if next.cr3 != 0 && next.cr3 != current_cr3() {
            // Refresh kernel upper-half entries in the target PML4 so that any dynamic
            // kernel mappings added after this task was spawned are visible immediately.
            // Without this, a stale PML4 causes #PF 0x0 (not-present, kernel).
            if crate::mm::r#virtual::is_initialized() {
                crate::mm::r#virtual::sync_kernel_mappings(next.cr3);
            }
            write_cr3(next.cr3);
        }

        if next.has_frame {
            let dst = saved_state as *mut u64;
            for i in 0..FRAME_WORDS {
                // SAFETY: same frame the stub will pop on return.
                unsafe { *dst.add(i) = next.frame[i] };
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
            unsafe { crate::arch::x86_64::init::restore_fpu_state(next.fx.0.as_ptr()) };
        } else {
            // SAFETY: the stub restores this image on return.
            unsafe {
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
    SCHED.lock().cur().filter(|t| t.kstack_phys != 0).map(|t| t.cr3)
}

/// Reserve `pages` pages of virtual address space for mmap in the current ring-3 task.
/// Leaves an unmapped guard page after each reservation.
pub fn reserve_user_range(pages: u64) -> Option<u64> {
    let mut s = SCHED.lock();
    let t = s.cur().filter(|t| t.kstack_phys != 0)?;
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

/// Context switches directly between two ring-3 tasks (for diagnostics and tests).
pub static USER_TO_USER_SWITCHES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn set_preemption_disabled(disabled: bool) {
    if let Some(t) = SCHED.lock().cur() {
        t.preemption_disabled = disabled;
    }
}

pub fn set_is_vfs_server(is_server: bool) {
    if !is_server { return; }
    grant_capability(current_pid(), Capability::VfsServer);
}

pub fn set_med_id(med_id: u64) {
    if let Some(t) = SCHED.lock().cur() {
        t.med_id = Some(med_id);
    }
}

pub fn get_tasks(out: &mut [TaskSnapshot]) -> usize {
    let s = SCHED.lock();
    let mut n = 0usize;
    for task in s.tasks.iter().flatten() {
        if n >= out.len() {
            break;
        }
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
