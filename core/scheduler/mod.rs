/*
Business Source License 1.1
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
}

pub type TaskId = u32;

const MAX_TASKS: usize = 64;
const FRAME_WORDS: usize = 21; // r15..rax, err, rip, cs, rflags, rsp, ss

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
    spawn_named("task", priority, entry_point, stack_pointer, 0)
}

pub fn spawn_named(
    name: &str,
    priority: Priority,
    entry_point: u64,
    stack_pointer: u64,
    memory_bytes: u64,
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

                // Select Ring 0 or Ring 3 segments based on priority
                if priority == Priority::Normal {
                    frame[17] = gdt_simple::USER_CS as u64;  // CS
                    frame[20] = gdt_simple::USER_DS as u64;  // SS
                } else {
                    frame[17] = gdt_simple::KERNEL_CS as u64; // CS
                    frame[20] = gdt_simple::KERNEL_DS as u64; // SS
                }

                // Grant basic capabilities to new tasks. 
                // In Phase 3, this is expanded to match the task's manifest.
                let mut caps = alloc::vec![Capability::Serial];
                if priority == Priority::System || priority == Priority::Compute {
                    caps.push(Capability::Spawn);
                    caps.push(Capability::MemHuge);
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
                });
                return Some(pid);
            }
        }
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

pub fn exit_current(_code: u64) {
    unsafe {
        if let Some(ref mut tcb) = TASKS[CURRENT_SLOT] {
            tcb.state = TaskState::Dead;
        }
    }
}

pub fn exit_pid(pid: TaskId) -> bool {
    unsafe {
        for i in 0..MAX_TASKS {
            if let Some(ref mut tcb) = TASKS[i] {
                if tcb.pid == pid {
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
pub fn wait_pid(pid: TaskId) {
    loop {
        let alive = unsafe {
            TASKS.iter().flatten().any(|t| t.pid == pid && t.state != TaskState::Dead)
        };
        if !alive {
            return;
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
                        TASKS[idx] = None;
                    }
                    continue;
                }

                if task.state == TaskState::Ready || task.state == TaskState::Running {
                    if task.priority >= best_prio {
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

pub fn on_timer_irq(saved_state: *mut u8) {
    unsafe {
        if !SCHEDULER_INITIALIZED {
            return;
        }

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

        if let Some(ref mut next) = TASKS[next_slot] {
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
        }
    }
}

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