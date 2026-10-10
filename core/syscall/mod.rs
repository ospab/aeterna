/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Syscall interface for AETERNA microkernel (Phase 3).
Provides a real dispatch table with VFS-backed sys_open/read/write/close.

Syscall ABI (x86_64):
  RAX = syscall number
  RDI = arg1,  RSI = arg2,  RDX = arg3,  R10 = arg4,  R8 = arg5
  Return value in RAX.

LSTAR MSR setup is done in init_syscall_msr() — configures the SYSCALL
instruction to jump to our handler entry point.
*/

extern crate alloc;

pub mod objects;

/// Syscall numbers for AETERNA microkernel
/// Follows microkernel philosophy: minimal set, everything else via IPC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SyscallNumber {
    /// Exit current process
    Exit = 0,
    /// Write to a file descriptor (fd, buf_ptr, len) -> bytes_written
    Write = 1,
    /// Read from a file descriptor (fd, buf_ptr, len) -> bytes_read
    Read = 2,
    /// Open a resource by path -> fd
    Open = 3,
    /// Close a file descriptor
    Close = 4,
    /// Send IPC message (target_pid, msg_ptr, msg_len)
    IpcSend = 10,
    /// Receive IPC message (buf_ptr, buf_len) -> (sender_pid, msg_len)
    IpcRecv = 11,
    /// Create IPC channel -> channel_id
    IpcCreate = 12,
    /// Yield CPU time to scheduler
    Yield = 20,
    /// Sleep for N milliseconds
    Sleep = 21,
    /// Get current process ID
    GetPid = 22,
    /// Spawn a new process/task (name_ptr, name_len, priority)
    Spawn = 23,
    /// Enable/disable preemption for current task (1=disabled, 0=enabled)
    PreemptControl = 24,
    /// Fork current process -> child_pid
    Fork = 30,
    /// Execute a new program (path_ptr, argv_ptr)
    Exec = 31,
    /// Wait for child process
    WaitPid = 32,
    /// Map memory pages (addr_hint, size, flags) -> mapped_addr
    Mmap = 40,
    /// Unmap memory pages (addr, size)
    Munmap = 41,
    /// Get system information (info_type, buf_ptr, buf_len)
    SysInfo = 50,
    /// Get uptime in milliseconds
    Uptime = 51,
    /// Get task list metadata
    GetTasks = 52,
    /// Delegate a capability to another process (target_pid, cap_id)
    CapDelegate = 70,
    /// Bind process to a specific Memory Execution Domain (med_id)
    MedAssign = 80,

    /// Detach kernel driver from a device (dev_id: 0=RTL8139)
    DevDetach = 110,

    /// Kernel objects, IPC, memory regions, interrupts, I/O ports: 200..=253,
    /// see docs/en/syscall-abi.md (dispatched from DISPATCH_TABLE).
    HandleClose = 200,
}

/// Syscall result codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum SyscallError {
    /// Success (not an error)
    Success = 0,
    /// Invalid syscall number
    InvalidSyscall = -1,
    /// Permission denied (capability check failed)
    PermissionDenied = -2,
    /// Invalid argument
    InvalidArgument = -3,
    /// Resource not found
    NotFound = -4,
    /// Resource busy
    Busy = -5,
    /// Out of memory
    OutOfMemory = -6,
    /// Operation not supported
    NotSupported = -7,
    /// I/O error
    IoError = -8,
    /// Process not found
    NoSuchProcess = -9,
    /// A pointer argument is outside user space or not mapped
    BadAddress = -10,
    /// Handle value is not in the caller's table (never issued, closed, or stale)
    BadHandle = -11,
    /// Handle refers to an object of the wrong type for this call
    WrongType = -12,
    /// The other side of the IPC is gone (channel closed, reply handle dropped)
    PeerClosed = -13,
    /// Handle table full
    TableFull = -14,
    /// Timed out
    Timeout = -15,
}

impl From<crate::mm::usercopy::UserCopyError> for SyscallError {
    fn from(e: crate::mm::usercopy::UserCopyError) -> Self {
        match e {
            crate::mm::usercopy::UserCopyError::TooLarge => SyscallError::InvalidArgument,
            _ => SyscallError::BadAddress,
        }
    }
}

/// Largest buffer a single read/write syscall moves (bigger requests are clamped).
const MAX_IO_CHUNK: usize = 64 * 1024;
/// Longest path or name accepted from user space.
const MAX_PATH: usize = 4096;

/// Syscall arguments passed in registers
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    pub number: u64,     // RAX
    pub arg1: u64,       // RDI
    pub arg2: u64,       // RSI
    pub arg3: u64,       // RDX
    pub arg4: u64,       // R10
    pub arg5: u64,       // R8
}

/// Dispatch table entry type
type SyscallFn = fn(&SyscallArgs) -> i64;

/// Dispatch table: syscall number → handler function.
/// Entries are (number, handler). Searched linearly (small table).
static DISPATCH_TABLE: &[(u64, SyscallFn)] = &[
    (0,  |a| syscall_exit(a.arg1)),
    (1,  |a| syscall_write(a.arg1, a.arg2, a.arg3)),
    (2,  |a| syscall_read(a.arg1, a.arg2, a.arg3)),
    (3,  |a| syscall_open(a.arg1, a.arg2, a.arg3)),
    (4,  |a| syscall_close(a.arg1)),
    (20, |_| syscall_yield()),
    (22, |_| syscall_getpid()),
    (23, |a| syscall_spawn(a.arg1, a.arg2, a.arg3)),
    (24, |a| syscall_preempt_control(a.arg1)),
    (32, |a| syscall_waitpid(a.arg1)),
    // SyscallNumber::Mmap = 40: map size bytes, flags bit0 = HUGE_PAGE
    (40, |a| syscall_mmap(a.arg1, a.arg2, a.arg3)),
    // SyscallNumber::Munmap = 41: unmap mapped region
    (41, |a| syscall_munmap(a.arg1, a.arg2)),
    (50, |a| syscall_sysinfo(a.arg1, a.arg2, a.arg3)),
    (51, |_| syscall_uptime()),
    (52, |_| syscall_get_tasks()),
    // 60/61/62 (raw port I/O, irq_wait), 100 (vfs_register), 120-122 (SMR with raw
    // physical addresses) and 130 (dma_alloc returning a physical address) are gone:
    // ring 3 gets hardware and shared memory only through handles (240-253 below).
    (70, |a| syscall_cap_delegate(a.arg1, a.arg2)),
    (80, |a| syscall_med_assign(a.arg1)),
    (110, |a| syscall_dev_detach(a.arg1)),
    // Kernel objects and handles (docs/en/syscall-abi.md)
    (200, |a| objects::handle_close(a.arg1)),
    (201, |a| objects::handle_dup(a.arg1, a.arg2)),
    (202, |a| objects::handle_info(a.arg1)),
    (210, |_| objects::channel_create()),
    (211, |a| objects::ipc_call(a.arg1, a.arg2, a.arg3)),
    (212, |a| objects::ipc_send(a.arg1, a.arg2)),
    (213, |a| objects::ipc_recv(a.arg1, a.arg2, a.arg3)),
    (214, |a| objects::ipc_reply(a.arg1, a.arg2)),
    (220, |_| objects::notify_create()),
    (221, |a| objects::notify_signal(a.arg1, a.arg2)),
    (222, |a| objects::notify_wait(a.arg1, a.arg2)),
    (230, |_| objects::process_self()),
    (231, |_| objects::thread_self()),
    (232, |a| objects::process_wait(a.arg1, a.arg2, a.arg3)),
    (233, |a| objects::process_kill(a.arg1)),
    (240, |a| objects::mem_create(a.arg1)),
    (241, |a| objects::mem_map(a.arg1, a.arg2, a.arg3)),
    (242, |a| objects::mem_unmap(a.arg1)),
    (243, |a| objects::mem_create_contig(a.arg1, a.arg2)),
    (244, |a| objects::mem_phys(a.arg1)),
    (245, |a| objects::mem_size(a.arg1)),
    (250, |a| objects::irq_bind(a.arg1, a.arg2, a.arg3)),
    (251, |a| objects::irq_ack(a.arg1)),
    (252, |a| objects::ioport_enable(a.arg1)),
    (253, |a| objects::ioport_disable(a.arg1)),
];

/// Dispatch a syscall by looking up the number in the dispatch table
pub fn dispatch(args: &SyscallArgs) -> i64 {
    for &(num, handler) in DISPATCH_TABLE {
        if num == args.number {
            return handler(args);
        }
    }
    SyscallError::InvalidSyscall as i64
}

// ─── SYSCALL MSR setup ──────────────────────────────────────────────────────

/// IA32_EFER MSR — Extended Feature Enable Register
const MSR_EFER: u32 = 0xC0000080;
/// IA32_STAR MSR — Segment selectors for SYSCALL/SYSRET
const MSR_STAR: u32 = 0xC0000081;
/// IA32_LSTAR MSR — Target RIP for SYSCALL instruction
const MSR_LSTAR: u32 = 0xC0000082;
/// IA32_FMASK MSR — RFLAGS mask during SYSCALL
const MSR_FMASK: u32 = 0xC0000084;
/// IA32_KERNEL_GS_BASE MSR — Base address of KERNEL_GS segment
const MSR_GS_BASE: u32 = 0xC0000101;
const MSR_KERNEL_GS_BASE: u32 = 0xC0000102;

#[repr(C)]
struct PerCpu {
    kernel_stack: u64,
    user_rsp: u64,
}

static mut PER_CPU: PerCpu = PerCpu {
    kernel_stack: 0,
    user_rsp: 0,
};

static mut SYSCALL_STACK: [u8; 16384] = [0; 16384];

/// Read a Model-Specific Register
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo, out("edx") hi,
        options(nomem, nostack)
    );
    (hi as u64) << 32 | lo as u64
}

/// Write a Model-Specific Register
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") lo, in("edx") hi,
        options(nomem, nostack)
    );
}

/// Initialize SYSCALL/SYSRET MSR registers.
/// After this, executing the SYSCALL instruction in ring 3 will jump
/// to syscall_entry_stub.
///
/// Note: we set up the MSRs even though we don't have ring-3 yet,
/// so the infrastructure is ready when userspace arrives.
pub fn init_syscall_msr() {
    unsafe {
        // 1. Enable SCE (System Call Extensions) bit in EFER
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer | 1); // bit 0 = SCE

        // 2. STAR: set kernel/user selectors for SYSCALL/SYSRET.
        // SYSCALL loads CS from STAR[47:32], SS = CS + 8.
        // SYSRETQ loads CS from (STAR[63:48] + 16), SS = (STAR[63:48] + 8).
        // Therefore the upper half stores USER_CS - 16.
        let star = ((crate::arch::x86_64::gdt_simple::KERNEL_CS as u64) << 32)
            | (((crate::arch::x86_64::gdt_simple::USER_CS as u64) - 16) << 48);
        wrmsr(MSR_STAR, star);

        // 3. LSTAR: entry point for SYSCALL instruction
        // For now, point to our minimal handler
        wrmsr(MSR_LSTAR, syscall_entry_stub as *const () as u64);

        // 4. FMASK: clear IF (bit 9) on SYSCALL entry (disable interrupts)
        wrmsr(MSR_FMASK, 0x200); // mask IF

        // 5. GS convention: while in the kernel, GS.base = PER_CPU and KERNEL_GS_BASE
        //    holds the user value. Every entry from ring 3 (SYSCALL and the interrupt
        //    stubs) does swapgs, and every return to ring 3 swaps back.
        PER_CPU.kernel_stack = (SYSCALL_STACK.as_ptr() as u64) + 16384;
        wrmsr(MSR_GS_BASE, core::ptr::addr_of!(PER_CPU) as u64);
        wrmsr(MSR_KERNEL_GS_BASE, 0);
    }

    crate::arch::x86_64::serial::write_str("[SYSCALL] MSR configured (LSTAR, STAR, FMASK, KERN_GS)\r\n");
}

/// Minimal SYSCALL entry stub.
/// Transition from Ring 3 to Ring 0.
#[no_mangle]
#[unsafe(naked)]
pub unsafe extern "C" fn syscall_entry_stub() {
    core::arch::naked_asm!(
        "swapgs",               // Get kernel GS base (points to PerCpu)
        "mov gs:[8], rsp",      // Stash user RSP (IF is masked, nothing can intervene)
        "mov rsp, gs:[0]",      // Switch to this task's kernel stack
        "push qword ptr gs:[8]", // Keep user RSP on the task's own stack: the per-CPU slot
                                 // is reused by the next task that enters while we block.

        "push r11",             // Save R11 (User RFLAGS)
        "push rcx",             // Save RCX (User RIP)
        
        // Save scratch registers that might be clobbered by Rust
        "push rdi",
        "push rsi",
        "push rdx",
        "push r8",
        "push r9",
        "push r10",
        
        // Pass arguments to syscall_dispatch (RAX=num, RDI=arg1, RSI=arg2, RDX=arg3, R10=arg4, R8=arg5)
        // System V ABI for x86_64 call: RDI, RSI, RDX, RCX, R8, R9
        "mov r9, r8",           // arg5
        "mov r8, r10",          // arg4
        "mov rcx, rdx",         // arg3
        "mov rdx, rsi",         // arg2
        "mov rsi, rdi",         // arg1
        "mov rdi, rax",         // number
        "sub rsp, 8",           // 9 pushes above: realign to 16 bytes for the call
        "call syscall_dispatch",
        "add rsp, 8",
        "cli",                 // A blocking syscall may have enabled interrupts; the
                                // stack/GS switch below must not be interrupted.

        // Restore scratch registers
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdx",
        "pop rsi",
        "pop rdi",

        "pop rcx",              // Restore RCX (User RIP)
        "pop r11",              // Restore R11 (User RFLAGS)

        "pop rsp",              // Restore user RSP saved on entry
        "swapgs",               // Restore user GS base
        "sysretq"
    );
}

/// Point the SYSCALL entry at the kernel stack of the task being switched in.
pub fn set_kernel_stack(top: u64) {
    // SAFETY: single CPU; called from the scheduler with interrupts disabled.
    unsafe { PER_CPU.kernel_stack = top };
}

#[no_mangle]
extern "C" fn syscall_dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let args = SyscallArgs {
        number: num,
        arg1:   a1,
        arg2:   a2,
        arg3:   a3,
        arg4:   a4,
        arg5:   a5,
    };
    dispatch(&args)
}

// ============================================================================
// Syscall implementations — real logic, not stubs
// ============================================================================

fn syscall_exit(code: u64) -> i64 {
    crate::arch::x86_64::serial::write_str("[SYSCALL] exit(");
    serial_dec(code);
    crate::arch::x86_64::serial::write_str(")\r\n");
    crate::core::scheduler::exit_current(code);

    // We arrived here via the SYSCALL instruction, so `syscall_entry_stub`
    // already executed `swapgs` (GS now points at the per-CPU kernel area).
    // Crucially, we will NOT return to the caller via `sysretq` — the process
    // is dead. Instead we re-enable interrupts and halt; the next timer IRQ
    // drives `on_timer_irq`, which sees this task as Dead and context-switches
    // (via iretq) into the next ready task, never returning here.
    //
    // GS stays on the kernel base: inside the kernel it always is. Whichever
    // interrupt switches us away swaps to the user base only if it returns to
    // ring 3, based on the frame of the task it resumes.
    unsafe {
        loop {
            core::arch::asm!("sti; hlt", options(nomem, nostack));
        }
    }
}

#[inline]
fn has_system_cap() -> bool {
    crate::core::scheduler::has_capability(crate::core::scheduler::Capability::System)
}

#[inline]
fn can_fs_read() -> bool {
    has_system_cap()
        || crate::core::scheduler::has_capability(crate::core::scheduler::Capability::FsRead)
}

#[inline]
fn can_fs_write() -> bool {
    has_system_cap()
        || crate::core::scheduler::has_capability(crate::core::scheduler::Capability::FsWrite)
}

#[inline]
fn can_serial_write() -> bool {
    has_system_cap()
        || crate::core::scheduler::has_capability(crate::core::scheduler::Capability::Serial)
}

/// sys_write(fd, buf_ptr, len) — write bytes to a file descriptor.
/// fd=1 → serial+framebuffer (stdout), fd=2 → serial (stderr).
/// fd≥3 → VFS file write.
/// Set by the console when it starts: from then on fd 1/2 of ring-3 programs also
/// reach the shell's output (before that, e.g. boot self-tests, serial only).
static CONSOLE_STDOUT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn set_console_stdout(on: bool) {
    CONSOLE_STDOUT.store(on, core::sync::atomic::Ordering::Relaxed);
}

fn syscall_write(fd: u64, buf_ptr: u64, len: u64) -> i64 {
    let len = (len as usize).min(MAX_IO_CHUNK);
    // stdout/stderr → serial output
    if fd == 1 || fd == 2 {
        if !can_serial_write() {
            return SyscallError::PermissionDenied as i64;
        }
        let buf = match crate::mm::usercopy::read_user_bytes(buf_ptr, len, MAX_IO_CHUNK) {
            Ok(b) => b,
            Err(e) => return SyscallError::from(e) as i64,
        };
        for &b in &buf {
            crate::arch::x86_64::serial::write_byte(b);
        }
        // Once the console runs, a program's output also goes where the shell's current
        // stdout/stderr goes (screen, pipe or redirect): the shell waits for the program.
        if CONSOLE_STDOUT.load(core::sync::atomic::Ordering::Relaxed) {
            let text = alloc::string::String::from_utf8_lossy(&buf);
            if fd == 1 {
                crate::userspace::plum::io::out(&text);
            } else {
                crate::userspace::plum::io::err(&text);
            }
        }
        return len as i64;
    }

    // VFS file descriptor
    if !can_fs_write() {
        return SyscallError::PermissionDenied as i64;
    }
    match crate::mm::usercopy::read_user_bytes(buf_ptr, len, MAX_IO_CHUNK) {
        Ok(buf) => crate::fs::sys_write(fd as usize, &buf),
        Err(e) => SyscallError::from(e) as i64,
    }
}

/// sys_read(fd, buf_ptr, len) — read bytes from a file descriptor.
/// fd=0 → keyboard (stdin), fd≥3 → VFS file read.
fn syscall_read(fd: u64, buf_ptr: u64, len: u64) -> i64 {
    let len = (len as usize).min(MAX_IO_CHUNK);
    if fd == 0 && CONSOLE_STDOUT.load(core::sync::atomic::Ordering::Relaxed) && len >= 1 {
        // A program run by the shell reads the shell's stdin: piped / redirected data
        // (0 bytes = end of input), or, on the console, one typed character (echoed),
        // sleeping until a key arrives. The shell kills the program on Ctrl+C.
        if let Some(chunk) = crate::userspace::plum::io::read_stdin_bytes(len) {
            return match crate::mm::usercopy::copy_to_user(buf_ptr, &chunk) {
                Ok(()) => chunk.len() as i64,
                Err(e) => SyscallError::from(e) as i64,
            };
        }
        loop {
            if let Some(ch) = crate::arch::x86_64::keyboard::poll_key() {
                let mut tmp = [0u8; 4];
                let bytes = ch.encode_utf8(&mut tmp).as_bytes();
                crate::userspace::plum::io::out(core::str::from_utf8(bytes).unwrap_or(""));
                let n = bytes.len().min(len);
                return match crate::mm::usercopy::copy_to_user(buf_ptr, &bytes[..n]) {
                    Ok(()) => n as i64,
                    Err(e) => SyscallError::from(e) as i64,
                };
            }
            crate::core::scheduler::sys_yield();
        }
    }
    if fd == 0 {
        // stdin: read one key from keyboard
        let key = crate::arch::x86_64::keyboard::poll_key();
        if let Some(ch) = key {
            if len >= 1 {
                return match crate::mm::usercopy::copy_to_user(buf_ptr, &[ch as u8]) {
                    Ok(()) => 1,
                    Err(e) => SyscallError::from(e) as i64,
                };
            }
        }
        return 0;
    }

    // VFS file descriptor
    if !can_fs_read() {
        return SyscallError::PermissionDenied as i64;
    }
    if !crate::mm::usercopy::range_ok(buf_ptr, len) {
        return SyscallError::BadAddress as i64;
    }
    let mut buf = alloc::vec![0u8; len];
    let n = crate::fs::sys_read(fd as usize, &mut buf);
    if n > 0 {
        if let Err(e) = crate::mm::usercopy::copy_to_user(buf_ptr, &buf[..n as usize]) {
            return SyscallError::from(e) as i64;
        }
    }
    n
}

/// sys_open(path_ptr, path_len, flags) — open a file, returning fd.
/// flags: 0=read, 1=write, 2=read+write
fn syscall_open(path_ptr: u64, path_len: u64, flags: u64) -> i64 {
    match flags {
        0 => {
            if !can_fs_read() {
                return SyscallError::PermissionDenied as i64;
            }
        }
        1 => {
            if !can_fs_write() {
                return SyscallError::PermissionDenied as i64;
            }
        }
        2 => {
            if !(can_fs_read() && can_fs_write()) {
                return SyscallError::PermissionDenied as i64;
            }
        }
        _ => return SyscallError::InvalidArgument as i64,
    }

    match crate::mm::usercopy::read_user_str(path_ptr, path_len as usize, MAX_PATH) {
        Ok(path) => crate::fs::sys_open(&path, flags),
        Err(e) => SyscallError::from(e) as i64,
    }
}

/// sys_close(fd) — close a file descriptor.
fn syscall_close(fd: u64) -> i64 {
    crate::fs::sys_close(fd as usize)
}

fn syscall_yield() -> i64 {
    if crate::core::scheduler::is_initialized() {
        crate::core::scheduler::tick();
    }
    SyscallError::Success as i64
}

/// sys_waitpid(pid) — block until the task with `pid` exits.
/// Returns 0 on success, -1 if pid is invalid / never existed.
fn syscall_waitpid(pid: u64) -> i64 {
    let _ = crate::core::scheduler::wait_pid(pid as crate::core::scheduler::TaskId);
    SyscallError::Success as i64
}

fn syscall_getpid() -> i64 {
    crate::core::scheduler::current_task_id() as i64
}

fn syscall_spawn(name_ptr: u64, name_len: u64, priority: u64) -> i64 {
    if !has_system_cap() &&
       !crate::core::scheduler::has_capability(crate::core::scheduler::Capability::Spawn) {
        return SyscallError::PermissionDenied as i64;
    }

    let name = match crate::mm::usercopy::read_user_str(name_ptr, name_len as usize, 64) {
        Ok(s) => s,
        Err(e) => return SyscallError::from(e) as i64,
    };
    let name = name.as_str();

    let prio = match priority {
        0 => crate::core::scheduler::Priority::Idle,
        1 => crate::core::scheduler::Priority::Normal,
        2 => crate::core::scheduler::Priority::System,
        3 => crate::core::scheduler::Priority::RealTime,
        _ => crate::core::scheduler::Priority::Compute,
    };

    match crate::core::scheduler::spawn_named(name, prio, 0, 0, 0, &[]) {
        Some(pid) => pid as i64,
        None => SyscallError::Busy as i64,
    }
}

fn syscall_preempt_control(disable: u64) -> i64 {
    crate::core::scheduler::set_preemption_disabled(disable != 0);
    0
}

fn syscall_sysinfo(info_type: u64, _buf_ptr: u64, _buf_len: u64) -> i64 {
    match info_type {
        0 => crate::mm::physical::total_memory() as i64,
        1 => crate::mm::physical::usable_memory() as i64,
        2 => crate::core::scheduler::task_count() as i64,
        _ => SyscallError::InvalidArgument as i64,
    }
}

fn syscall_uptime() -> i64 {
    crate::arch::x86_64::idt::timer_ticks() as i64
}

fn syscall_get_tasks() -> i64 {
    crate::core::scheduler::task_count() as i64
}

pub type TaskInfo = crate::core::scheduler::TaskSnapshot;

pub fn sys_get_tasks(out: &mut [TaskInfo]) -> usize {
    crate::core::scheduler::get_tasks(out)
}

// ─── sys_mmap (SyscallNumber::Mmap = 40) ────────────────────────────────────
//
// ABI: RDI=addr_hint (ignored), RSI=size, RDX=flags (ignored for now)
// Allocates zeroed pages and maps them read/write into the calling task's
// address space. Returns the user virtual address, or a negative SyscallError.
// Only ring-3 tasks with their own address space may call it.

/// Largest single mmap request (64 MiB).
const MAX_MMAP_BYTES: u64 = 64 * 1024 * 1024;

fn syscall_mmap(_addr_hint: u64, size: u64, _flags: u64) -> i64 {
    use crate::mm::{physical, r#virtual as vmm};
    if size == 0 || size > MAX_MMAP_BYTES {
        return SyscallError::InvalidArgument as i64;
    }
    let cr3 = match crate::core::scheduler::current_user_cr3() {
        Some(c) => c,
        None => return SyscallError::NotSupported as i64,
    };
    let pages = (size + physical::FRAME_SIZE - 1) / physical::FRAME_SIZE;
    let base = match crate::core::scheduler::reserve_user_range(pages) {
        Some(b) => b,
        None => return SyscallError::OutOfMemory as i64,
    };

    for i in 0..pages {
        let va = base + i * physical::FRAME_SIZE;
        let ok = match physical::alloc_frame() {
            Some(phys) => {
                if vmm::map_page(cr3, va, phys, vmm::FLAG_USER | vmm::FLAG_WRITABLE | vmm::FLAG_OWNED) {
                    true
                } else {
                    physical::free_frame(phys);
                    false
                }
            }
            None => false,
        };
        if !ok {
            // Roll back what was mapped so far.
            unmap_user_pages(cr3, base, i);
            return SyscallError::OutOfMemory as i64;
        }
    }

    let pid = crate::core::scheduler::current_pid();
    crate::core::scheduler::add_memory_usage(pid, pages * physical::FRAME_SIZE);
    base as i64
}

/// sys_munmap(addr, size) — unmap and free pages of the caller's address space.
/// Only page-aligned user ranges are accepted; pages that are not mapped are skipped.
fn syscall_munmap(addr: u64, size: u64) -> i64 {
    use crate::mm::physical::FRAME_SIZE;
    if size == 0 || addr % FRAME_SIZE != 0 || !crate::mm::usercopy::range_ok(addr, size as usize) {
        return SyscallError::InvalidArgument as i64;
    }
    let cr3 = match crate::core::scheduler::current_user_cr3() {
        Some(c) => c,
        None => return SyscallError::NotSupported as i64,
    };
    let pages = (size + FRAME_SIZE - 1) / FRAME_SIZE;
    let freed = unmap_user_pages(cr3, addr, pages);
    let pid = crate::core::scheduler::current_pid();
    crate::core::scheduler::sub_memory_usage(pid, freed * FRAME_SIZE);
    SyscallError::Success as i64
}

/// Unmap `pages` pages starting at `base` in address space `cr3` and free their frames.
/// Returns how many pages were actually mapped (and are now freed).
fn unmap_user_pages(cr3: u64, base: u64, pages: u64) -> u64 {
    use crate::mm::{physical, r#virtual as vmm};
    let current = vmm::read_cr3() & !0xFFF == cr3 & !0xFFF;
    let mut freed = 0;
    for i in 0..pages {
        let va = base + i * physical::FRAME_SIZE;
        if let Some((phys, flags)) = vmm::unmap_page_entry(cr3, va) {
            if current {
                vmm::invlpg(va);
            }
            // Only frames the process owns go back to the allocator; shared ones
            // (e.g. kernel text mapped for tests) are just unmapped.
            if flags & vmm::FLAG_OWNED != 0 {
                physical::free_frame(phys);
                freed += 1;
            }
        }
    }
    freed
}

// Helper
fn serial_dec(mut val: u64) {
    if val == 0 {
        crate::arch::x86_64::serial::write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    for j in (0..i).rev() {
        crate::arch::x86_64::serial::write_byte(buf[j]);
    }
}

fn syscall_cap_delegate(target_pid: u64, cap_id: u64) -> i64 {
    let cap = match cap_id {
        31 => crate::core::scheduler::Capability::FsRead,
        32 => crate::core::scheduler::Capability::FsWrite,
        37 => crate::core::scheduler::Capability::Net,
        38 => crate::core::scheduler::Capability::System,
        39 => crate::core::scheduler::Capability::Device,
        _  => return SyscallError::InvalidArgument as i64,
    };

    if !crate::core::scheduler::has_capability(cap) {
        return SyscallError::PermissionDenied as i64;
    }

    if crate::core::scheduler::grant_capability(target_pid as u32, cap) {
        0
    } else {
        SyscallError::NoSuchProcess as i64
    }
}

fn syscall_med_assign(med_id: u64) -> i64 {
    // Requires CapSystem or CapMemHuge
    if !crate::core::scheduler::has_capability(crate::core::scheduler::Capability::System) &&
       !crate::core::scheduler::has_capability(crate::core::scheduler::Capability::MemHuge) {
        return SyscallError::PermissionDenied as i64;
    }
    
    // Store in TCB for deterministic NUMA/bandwidth enforcement
    crate::core::scheduler::set_med_id(med_id);
    0
}

fn syscall_dev_detach(dev_id: u64) -> i64 {
    if !crate::core::scheduler::has_capability(crate::core::scheduler::Capability::Device) {
        return SyscallError::PermissionDenied as i64;
    }
    if dev_id == 0 {
        crate::userspace::net::rtl8139::detach();
    } else if dev_id == 1 {
        crate::drivers::nvme::detach();
    }
    0
}
