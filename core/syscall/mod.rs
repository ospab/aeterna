/*
Business Source License 1.1
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
    /// I/O port read (port, size)
    IopIn = 60,
    /// I/O port write (port, size, value)
    IopOut = 61,
    /// Wait for an interrupt (irq_num)
    IrqWait = 62,
    /// Delegate a capability to another process (target_pid, cap_id)
    CapDelegate = 70,
    /// Bind process to a specific Memory Execution Domain (med_id)
    MedAssign = 80,

    /// Register current process as a VFS server for a mount point (path_ptr, path_len)
    VfsRegister = 100,

    /// Detach kernel driver from a device (dev_id: 0=RTL8139)
    DevDetach = 110,

    /// Create a new IPC channel (returns channel_id)
    SmrCreate = 120,
    /// Send a descriptor to a channel (channel_id, phys_addr, length)
    SmrSend = 121,
    /// Receive a descriptor from a channel (channel_id) -> (phys_addr, length)
    SmrRecv = 122,

    /// Allocate physically contiguous DMA buffer (size_bytes, alignment)
    DmaAlloc = 130,
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
}

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
    (60, |a| syscall_ioport_in(a.arg1, a.arg2)),
    (61, |a| syscall_ioport_out(a.arg1, a.arg2, a.arg3)),
    (62, |a| syscall_irq_wait(a.arg1)),
    (70, |a| syscall_cap_delegate(a.arg1, a.arg2)),
    (80, |a| syscall_med_assign(a.arg1)),
    (100, |a| syscall_vfs_register(a.arg1, a.arg2)),
    (110, |a| syscall_dev_detach(a.arg1)),
    (120, |a| syscall_smr_create(a.arg1)),
    (121, |a| syscall_smr_send(a.arg1, a.arg2, a.arg3)),
    (122, |a| syscall_smr_recv(a.arg1)),
    (130, |a| syscall_dma_alloc(a.arg1, a.arg2)),
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

        // 2. STAR: set kernel CS/SS and user CS/SS
        // Bits 47:32 = kernel CS (0x08), kernel SS is CS+8 (0x10)
        // Bits 63:48 = user CS-16 for SYSRET (0x1B - 16 = user CS=0x23, SS=0x1B)
        // For now, kernel-only: CS=0x08, SS=0x10
        let star = (0x0008u64 << 32) | (0x0010u64 << 48);
        wrmsr(MSR_STAR, star);

        // 3. LSTAR: entry point for SYSCALL instruction
        // For now, point to our minimal handler
        wrmsr(MSR_LSTAR, syscall_entry_stub as *const () as u64);

        // 4. FMASK: clear IF (bit 9) on SYSCALL entry (disable interrupts)
        wrmsr(MSR_FMASK, 0x200); // mask IF

        // 5. KERNEL_GS_BASE: base for swapgs
        unsafe {
            PER_CPU.kernel_stack = (SYSCALL_STACK.as_ptr() as u64) + 16384;
            wrmsr(MSR_KERNEL_GS_BASE, core::ptr::addr_of!(PER_CPU) as u64);
        }
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
        "mov gs:[8], rsp",      // Save user RSP to user_rsp
        "mov rsp, gs:[0]",      // Load kernel_stack to RSP
        
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
        "call syscall_dispatch",
        
        // Restore scratch registers
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdx",
        "pop rsi",
        "pop rdi",

        "pop rcx",              // Restore RCX (User RIP)
        "pop r11",              // Restore R11 (User RFLAGS)
        
        "mov rsp, gs:[8]",      // Restore user RSP
        "swapgs",               // Restore user GS base
        "sysretq"
    );
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
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}

/// sys_write(fd, buf_ptr, len) — write bytes to a file descriptor.
/// fd=1 → serial+framebuffer (stdout), fd=2 → serial (stderr).
/// fd≥3 → VFS file write.
fn syscall_write(fd: u64, buf_ptr: u64, len: u64) -> i64 {
    // stdout/stderr → serial output
    if fd == 1 || fd == 2 {
        unsafe {
            let buf = core::slice::from_raw_parts(buf_ptr as *const u8, len as usize);
            for &b in buf {
                crate::arch::x86_64::serial::write_byte(b);
            }
        }
        return len as i64;
    }

    // VFS file descriptor
    unsafe {
        let buf = core::slice::from_raw_parts(buf_ptr as *const u8, len as usize);
        crate::fs::sys_write(fd as usize, buf)
    }
}

/// sys_read(fd, buf_ptr, len) — read bytes from a file descriptor.
/// fd=0 → keyboard (stdin), fd≥3 → VFS file read.
fn syscall_read(fd: u64, buf_ptr: u64, len: u64) -> i64 {
    if fd == 0 {
        // stdin: read one key from keyboard
        let key = crate::arch::x86_64::keyboard::poll_key();
        if let Some(ch) = key {
            if len >= 1 {
                unsafe {
                    let buf = core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len as usize);
                    buf[0] = ch as u8;
                }
                return 1;
            }
        }
        return 0;
    }

    // VFS file descriptor
    unsafe {
        let buf = core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len as usize);
        crate::fs::sys_read(fd as usize, buf)
    }
}

/// sys_open(path_ptr, path_len, flags) — open a file, returning fd.
/// flags: 0=read, 1=write, 2=read+write
fn syscall_open(path_ptr: u64, path_len: u64, flags: u64) -> i64 {
    unsafe {
        let path_bytes = core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize);
        let path = match core::str::from_utf8(path_bytes) {
            Ok(s) => s,
            Err(_) => return SyscallError::InvalidArgument as i64,
        };
        crate::fs::sys_open(path, flags)
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
    crate::core::scheduler::wait_pid(pid as crate::core::scheduler::TaskId);
    SyscallError::Success as i64
}

fn syscall_getpid() -> i64 {
    crate::core::scheduler::current_task_id() as i64
}

fn syscall_spawn(name_ptr: u64, name_len: u64, priority: u64) -> i64 {
    let name = unsafe {
        let bytes = core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize);
        match core::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return SyscallError::InvalidArgument as i64,
        }
    };

    let prio = match priority {
        0 => crate::core::scheduler::Priority::Idle,
        1 => crate::core::scheduler::Priority::Normal,
        2 => crate::core::scheduler::Priority::System,
        3 => crate::core::scheduler::Priority::RealTime,
        _ => crate::core::scheduler::Priority::Compute,
    };

    match crate::core::scheduler::spawn_named(name, prio, 0, 0, 0) {
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
// ABI: RDI=addr_hint (0=kernel_picks), RSI=size, RDX=flags
//   flags bit 0 = HUGE_PAGE (2MiB aligned allocation)
//   flags bit 1 = EXEC      (mark executable, reserved)
//
// Returns: mapped virtual address (as i64), or negative SyscallError on fail.
// Alignment: always 64-byte minimum; HUGE_PAGE requests 2MiB alignment (align=0x200000).
//
// SAFETY invariant: returned pointer is heap-allocated and must be freed via
// sys_munmap with the same size.  The caller (aai) holds a CapabilityToken{} for
// MemHuge before invoking this path (token checked at dispatch time in future).

fn syscall_mmap(_addr_hint: u64, size: u64, flags: u64) -> i64 {
    let size = size as usize;
    if size == 0 {
        return SyscallError::InvalidArgument as i64;
    }
    let huge = (flags & 1) != 0;

    if huge {
        // AI-native path: use the 2MB physical frame allocator
        if let Some(phys) = crate::mm::physical::alloc_huge_frame() {
            let virt = crate::mm::r#virtual::phys_to_virt(phys);
            
            crate::arch::x86_64::serial::write_str("[SYSCALL] Mmap(HUGE): ");
            serial_dec(crate::mm::physical::HUGE_FRAME_SIZE);
            crate::arch::x86_64::serial::write_str(" bytes @ Phys 0x");
            serial_hex(phys);
            crate::arch::x86_64::serial::write_str(" / Virt 0x");
            serial_hex(virt);
            crate::arch::x86_64::serial::write_str("\r\n");

            let current_pid = crate::core::scheduler::current_pid();
            crate::core::scheduler::add_memory_usage(current_pid, crate::mm::physical::HUGE_FRAME_SIZE);

            return virt as i64;
        } else {
            return SyscallError::OutOfMemory as i64;
        }
    }

    // 2 MiB alignment for HUGE_PAGE; 64-byte otherwise (AVX-512 native).
    let align: usize = 64;
    // Round size up to alignment boundary to avoid partial-page tails.
    let alloc_size = (size + align - 1) & !(align - 1);

    let layout = match core::alloc::Layout::from_size_align(alloc_size, align) {
        Ok(l)  => l,
        Err(_) => return SyscallError::InvalidArgument as i64,
    };

    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        crate::arch::x86_64::serial::write_str("[SYSCALL] Mmap: OOM\r\n");
        return SyscallError::OutOfMemory as i64;
    }

    crate::arch::x86_64::serial::write_str("[SYSCALL] Mmap: ");
    serial_dec(alloc_size as u64);
    crate::arch::x86_64::serial::write_str(" bytes @ 0x");
    serial_hex(ptr as u64);
    crate::arch::x86_64::serial::write_str("\r\n");

    let current_pid = crate::core::scheduler::current_pid();
    crate::core::scheduler::add_memory_usage(current_pid, alloc_size as u64);

    ptr as i64
}

/// sys_munmap(addr, size) — free a mapping previously created by sys_mmap.
/// The size must match exactly what was passed to Mmap.
fn syscall_munmap(addr: u64, size: u64) -> i64 {
    if addr == 0 || size == 0 {
        return SyscallError::InvalidArgument as i64;
    }
    let size = size as usize;
    // We can only know the alignment from size; use 64-byte minimum.
    let align: usize = if size % 0x200_000 == 0 { 0x200_000 } else { 64 };
    let alloc_size = (size + align - 1) & !(align - 1);

    let layout = match core::alloc::Layout::from_size_align(alloc_size, align) {
        Ok(l)  => l,
        Err(_) => return SyscallError::InvalidArgument as i64,
    };
    // SAFETY: addr points to memory allocated by syscall_mmap with the same layout.
    unsafe { alloc::alloc::dealloc(addr as *mut u8, layout); }

    let current_pid = crate::core::scheduler::current_pid();
    crate::core::scheduler::sub_memory_usage(current_pid, alloc_size as u64);

    SyscallError::Success as i64
}

fn syscall_ioport_in(port: u64, size: u64) -> i64 {
    if !crate::core::scheduler::has_capability(crate::core::scheduler::Capability::Device) {
        return SyscallError::PermissionDenied as i64;
    }
    
    unsafe {
        match size {
            1 => {
                let val: u8;
                core::arch::asm!("in al, dx", out("al") val, in("dx") port as u16);
                val as i64
            }
            2 => {
                let val: u16;
                core::arch::asm!("in ax, dx", out("ax") val, in("dx") port as u16);
                val as i64
            }
            4 => {
                let val: u32;
                core::arch::asm!("in eax, dx", out("eax") val, in("dx") port as u16);
                val as i64
            }
            _ => SyscallError::InvalidArgument as i64
        }
    }
}

fn syscall_ioport_out(port: u64, size: u64, val: u64) -> i64 {
    if !crate::core::scheduler::has_capability(crate::core::scheduler::Capability::Device) {
        return SyscallError::PermissionDenied as i64;
    }

    unsafe {
        match size {
            1 => {
                core::arch::asm!("out dx, al", in("dx") port as u16, in("al") val as u8);
                0
            }
            2 => {
                core::arch::asm!("out dx, ax", in("dx") port as u16, in("ax") val as u16);
                0
            }
            4 => {
                core::arch::asm!("out dx, eax", in("dx") port as u16, in("eax") val as u32);
                0
            }
            _ => SyscallError::InvalidArgument as i64
        }
    }
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

fn syscall_irq_wait(irq_num: u64) -> i64 {
    if !crate::core::scheduler::has_capability(crate::core::scheduler::Capability::Device) {
        return SyscallError::PermissionDenied as i64;
    }
    // In Phase 5, this blocks the caller until the IRQ is received by the kernel.
    // For this simulation, we yield.
    crate::core::scheduler::sys_yield();
    0
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

fn syscall_vfs_register(path_ptr: u64, path_len: u64) -> i64 {
    if !crate::core::scheduler::has_capability(crate::core::scheduler::Capability::VfsServer) &&
       !crate::core::scheduler::has_capability(crate::core::scheduler::Capability::System) {
        return SyscallError::PermissionDenied as i64;
    }

    let path = unsafe {
        let bytes = core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize);
        match core::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return SyscallError::InvalidArgument as i64,
        }
    };

    crate::arch::x86_64::serial::write_str("[VFS] Registering userspace server at ");
    crate::arch::x86_64::serial::write_str(path);
    crate::arch::x86_64::serial::write_str("\r\n");

    let current_pid = crate::core::scheduler::current_pid();

    // Allocate an SMR channel for VFS IPC
    let channel_id = crate::core::ipc::userspace_ipc::create_channel(current_pid);
    if channel_id == 0 {
        return SyscallError::OutOfMemory as i64;
    }

    crate::fs::register_userspace_fs(path, current_pid, channel_id);
    crate::core::scheduler::set_is_vfs_server(true);
    
    // Return channel_id so the server can start polling it
    channel_id as i64
}

fn syscall_dev_detach(dev_id: u64) -> i64 {
    if !crate::core::scheduler::has_capability(crate::core::scheduler::Capability::Device) {
        return SyscallError::PermissionDenied as i64;
    }
    if dev_id == 0 {
        crate::net::rtl8139::detach();
    } else if dev_id == 1 {
        crate::drivers::nvme::detach();
    }
    0
}

fn serial_hex(mut val: u64) {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    let mut i = 0;
    if val == 0 { crate::arch::x86_64::serial::write_byte(b'0'); return; }
    while val > 0 {
        buf[i] = HEX[(val & 0xF) as usize];
        val >>= 4;
        i += 1;
    }
    for j in (0..i).rev() {
        crate::arch::x86_64::serial::write_byte(buf[j]);
    }
}

// ─── SMR IPC Syscalls ────────────────────────────────────────────────────────

fn syscall_smr_create(_flags: u64) -> i64 {
    let pid = crate::core::scheduler::current_pid();
    let id = crate::core::ipc::userspace_ipc::create_channel(pid);
    if id == 0 {
        SyscallError::OutOfMemory as i64
    } else {
        id as i64
    }
}

fn syscall_smr_send(channel_id: u64, phys_addr: u64, length: u64) -> i64 {
    crate::core::ipc::userspace_ipc::send_to_channel(channel_id as u32, phys_addr, length)
}

fn syscall_smr_recv(channel_id: u64) -> i64 {
    let (addr, _len) = crate::core::ipc::userspace_ipc::recv_from_channel(channel_id as u32);
    addr as i64
}

// ─── DMA Allocation Syscall ──────────────────────────────────────────────────

fn syscall_dma_alloc(size_bytes: u64, _alignment: u64) -> i64 {
    if !crate::core::scheduler::has_capability(crate::core::scheduler::Capability::Device) &&
       !crate::core::scheduler::has_capability(crate::core::scheduler::Capability::System) {
        return SyscallError::PermissionDenied as i64;
    }

    let frames = (size_bytes + 4095) / 4096;
    match crate::mm::physical::alloc_frames(frames) {
        Some(phys) => {
            crate::arch::x86_64::serial::write_str("[DMA] Allocated ");
            serial_dec(frames);
            crate::arch::x86_64::serial::write_str(" frames at phys 0x");
            serial_hex(phys);
            crate::arch::x86_64::serial::write_str("\r\n");
            let current_pid = crate::core::scheduler::current_pid();
            crate::core::scheduler::add_memory_usage(current_pid, frames * 4096);

            phys as i64
        }
        None => SyscallError::OutOfMemory as i64,
    }
}