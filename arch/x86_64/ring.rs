/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Ring transition helpers for AETERNA microkernel.

Milestone 1 — clean ring-3 round trip.

The ring-3 task is registered with the scheduler as an ordinary `Ready` task
whose saved frame carries USER_CS/USER_DS. The first preemption context-switch
(`scheduler::on_timer_irq`) therefore drops into ring 3 via `iretq` — we never
hand-roll the privilege transition here. When the task calls `exit`, the
scheduler simply switches back to the kernel's own (slot-0) context, so the
kernel keeps running normally afterwards.
*/

use crate::arch::x86_64::serial;

/// Virtual address where the user code page is mapped in the task's address space.
const USER_CODE_BASE: u64 = 0x0000_0000_0040_0000;
/// Top of the user stack (one page mapped just below this).
const USER_STACK_TOP: u64 = 0x0000_0000_0080_0000;

/// Minimal ring-3 program (Milestone 1 smoke test).
///
/// Self-contained: touches no memory, only registers — so it works regardless
/// of which virtual address it is mapped at and needs no user-mapped .rodata.
///
///   1. `getpid` (syscall 22) → returns our PID in RAX (proves SYSRET return value)
///   2. `exit(pid)` (syscall 0) → kernel logs `[SYSCALL] exit(<pid>)` and reaps us
///
/// Seeing `exit(<pid>)` on the serial log *and* the kernel continuing to the
/// terminal proves the full ring0→ring3→syscall→ring0 chain is sound.
#[unsafe(naked)]
pub unsafe extern "C" fn ring3_smoke_entry() -> ! {
    core::arch::naked_asm!(
        "mov rax, 22",   // SyscallNumber::GetPid
        "syscall",       // → RAX = current pid
        "mov rdi, rax",  // exit code = pid
        "mov rax, 0",    // SyscallNumber::Exit
        "syscall",       // does not return
        "ud2",           // trap if it somehow does
    );
}

/// Exit code a stress task reports when it detects corrupted state.
pub const STRESS_FAIL_CODE: u64 = 0xBAD;

/// Ring-3 stress program: checks that per-task kernel stacks and FPU/SSE state
/// survive preemption and blocking syscalls while another ring-3 task runs.
///
/// Keeps its PID in r12 and xmm0, spins long enough to be preempted many times,
/// and after each spin verifies both and makes a syscall. Then it blocks in
/// `waitpid(pid + 1)` — for the first of two tasks spawned back to back that is
/// the second one, so it sleeps *inside the kernel* while the other keeps making
/// syscalls. Exits with its PID on success, `STRESS_FAIL_CODE` on any mismatch.
#[unsafe(naked)]
pub unsafe extern "C" fn ring3_stress_entry() -> ! {
    core::arch::naked_asm!(
        "mov rax, 22",          // getpid
        "syscall",
        "mov r12, rax",         // r12 = pid (callee-saved: kernel must preserve it)
        "movq xmm0, rax",       // xmm0 = pid (must survive context switches)
        "shl rax, 6",           // give each task a different user RSP, so a mixed-up
        "sub rsp, rax",         // kernel stack returns us to the other task's RSP
        "mov r14, rsp",         // r14 = expected RSP after every syscall
        "mov r13, 10",          // iterations, ~20 ms each
        "2:",
        // Spin until the uptime counter (100 Hz) moves by 2 ticks. A fixed pause
        // count is not enough: under QEMU TCG it finishes within one 1 ms time slice
        // and the two tasks would never be preempted mid-loop.
        "mov rax, 51",          // uptime
        "syscall",
        "lea r15, [rax + 2]",
        "3:",
        "mov rcx, 10000",
        "4:",
        "pause",
        "dec rcx",
        "jnz 4b",
        "mov rax, 51",
        "syscall",
        "cmp rax, r15",
        "jb 3b",
        "movq rax, xmm0",
        "cmp rax, r12",
        "jne 9f",
        "mov rax, 22",          // getpid again: return value must still be ours
        "syscall",
        "cmp rax, r12",
        "jne 9f",
        "cmp rsp, r14",
        "jne 9f",
        "dec r13",
        "jnz 2b",
        "lea rdi, [r12 + 1]",   // waitpid(pid + 1): blocks in the kernel if that task lives
        "mov rax, 32",
        "syscall",
        "cmp rsp, r14",
        "jne 9f",
        "movq rax, xmm0",
        "cmp rax, r12",
        "jne 9f",
        "mov rdi, r12",         // exit(pid): success
        "mov rax, 0",
        "syscall",
        "ud2",
        "9:",
        "mov rdi, {fail}",      // exit(0xBAD): state was corrupted
        "mov rax, 0",
        "syscall",
        "ud2",
        fail = const STRESS_FAIL_CODE,
    );
}

/// Exit code of the user-copy test on success.
pub const USERCOPY_OK_CODE: u64 = 0x600D;

/// Ring-3 program checking that the kernel validates user pointers and that
/// mmap/munmap work on the caller's own address space.
#[unsafe(naked)]
pub unsafe extern "C" fn ring3_usercopy_entry() -> ! {
    core::arch::naked_asm!(
        // write(1, <kernel address>, 4) must fail with BadAddress (-10)
        "mov rdi, 1",
        "mov rsi, 0xFFFF800000000000",
        "mov rdx, 4",
        "mov rax, 1",
        "syscall",
        "cmp rax, -10",
        "jne 9f",
        // write(1, <unmapped user address>, 4) must fail the same way, not panic
        "mov rdi, 1",
        "mov rsi, 0x100000000",
        "mov rdx, 4",
        "mov rax, 1",
        "syscall",
        "cmp rax, -10",
        "jne 9f",
        // mmap(0, 4096, 0) -> a fresh writable page
        "xor edi, edi",
        "mov rsi, 4096",
        "xor edx, edx",
        "mov rax, 40",
        "syscall",
        "test rax, rax",
        "js 9f",
        "jz 9f",
        "mov r12, rax",
        "mov byte ptr [r12], 0x6F",     // 'o'
        "mov byte ptr [r12 + 1], 0x6B", // 'k'
        "mov byte ptr [r12 + 2], 0x0A", // '\n'
        // write(1, page, 3) must succeed and print "ok"
        "mov rdi, 1",
        "mov rsi, r12",
        "mov rdx, 3",
        "mov rax, 1",
        "syscall",
        "cmp rax, 3",
        "jne 9f",
        // munmap(page, 4096) -> 0
        "mov rdi, r12",
        "mov rsi, 4096",
        "mov rax, 41",
        "syscall",
        "test rax, rax",
        "jnz 9f",
        "mov rdi, {ok}",
        "mov rax, 0",
        "syscall",
        "ud2",
        "9:",
        "mov rdi, {fail}",
        "mov rax, 0",
        "syscall",
        "ud2",
        ok = const USERCOPY_OK_CODE,
        fail = const STRESS_FAIL_CODE,
    );
}

/// Spawn the user-copy test task.
pub fn launch_ring3_usercopy_test() -> Option<u32> {
    launch_embedded("ring3-usercopy", ring3_usercopy_entry as *const () as u64)
}

/// Prepare a ring-3 smoke task and hand it to the scheduler.
///
/// Returns the new task's PID on success. The task does not run synchronously —
/// it starts on the next preemption tick and the kernel continues immediately.
pub fn launch_ring3_smoke_test() -> Option<u32> {
    launch_embedded("ring3-smoke", ring3_smoke_entry as *const () as u64)
}

/// Spawn two ring-3 stress tasks back to back (see `ring3_stress_entry`).
pub fn launch_ring3_stress_test() -> Option<(u32, u32)> {
    // The kernel thread runs at Idle priority, so without this the first task would
    // run to completion before the second one even exists, and they would never overlap.
    crate::core::scheduler::set_preemption_disabled(true);
    let a = launch_embedded("ring3-stress-a", ring3_stress_entry as *const () as u64);
    let b = launch_embedded("ring3-stress-b", ring3_stress_entry as *const () as u64);
    crate::core::scheduler::set_preemption_disabled(false);
    Some((a?, b?))
}

/// Map a naked function from kernel text into a fresh address space and spawn it in ring 3.
fn launch_embedded(name: &str, entry_addr: u64) -> Option<u32> {
    use crate::mm::r#virtual as vmm;

    if !vmm::is_initialized() {
        serial::write_str("[RING] VMM not initialized\r\n");
        return None;
    }

    // Fresh address space (kernel upper-half mirrored, user lower-half empty).
    let pml4 = match vmm::create_address_space() {
        Some(p) => p,
        None => {
            serial::write_str("[RING] Failed to allocate user address space\r\n");
            return None;
        }
    };

    // Locate the physical frame backing the smoke entry in kernel memory.
    // (Milestone 1 reuses the kernel code page mapped USER; Milestone 2's ELF
    // loader will copy real user code into freshly-allocated user frames.)
    let code_page_virt = entry_addr & !0xFFFu64;
    let code_page_phys = match vmm::translate_current(code_page_virt) {
        Some(p) => p & !0xFFFu64,
        None => {
            serial::write_str("[RING] Failed to translate smoke entry page\r\n");
            return None;
        }
    };
    let entry_offset = entry_addr & 0xFFFu64;

    // Allocate and zero a user stack frame.
    let stack_phys = match crate::mm::physical::alloc_frame() {
        Some(p) => p,
        None => {
            serial::write_str("[RING] Failed to allocate user stack frame\r\n");
            return None;
        }
    };
    unsafe {
        core::ptr::write_bytes(vmm::phys_to_virt(stack_phys) as *mut u8, 0, 4096);
    }

    // Map two code pages (entry may sit near a page boundary) read+exec for ring 3,
    // and one writable stack page.
    let code_ok = vmm::map_page(pml4, USER_CODE_BASE, code_page_phys, vmm::FLAG_USER)
        && vmm::map_page(
            pml4,
            USER_CODE_BASE + 0x1000,
            code_page_phys + 0x1000,
            vmm::FLAG_USER,
        );
    let stack_ok = vmm::map_page(
        pml4,
        USER_STACK_TOP - 0x1000,
        stack_phys,
        vmm::FLAG_USER | vmm::FLAG_WRITABLE | vmm::FLAG_OWNED, // stack frame is freed with the space
    );
    if !code_ok || !stack_ok {
        serial::write_str("[RING] Failed to map user pages\r\n");
        return None;
    }

    // Make sure kernel upper-half entries are current in the new PML4.
    vmm::sync_kernel_mappings(pml4);

    let user_entry = USER_CODE_BASE + entry_offset;
    let user_stack = USER_STACK_TOP - 16; // 16-byte aligned headroom

    // Minimal manifest: Serial is enough for the smoke test (and exercises the
    // capability check path); getpid/exit need no capability.
    let caps = alloc::vec![crate::core::scheduler::Capability::Serial];

    let pid = crate::core::scheduler::spawn_user_task(
        name,
        crate::core::scheduler::Priority::Normal,
        pml4,
        user_entry,
        user_stack,
        caps,
    );

    match pid {
        Some(p) => {
            serial::write_str("[RING] Ring-3 task ");
            serial::write_str(name);
            serial::write_str(" spawned (pid ");
            crate::arch::x86_64::init::serial_dec(p as u64);
            serial::write_str("), entry=0x");
            crate::arch::x86_64::init::serial_hex(user_entry);
            serial::write_str("\r\n");
        }
        None => serial::write_str("[RING] Failed to spawn ring-3 task\r\n"),
    }
    pid
}
