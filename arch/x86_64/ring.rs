/*
Business Source License 1.1
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

/// Prepare a ring-3 smoke task and hand it to the scheduler.
///
/// Returns the new task's PID on success. The task does not run synchronously —
/// it starts on the next preemption tick and the kernel continues immediately.
pub fn launch_ring3_smoke_test() -> Option<u32> {
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
    let entry_addr = ring3_smoke_entry as *const () as u64;
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
        vmm::FLAG_USER | vmm::FLAG_WRITABLE,
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
        "ring3-smoke",
        crate::core::scheduler::Priority::Normal,
        pml4,
        user_entry,
        user_stack,
        caps,
    );

    match pid {
        Some(p) => {
            serial::write_str("[RING] Ring-3 smoke task spawned (pid ");
            crate::arch::x86_64::init::serial_dec(p as u64);
            serial::write_str("), entry=0x");
            crate::arch::x86_64::init::serial_hex(user_entry);
            serial::write_str("\r\n");
        }
        None => serial::write_str("[RING] Failed to spawn ring-3 task\r\n"),
    }
    pid
}
