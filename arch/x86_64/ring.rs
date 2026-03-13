/*
Business Source License 1.1
Copyright (c) 2026 ospab
Ring transition helpers for AETERNA microkernel.
*/

use core::arch::naked_asm;
use crate::arch::x86_64::gdt_simple;
use crate::arch::x86_64::serial;

const USER_CODE_BASE: u64 = 0x0000_0000_0040_0000;
const USER_STACK_TOP: u64 = 0x0000_0000_0080_0000;

#[unsafe(naked)]
pub unsafe extern "C" fn ring3_smoke_entry() -> ! {
    naked_asm!(
        "mov rax, 22",
        "syscall",
        "mov rax, 0",
        "xor rdi, rdi",
        "syscall",
        "ud2",
    );
}

/// Switch from Ring 0 to Ring 3 using iretq.
///
/// # Safety
/// - `entry` must point to executable user-mapped code.
/// - `user_stack` must point to writable user-mapped memory.
/// - Caller must ensure current address space has USER mappings for both.
#[unsafe(naked)]
pub unsafe extern "C" fn switch_to_ring3(entry: u64, user_stack: u64) -> ! {
    naked_asm!(
        "mov ax, {user_ds}",
        "mov ds, ax",
        "mov es, ax",
        "push {user_ds}",
        "push rsi",
        "pushfq",
        "or qword ptr [rsp], 0x200",
        "push {user_cs}",
        "push rdi",
        "iretq",
        "2:",
        "ud2",
        user_ds = const gdt_simple::USER_DS,
        user_cs = const gdt_simple::USER_CS,
    );
}

pub fn launch_ring3_smoke_test() -> bool {
    if !crate::mm::r#virtual::is_initialized() {
        serial::write_str("[RING] VMM not initialized\r\n");
        return false;
    }

    let pml4 = match crate::mm::r#virtual::create_address_space() {
        Some(p) => p,
        None => {
            serial::write_str("[RING] Failed to allocate user address space\r\n");
            return false;
        }
    };

    let entry_addr = ring3_smoke_entry as *const () as u64;
    let code_page_virt = entry_addr & !0xFFFu64;
    let code_page_phys = match crate::mm::r#virtual::translate_current(code_page_virt) {
        Some(p) => p & !0xFFFu64,
        None => {
            serial::write_str("[RING] Failed to translate smoke entry page\r\n");
            return false;
        }
    };
    let entry_offset = entry_addr & 0xFFFu64;

    let stack_phys = match crate::mm::physical::alloc_frame() {
        Some(p) => p,
        None => {
            serial::write_str("[RING] Failed to allocate user stack frame\r\n");
            return false;
        }
    };

    let stack_virt = crate::mm::r#virtual::phys_to_virt(stack_phys) as *mut u8;
    unsafe {
        core::ptr::write_bytes(stack_virt, 0, 4096);
    }

    let code_ok = crate::mm::r#virtual::map_page(
        pml4,
        USER_CODE_BASE,
        code_page_phys,
        crate::mm::r#virtual::FLAG_USER,
    );
    let stack_ok = crate::mm::r#virtual::map_page(
        pml4,
        USER_STACK_TOP - 0x1000,
        stack_phys,
        crate::mm::r#virtual::FLAG_USER | crate::mm::r#virtual::FLAG_WRITABLE,
    );

    if !code_ok || !stack_ok {
        serial::write_str("[RING] Failed to map user pages\r\n");
        return false;
    }

    crate::mm::r#virtual::sync_kernel_mappings(pml4);

    serial::write_str("[RING] Switching to Ring 3 smoke task via iretq\r\n");

    unsafe {
        crate::mm::r#virtual::switch_address_space(pml4);
        switch_to_ring3(USER_CODE_BASE + entry_offset, USER_STACK_TOP - 16);
    }
}
