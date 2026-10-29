/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Jump into the kernel with the ospab boot protocol registers (see ospab_proto.rs).
Shared by the UEFI and BIOS front-ends; both call it in 64-bit mode.
*/
core::arch::global_asm!(
    ".global ospab_handoff",
    "ospab_handoff:",
    "cli",
    "mov cr3, rcx",
    "mov rsp, r8",
    "push 0",
    "mov rax, r9",
    "xor ebx, ebx",
    "xor ecx, ecx",
    "xor ebp, ebp",
    "xor r8d, r8d",
    "xor r9d, r9d",
    "xor r10d, r10d",
    "xor r11d, r11d",
    "xor r12d, r12d",
    "xor r13d, r13d",
    "xor r14d, r14d",
    "xor r15d, r15d",
    "jmp rax",
);

extern "sysv64" {
    /// RDI = BootInfo phys, RSI = magic, RDX = HHDM, RCX = PML4, R8 = stack top, R9 = entry.
    pub fn ospab_handoff(info: u64, magic: u64, hhdm: u64, cr3: u64, stack: u64, entry: u64) -> !;
}

/// Turn on EFER.NXE (the kernel tables use NX bits), then enter the kernel.
///
/// # Safety
/// `pml4` must map this code (identity), the stack and the kernel; interrupts are disabled.
pub unsafe fn enter_kernel(info: u64, magic: u64, hhdm: u64, pml4: u64, stack_top: u64, entry: u64) -> ! {
    let (lo, hi): (u32, u32);
    core::arch::asm!("rdmsr", in("ecx") 0xC000_0080u32, out("eax") lo, out("edx") hi);
    core::arch::asm!("wrmsr", in("ecx") 0xC000_0080u32, in("eax") lo | (1 << 11), in("edx") hi);
    ospab_handoff(info, magic, hhdm, pml4, stack_top, entry)
}
