# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 ospab
# ospab-boot BIOS: stage1 boot sector, stage2 real-mode entry, long mode <-> real mode thunk.
# Intel syntax. Placeholders: {regs} {rmstack} {bootdrv} (see rm.rs).

# ---------------------------------------------------------------------------------------
# stage1: runs at 0x7C00. MBR of an installed disk, hybrid-ISO MBR, or El Torito boot image.
#   0x08..0x3F  El Torito boot info table (xorriso -boot-info-table fills it; bi_file at 0x0C)
#   0x40        stage2 start, in sectors of the boot drive; 0 = take it from the boot info
#               table (CD: the sector after this one)
#   0x48        size of the stage2 part in 512-byte units (set by the linker)
#   0x1BE..     partition table (installed disk: kept by the installer)
# Memory: 0x600 boot drive, 0x610 DAP, 0x630 drive parameters.
# ---------------------------------------------------------------------------------------
.section .stage1,"ax",@progbits
.code16
.global stage1
stage1:
    .byte 0xEA
    .word 0x7C00 + (s1_start - stage1)
    .word 0
    .org 8
    .skip 56, 0
    .org 0x40
    .quad 0
    .word __loaded_sectors
    .word 0
    .org 0x50
s1_start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti
    cld
    mov byte ptr [0x600], dl
    mov word ptr [0x630], 0x1E
    mov si, 0x630
    mov ah, 0x48
    int 0x13
    mov bx, 512
    jc 1f
    mov ax, word ptr [0x648]
    test ax, ax
    jz 1f
    mov bx, ax
1:
    mov cx, bx
    shr cx, 9
    movzx ecx, cx
    mov eax, dword ptr [0x7C40]
    mov edx, dword ptr [0x7C44]
    mov ebp, eax
    or ebp, edx
    jnz 2f
    mov eax, dword ptr [0x7C0C]
    inc eax
    xor edx, edx
2:
    mov dword ptr [0x618], eax
    mov dword ptr [0x61C], edx
    movzx eax, word ptr [0x7C48]
    lea eax, [eax + ecx - 1]
    xor edx, edx
    div ecx
    mov ebp, eax
    mov eax, 64
    xor edx, edx
    div ecx
    mov edi, eax
    mov word ptr [0x614], 0
    mov word ptr [0x616], 0x0800
    mov byte ptr [0x610], 16
    mov byte ptr [0x611], 0
3:
    mov eax, ebp
    cmp eax, edi
    jbe 4f
    mov eax, edi
4:
    mov word ptr [0x612], ax
    mov si, 0x610
    mov dl, byte ptr [0x600]
    mov ah, 0x42
    int 0x13
    jc s1_fail
    movzx eax, word ptr [0x612]
    sub ebp, eax
    add dword ptr [0x618], eax
    adc dword ptr [0x61C], 0
    imul eax, ecx
    shl eax, 5
    add word ptr [0x616], ax
    test ebp, ebp
    jnz 3b
    mov dl, byte ptr [0x600]
    .byte 0xEA
    .word 0x8000
    .word 0
s1_fail:
    mov si, offset s1_msg
5:
    lodsb
    test al, al
    jz 6f
    mov ah, 0x0E
    mov bx, 7
    int 0x10
    jmp 5b
6:
    hlt
    jmp 6b
s1_msg:
    .asciz "ospab-boot: cannot read stage2"
    .org 0x1B0
    .org 0x1FE
    .word 0xAA55

# ---------------------------------------------------------------------------------------
# stage2 entry, real mode. DL = boot drive. Everything in this section lives below 64 KiB.
# ---------------------------------------------------------------------------------------
.section .rm,"awx",@progbits
.code16
.global rm_entry
rm_entry:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, {rmstack}
    mov byte ptr [{bootdrv}], dl
    cld
    mov ax, 0x2401
    int 0x15
    # Some BIOSes (VMware) return from INT 15h with interrupts enabled; in long mode the
    # timer IRQ would then arrive as vector 8 (the BIOS PIC base) and look like a double fault.
    cli
    in al, 0x92
    test al, 2
    jnz 1f
    or al, 2
    and al, 0xFE
    out 0x92, al
1:
    .byte 0x66
    lgdt [gdt_ptr]
    mov eax, cr0
    or al, 1
    mov cr0, eax
    .byte 0x66, 0xEA
    .long pm_entry
    .word 0x28

.code32
pm_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov edi, offset __pagetables
    xor eax, eax
    mov ecx, 6 * 1024
    rep stosd
    mov edi, offset __pagetables
    lea eax, [edi + 0x1003]
    mov dword ptr [edi], eax
    lea eax, [edi + 0x2003]
    mov dword ptr [edi + 0x1000], eax
    add eax, 0x1000
    mov dword ptr [edi + 0x1008], eax
    add eax, 0x1000
    mov dword ptr [edi + 0x1010], eax
    add eax, 0x1000
    mov dword ptr [edi + 0x1018], eax
    lea edi, [edi + 0x2000]
    mov eax, 0x83
    mov ecx, 2048
2:
    mov dword ptr [edi], eax
    mov dword ptr [edi + 4], 0
    add eax, 0x200000
    add edi, 8
    dec ecx
    jnz 2b
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax
    mov eax, offset __pagetables
    mov cr3, eax
    mov ecx, 0xC0000080
    rdmsr
    or eax, 0x100
    wrmsr
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax
    .byte 0xEA
    .long lm_entry
    .word 0x08

.code64
lm_entry:
    cli
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov esp, offset __stack_top
    xor ebp, ebp
    movzx edi, byte ptr [{bootdrv}]
    call bios_main
7:
    hlt
    jmp 7b

# --- thunk: rm_call(int_no in edi). Registers are exchanged through the block at {regs}. ---
.global rm_call
rm_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov byte ptr [rip + rm_intop + 1], dil
    mov qword ptr [rip + rm_saved_rsp], rsp
    cli
    push 0x18
    mov eax, offset rm16_pm
    push rax
    .byte 0x48, 0xCB

.code16
rm16_pm:
    mov ax, 0x20
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov eax, cr0
    and eax, 0x7FFFFFFF
    mov cr0, eax
    mov ecx, 0xC0000080
    rdmsr
    and eax, 0xFFFFFEFF
    wrmsr
    mov eax, cr4
    and eax, 0xFFFFFFDF
    mov cr4, eax
    mov eax, cr0
    and eax, 0xFFFFFFFE
    mov cr0, eax
    .byte 0xEA
    .word rm_real
    .word 0
rm_real:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov sp, {rmstack}
    lidt [rm_idt_ptr]
    push dword ptr [{regs} + 28]
    popfd
    mov ebx, dword ptr [{regs} + 4]
    mov ecx, dword ptr [{regs} + 8]
    mov edx, dword ptr [{regs} + 12]
    mov esi, dword ptr [{regs} + 16]
    mov edi, dword ptr [{regs} + 20]
    mov ebp, dword ptr [{regs} + 24]
    mov eax, dword ptr [{regs}]
    mov es, word ptr [{regs} + 34]
    mov ds, word ptr [{regs} + 32]
    sti
    nop
rm_intop:
    .byte 0xCD, 0
    cli
    .byte 0x2E
    mov dword ptr [{regs}], eax
    .byte 0x2E
    mov dword ptr [{regs} + 4], ebx
    .byte 0x2E
    mov dword ptr [{regs} + 8], ecx
    .byte 0x2E
    mov dword ptr [{regs} + 12], edx
    .byte 0x2E
    mov dword ptr [{regs} + 16], esi
    .byte 0x2E
    mov dword ptr [{regs} + 20], edi
    .byte 0x2E
    mov dword ptr [{regs} + 24], ebp
    pushfd
    pop eax
    .byte 0x2E
    mov dword ptr [{regs} + 28], eax
    xor ax, ax
    mov ds, ax
    mov es, ax
    .byte 0x66
    lgdt [gdt_ptr]
    mov eax, cr0
    or al, 1
    mov cr0, eax
    .byte 0x66, 0xEA
    .long pm_back
    .word 0x28

.code32
pm_back:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax
    mov eax, offset __pagetables
    mov cr3, eax
    mov ecx, 0xC0000080
    rdmsr
    or eax, 0x100
    wrmsr
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax
    .byte 0xEA
    .long lm_back
    .word 0x08

.code64
lm_back:
    cli
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov rsp, qword ptr [rip + rm_saved_rsp]
    cld
    lidt [rip + ospab_idt_ptr]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.balign 8
rm_saved_rsp:
    .quad 0
rm_idt_ptr:
    .word 0x3FF
    .long 0
gdt_ptr:
    .word gdt_end - gdt - 1
    .long gdt
.balign 8
gdt:
    .quad 0
    .quad 0x00209A0000000000
    .quad 0x00CF92000000FFFF
    .quad 0x00009A000000FFFF
    .quad 0x000092000000FFFF
    .quad 0x00CF9A000000FFFF
gdt_end:

# --- CPU exceptions in long mode: print the vector and the frame, then halt. 32 stubs of 8 bytes. ---
.code64
.balign 8
.global exc_stubs
exc_stubs:
.set vec, 0
.rept 32
    .balign 8
    push vec
    jmp exc_common
    .set vec, vec + 1
.endr
exc_common:
    mov rdi, rsp
    and rsp, -16
    call exception_handler
8:
    hlt
    jmp 8b
