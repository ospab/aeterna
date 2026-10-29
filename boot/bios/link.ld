/* SPDX-License-Identifier: AGPL-3.0-only
   ospab-boot BIOS image layout (see docs/en/boot.md).

   lld lays a raw binary out by address, so the linked file has stage1 at offset 0 and
   stage2 at offset 0x400. scripts/bios-image.sh moves stage2 to offset 0x800 (the second
   2048-byte CD sector) to make bios.img.

   stage1   runs at 0x7C00
   stage2   loaded by stage1 to 0x8000, entered in real mode (.rm first, below 64 KiB)
   .bss     not in the file; lives at 2 MiB (page tables, stack, heap) */
ENTRY(rm_entry)
SECTIONS
{
    .stage1 0x7C00 : { KEEP(*(.stage1)) }

    .loaded 0x8000 :
    {
        KEEP(*(.rm))
        *(.text .text.*)
        *(.rodata .rodata.*)
        *(.data .data.*)
        *(.got .got.*)
        . = ALIGN(512);
    }

    __loaded_end = .;
    __loaded_sectors = (__loaded_end - 0x8000) / 512;

    .bss 0x200000 (NOLOAD) :
    {
        __bss_start = .;
        . = ALIGN(4096);
        __pagetables = .;
        . += 6 * 4096;
        __stack_bottom = .;
        . += 256K;
        __stack_top = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4096);
        __bss_end = .;
    }

    /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) *(.eh_frame_hdr) }
}
