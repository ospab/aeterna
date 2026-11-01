# Architecture

ospab.os is moving from a monolithic kernel to a microkernel. This page describes the
system as it is now and marks what is still to move. The plan is in [ROADMAP.md](../../ROADMAP.md).

## Boot flow

1. Firmware to loader. ospab-boot is the only loader. It has a BIOS and a UEFI front-end
   (`boot/bios`, `boot/uefi`, shared code in `boot/common`). It reads its config `ospab.cfg`, shows
   a menu, loads the kernel ELF and modules from FAT or ISO9660 and sets up page tables. It takes
   the memory map and framebuffer (GOP or VBE) from the firmware and jumps to the kernel. See
   [Boot](boot.md).
2. Boot contract. Both front-ends pass a `BootInfo` structure
   (`arch/x86_64/boot/ospab_proto.rs`: physical addresses only, no firmware types) with the magic
   `OSPABOOT` in RSI. The kernel boots only this way. `arch/x86_64/boot/` turns it into the types
   the rest of the kernel uses (`types.rs`).
3. Kernel start (`src/main.rs`), in this order: CPU tables, interrupts, timers and the clock;
   memory (frames, heap, paging); ACPI; PCI; scheduler and system calls; filesystem; storage and
   persistence; USB, GPU, audio, NVMe; network; shell; ring-3 self-test; console.

## Address space

| Range | Contents |
|---|---|
| `0x0000_0000_0040_0000` | user program image (static ELF linked at 4 MiB) |
| user stack and `mmap` area | per process |
| `0xFFFF_8000_0000_0000` | direct map of physical memory (HHDM) |
| `0xFFFF_FFFF_8020_0000` | kernel image |

Every process has its own page tables. The kernel half is shared and marked supervisor-only.
Pages owned by a process are freed when it exits. SMEP and SMAP are on when the CPU has them. The
kernel touches user memory only through `copy_from_user` and `copy_to_user`, which turn a bad
pointer into an error instead of a crash.

## Rings and entry

- System calls use `SYSCALL`/`SYSRET`. The entry stub switches to the current task's kernel stack
  through GS.
- Interrupts from ring 3 take the kernel stack from `TSS.RSP0`, which the scheduler updates on
  every switch.
- An exception in a ring-3 task kills that task, not the kernel.

## Scheduling

The scheduler is preemptive and runs off the PIT (100 Hz) and the local APIC timer. Each task has
its own kernel stack and FPU/SIMD area. The context switch uses XSAVE when available (with AVX
state) and FXSAVE otherwise. A blocking call parks the task until it is woken or its deadline
passes.

## Kernel objects, handles and IPC

The objects are Process, Thread, Channel, Notification and Reply. Each process has a handle table.
A handle carries rights (read, write, duplicate, transfer) and a generation, so stale handles are
refused.

- Synchronous IPC: `call` sends a message (up to 128 bytes and 4 handles) and blocks for the
  reply. The server gets the message from `recv` together with a one-shot Reply object.
- One-way send goes into a short queue. Notifications are a 32-bit signal mask.
- Handles move between processes inside messages, and only with the transfer right.

Numbers and registers are in [System call ABI](syscall-abi.md). The safe Rust API is in
`user/liboos/src/ipc.rs`.

Next on the roadmap: shared memory objects, and interrupts, I/O ports and device memory as
handles. With those, drivers and the GUI compositor can run as ring-3 servers.

## What still runs in ring 0

The shell and coreutils, all drivers, the network stack, the filesystem and the console run inside
the kernel today. Programs installed from packages run in ring 3 as separate processes.

## Filesystem and persistence

The root is a copy-on-write overlay: a read-only base layer with the system files and a writable
upper layer. With an `AETERNA` partition the upper layer is an AeternaFS v2 volume
([aeternafs.md](aeternafs.md)): a copy-on-write filesystem with checksums and atomic commits, over
the AHCI, NVMe, virtio-blk or ATA driver. Changes are committed a few seconds after the last write,
by `sync`, and before reboot or power-off; after a power cut the volume mounts at the last commit.
Without a disk (live ISO) the upper layer is a RamFS. `/proc` and `/sys` are virtual.

## Time

The system clock is a signed 64-bit count of nanoseconds since 2012-08-09 00:00:00 UTC (the
ospab epoch). It starts from the CMOS RTC, NTP corrects it and the TSC advances it. Unix time
appears only at the edges: NTP, TLS, HTTP and file systems.
