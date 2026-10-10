# Architecture

ospab.os is in transition from a monolithic kernel to a microkernel. This page describes the
system as it is now and marks what is still to move. The plan is in [ROADMAP.md](../../ROADMAP.md).

## Boot flow

1. **Firmware → loader.** Either Limine (ISO, BIOS and UEFI) or **ospab-boot** (installed disks,
   disk images, the test entry on the ISO). ospab-boot reads its config `ospab.cfg`, shows a menu,
   loads the kernel ELF and modules from FAT or ISO9660, sets up page tables, takes the memory map
   and framebuffer from UEFI and jumps to the kernel.
2. **Boot contract.** The kernel accepts both loaders. ospab-boot passes a `BootInfo` structure
   (`arch/x86_64/boot/ospab_proto.rs`: physical addresses only, no UEFI types) with the magic
   `OSPABOOT` in RSI; Limine passes zeroed registers and its own request structures.
   `arch/x86_64/boot/mod.rs` hides the difference from the rest of the kernel.
3. **Kernel start** (`src/main.rs`): CPU tables, interrupts, timers and the clock; memory
   (frames, heap, paging); ACPI; PCI; scheduler and system calls; filesystem; storage and
   persistence; USB, GPU, audio, NVMe; network; shell; ring-3 self-test; console.

## Address space

| Range | Contents |
|---|---|
| `0x0000_0000_0040_0000` | user program image (static ELF linked at 4 MiB) |
| user stack and `mmap` area | per process |
| `0xFFFF_8000_0000_0000` | direct map of physical memory (HHDM) |
| `0xFFFF_FFFF_8020_0000` | kernel image |

Every process has its own page tables; the kernel half is shared and marked supervisor-only.
Pages owned by a process are freed when it exits. SMEP and SMAP are enabled when the CPU has them;
the kernel touches user memory only through `copy_from_user` / `copy_to_user`, which turn a bad
pointer into an error instead of a crash.

## Rings and entry

- **System calls** use `SYSCALL`/`SYSRET`. The entry stub switches to the current task's kernel
  stack through GS.
- **Interrupts** from ring 3 take the kernel stack from `TSS.RSP0`, which the scheduler updates on
  every switch.
- **Exceptions** in a ring-3 task kill that task, not the kernel.

## Scheduling

Preemptive, driven by the PIT (100 Hz) and the local APIC timer. Each task has its own kernel
stack and FPU/SIMD area; the context switch uses XSAVE when available (with AVX state) and FXSAVE
otherwise. Blocking calls park the task until it is woken or its deadline passes.

## Kernel objects, handles and IPC

Objects: Process, Thread, Channel, Notification, Reply. Each process has a handle table; a handle
carries rights (read, write, duplicate, transfer) and a generation, so stale handles are refused.

- **Synchronous IPC:** `call` sends a message (up to 128 bytes and 4 handles) and blocks for the
  reply; the server receives it with `recv` together with a one-shot Reply object.
- **One-way send** into a short queue, and **notifications** (a 32-bit signal mask).
- Handles move between processes inside messages, only with the transfer right.

Numbers and registers: [System call ABI](syscall-abi.md). The safe Rust API is in
`user/liboos/src/ipc.rs`.

Next on the roadmap: shared memory objects, and interrupts, I/O ports and device memory as
handles, so that drivers and the GUI compositor can run as ring-3 servers.

## What still runs in ring 0

The shell and coreutils, all drivers, the network stack, the filesystem and the console run inside
the kernel today. Programs installed from packages run in ring 3 as separate processes.

## Filesystem and persistence

The root is a copy-on-write overlay: a read-only base layer with the system files and a writable
upper layer. The upper layer is serialized to the `AETERNA` partition by `sync` and automatically
after changes. `/proc` and `/sys` are virtual.

## Time

The system clock is a signed 64-bit count of nanoseconds since **2012-08-09 00:00:00 UTC** (the
ospab epoch). It is seeded from the CMOS RTC, corrected by NTP, and advanced by the TSC. Unix time
is used only at the edges: NTP, TLS, HTTP and file systems.
