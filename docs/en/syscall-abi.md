# System call ABI: objects, handles, IPC

Implementation: `core/object.rs` (logic), `core/syscall/objects.rs` (glue); program wrappers are
in `user/liboos/src/ipc.rs` (IPC), `user/liboos/src/mem.rs` (memory regions) and
`user/liboos/src/hw.rs` (interrupts, I/O ports, DMA). Other calls (write, mmap, ...) are in `core/syscall/mod.rs`.

## Convention

`SYSCALL`: number in `RAX`, arguments in `RDI, RSI, RDX, R10, R8`, result in `RAX`.
`RCX` and `R11` are clobbered. A negative result is an error:

| Code | Name | Meaning |
|---|---|---|
| -1 | InvalidSyscall | no such call |
| -2 | PermissionDenied | the handle lacks a required right |
| -3 | InvalidArgument | bad argument (length > 128, duplicate handle, ...) |
| -5 | Busy | the channel queue is full |
| -6 | OutOfMemory | no frames, no free virtual range, object table full |
| -7 | NotSupported | the object cannot do this (e.g. `mem_phys` of anonymous memory) |
| -9 | NoSuchProcess | |
| -10 | BadAddress | pointer outside the process address space |
| -11 | BadHandle | value not in the table (never issued, closed or stale) |
| -12 | WrongType | the handle refers to an object of another type |
| -13 | PeerClosed | the other side is gone (channel closed, Reply dropped) |
| -14 | TableFull | the process handle table is full (256) |
| -15 | Timeout | the wait timed out |

## Handles and rights

A handle is a `u32`: `(generation << 16) | (slot + 1)`; 0 is invalid. A closed slot gets a new
generation, so an old value is refused (`BadHandle`) even if the slot is reused. Handles given by
the kernel before a program starts get the values 1, 2, 3... in the order they were granted.

Rights: `READ`=1 (receive, wait), `WRITE`=2 (call, send, signal, reply, kill), `DUP`=4 (may be
duplicated), `TRANSFER`=8 (may be sent in a message). Memory objects add `MAP`=16 (may be
mapped), `EXEC`=32 (may be mapped executable; not handed out by any call yet) and `PHYS`=64 (the
physical address may be read). A duplicate can only lose rights.

Objects: **Process**, **Thread** (one thread per process for now), **Channel**, **Notification**,
**Reply** (the right to answer one call; created by the kernel on `call` and handed to the
receiver in `recv`), **MemoryRegion**, **MmioRegion**, **Interrupt**, **IoPortRange**,
**Resource** (see below). An object lives while at least one handle or in-flight message refers to it.
When a process exits all its handles are closed, objects are freed and waiters are woken.

## Message

160 bytes: `tag: u64`, `len: u32` (≤ 128), `nhandles: u32` (≤ 4), `handles: [u32; 4]`,
`data: [u8; 128]`. Handles in a message are **moved** (removed from the sender, the `TRANSFER`
right is required); the receiver gets new values, and on return `handles[]` holds the values in
the receiver's table.

## Calls

| No. | Call | Arguments → result |
|---|---|---|
| 200 | handle_close | h → 0 |
| 201 | handle_dup | h, rights → new h (needs DUP) |
| 202 | handle_info | h → type \| rights<<8 (1 Process, 2 Thread, 3 Channel, 4 Notification, 5 Reply, 6 MemoryRegion, 7 MmioRegion, 8 Interrupt, 9 IoPortRange, 10 Resource) |
| 210 | channel_create | → h (all rights) |
| 211 | ipc_call | ch (WRITE), req*, reply* → reply.len; sleeps until the server replies |
| 212 | ipc_send | ch (WRITE), msg* → 0; one-way, does not block |
| 213 | ipc_recv | ch (READ), msg*, timeout → Reply handle (0 for one-way messages); sleeps until a request arrives |
| 214 | ipc_reply | reply_h (WRITE), msg* → 0; the Reply handle is consumed |
| 220 | notify_create | → h |
| 221 | notify_signal | h (WRITE), bits → 0 (OR into a 32-bit word) |
| 222 | notify_wait | h (READ), timeout → bits (≠ 0); the word is cleared |
| 230 / 231 | process_self / thread_self | → h (all rights) |
| 232 | process_wait | h (READ), code*, timeout → 0; the exit code is written to `code*` |
| 233 | process_kill | h (WRITE) → 0 (a process cannot kill itself; use exit) |
| 240 | mem_create | size → h (READ\|WRITE\|MAP\|DUP\|TRANSFER); zeroed pages, size rounded up, ≤ 64 MiB |
| 241 | mem_map | h (MAP+READ, +WRITE, +EXEC), hint, prot → address of the mapping |
| 242 | mem_unmap | addr (exactly what mem_map returned) → 0 |
| 243 | mem_create_contig | resource (DMA, WRITE), size → h (as mem_create + PHYS); contiguous, ≤ 4 MiB |
| 244 | mem_phys | h (PHYS) → physical address (contiguous and MMIO regions) |
| 245 | mem_size | h → size in bytes |
| 250 | irq_bind | irq (READ), notification (WRITE), bits → 0 |
| 251 | irq_ack | irq (WRITE) → 0; unmasks the line |
| 252 | ioport_enable | h (READ+WRITE) → 0; the ports become accessible to IN/OUT |
| 253 | ioport_disable | h → 0 |

`timeout` is in 100 Hz ticks; 0 waits forever. Waiting does not spin: the task becomes Waiting,
the CPU halts, and the other side (or the deadline) wakes it. When no handle with `READ` is left on
a channel, the channel closes and every pending `call` gets `PeerClosed`.

## Files and standard streams

Per-process descriptor table (`core/fd.rs`, see [Kernel internals](kernel.md)). Numbers are
unchanged:

| No. | Call | Arguments → result |
|---|---|---|
| 0 | exit | code |
| 1 | write | fd, buf*, len → bytes written |
| 2 | read | fd, buf*, len → bytes read, 0 at end of input |
| 3 | open | path*, path_len, flags (0 read, 1 write/create, 2 read+write) → fd ≥ 3 |
| 4 | close | fd → 0 |
| 5 | seek | fd, offset, whence (0 set, 1 current, 2 end) → new offset |

fd 0, 1 and 2 exist in every process and cannot be closed. Descriptors are private to the
process and are closed when it exits; at most 64 per process. `read(0)` on the console blocks
for a typed line (echo, Backspace, Ctrl+D = end of input; Ctrl+C makes the shell kill the
program). A closed or unknown descriptor returns -1. The filesystem calls need the FsRead and
FsWrite capabilities.

## Shared memory (stage 2, item 12)

A **MemoryRegion** is a set of physical pages owned by the kernel object. `mem_create` makes an
anonymous region; the handle is passed to another process in a message (usually a duplicate with
fewer rights). Each process maps it with `mem_map` and sees the other's writes.

- `prot` for `mem_map`: `READ`=1, `WRITE`=2, `EXEC`=4. `READ` is required; `WRITE|EXEC` together
  is refused (W^X) with `InvalidArgument`. Rights needed: `MAP`+`READ`, plus `WRITE` for a
  writable mapping and `EXEC` for an executable one. **Pages are no-execute by default**; `EXEC`
  is granted by no call yet, so shared memory is never executable. A process that writes through
  a read-only mapping gets a page fault and is killed.
- `hint` is reserved (pass 0): the kernel picks the address in the process's mmap area.
- The whole region is mapped; `mem_unmap` takes exactly the address `mem_map` returned (partial
  unmaps are not supported).
- A mapping holds its own reference: closing the handle does not unmap. The pages are freed when
  the last handle is closed **and** the last mapping is gone. Process exit closes the handles and
  drops the mappings.
- Removed: the old SMR mechanism (calls 120–122, raw physical addresses with no owner),
  `dma_alloc` (130), which returned a physical address to ring 3, raw port I/O (60/61),
  `irq_wait` (62) and `vfs_register` (100).

**DMA.** `mem_create_contig(resource, size)` allocates physically contiguous pages and the handle
carries `PHYS`; `mem_phys` returns the address to program into a device. Only a process with a
**Resource** handle of kind DMA (with `WRITE`) can do this; a duplicate without `PHYS` can be
handed to clients so they do not learn the address.

## Hardware as handles (stage 2, item 13)

Interrupt, IoPortRange, MmioRegion and Resource objects cannot be created by any system call. They
are made only by the privileged root (today the kernel boot code, `core::object::kernel_new_*`;
later `seed`) and given to a driver as bootstrap handles (`core::elf::spawn_with_handles`).

- **Interrupt**: a legacy (8259) IRQ line, currently only 3, 6 or 8 (lines no kernel driver
  uses); one object per line; MSI is not supported yet. After `irq_bind` every interrupt **masks
  the line**, ORs `bits` into the notification and wakes its waiter; the kernel sends EOI. The
  driver services the device and calls `irq_ack`, which unmasks the line. The line is masked from
  creation until the first `irq_ack`, and again when the object goes away.
- **IoPortRange**: ports `[base, base+count)`. Mechanism: the **I/O permission bitmap in the
  TSS**. `IOPL` stays 0; `ioport_enable` builds the process's bitmap (one bit per port, 1 =
  denied) and the scheduler copies it into the TSS on a switch to that process (only the bytes in
  use, and only when another process's bitmap is loaded). For processes without ports the bitmap
  is switched off (`iopb_offset` beyond the TSS limit), so any IN/OUT raises #GP and the process
  is killed. Port access itself costs nothing (no system call per access). Like a mapping, an
  enabled range holds a reference and lasts until `ioport_disable` or exit.
- **MmioRegion**: a device physical range (e.g. a PCI BAR); `mem_map` works on it as on a
  MemoryRegion, but the pages are mapped **uncached** (PCD|PWT) and never freed. RAM managed by
  the frame allocator cannot be wrapped as MMIO.
- **Resource**: authority to create special objects; kind DMA allows `mem_create_contig`.

Tests: boot with the kernel parameter `selftest=mem` (`user/memtest`, `user/uartdrv`). The COM2
driver (`uartdrv`) needs a second serial port in QEMU: `-serial file:com1.log -serial file:com2.log`.

## Screen, keyboard, clock (games and emulators)

Implementation: `core/syscall/screen.rs`; wrappers in `user/liboos/src/screen.rs`. The program
needs the Framebuf capability (the shell gives it to every program it starts).

| No. | Call | Arguments → result |
|---|---|---|
| 21 | sleep_ms | ms → 0; the task really sleeps (the shell and other tasks run), at least `ms`, woken by the 100 Hz tick, so up to 10 ms late |
| 260 | screen_acquire | info* → 0 |
| 261 | screen_release | → 0 |
| 262 | screen_flush | → 0; the caller must own the screen |
| 263 | kbd_mode | raw (0 or 1) → 0 |
| 264 | kbd_event | → event, 0 if the queue is empty |
| 270 | clock_ns | → monotonic nanoseconds since boot |

**screen_acquire.** Maps the boot framebuffer into the caller (read/write, no-execute, uncached,
as an MmioRegion mapping) and writes 32 bytes to `info*`: `addr: u64`, `width: u32`,
`height: u32`, `pitch: u32` (bytes per line), `bpp: u32`, `red_shift`, `green_shift`,
`blue_shift` (one byte each), one pad byte. `addr` already includes the offset inside the first
page. From now on the kernel console keeps its text in the shadow buffer but draws no pixels
(`arch/x86_64/framebuffer.rs`, `screen_held`). Only one process can own the screen: a second
caller gets -5 (Busy). -2 without the Framebuf capability, -7 without a framebuffer.
`screen_release` gives it back and the console repaints from its shadow; the mapping then stays
until the process exits but must not be used. When the owner exits or is killed the kernel
releases the screen itself (scheduler teardown, `screen::process_gone`).

**screen_flush.** On VMware SVGA II a framebuffer write is not shown until an update command is
sent; this call sends one for the whole screen. Call it once per frame. It does nothing on
plain framebuffers.

**kbd_mode / kbd_event.** In raw mode the program gets PC set-1 scancodes as events instead of
the console line discipline (`core/stdin.rs`). Event value: bits 0..7 the scancode (1..0x7F),
bit 8 set if the key had the 0xE0 prefix, bit 9 set for a release. 0 means no event. Only one
process can be in raw mode (another caller gets -5). The kernel leaves raw mode and flushes the
queue when the owner exits. **Ctrl+C still works**: the keyboard interrupt sets the interrupt
flag before the scancode is queued. A program that owns the screen or the raw keyboard is ended
by the kernel itself at its next `kbd_event`, `screen_flush` or `sleep_ms` call (exit code 130),
because a program that never blocks would starve the shell, which normally does the killing. The
screen and the keyboard are then released. Text pasted with Ctrl+V and serial input
are not delivered in raw mode.

**clock_ns.** Monotonic, from the TSC when it is calibrated (otherwise the 100 Hz tick).
