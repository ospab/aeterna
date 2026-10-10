# System call ABI: objects, handles, IPC

Implementation: `core/object.rs` (logic), `core/syscall/objects.rs` (glue); program wrappers are
in `user/liboos/src/ipc.rs`. Other calls (write, mmap, ...) are in `core/syscall/mod.rs`.

## Convention

`SYSCALL`: number in `RAX`, arguments in `RDI, RSI, RDX, R10, R8`, result in `RAX`.
`RCX` and `R11` are clobbered. A negative result is an error:

| Code | Name | Meaning |
|---|---|---|
| -1 | InvalidSyscall | no such call |
| -2 | PermissionDenied | the handle lacks a required right |
| -3 | InvalidArgument | bad argument (length > 128, duplicate handle, ...) |
| -5 | Busy | the channel queue is full |
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
duplicated), `TRANSFER`=8 (may be sent in a message). A duplicate can only lose rights.

Objects: **Process**, **Thread** (one thread per process for now), **Channel**, **Notification**,
**Reply** (the right to answer one call; created by the kernel on `call` and handed to the
receiver in `recv`). An object lives while at least one handle or in-flight message refers to it.
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
| 202 | handle_info | h → type \| rights<<8 (1 Process, 2 Thread, 3 Channel, 4 Notification, 5 Reply) |
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

`timeout` is in 100 Hz ticks; 0 waits forever. Waiting does not spin: the task becomes Waiting,
the CPU halts, and the other side (or the deadline) wakes it. When no handle with `READ` is left on
a channel, the channel closes and every pending `call` gets `PeerClosed`.

## Drivers in ring 3 (stage 2, item 13)

Interrupts and device memory or I/O ports will become objects of the same kind: an Interrupt that
signals a Notification, and MemoryRegion/IoPort objects with `READ`/`WRITE`/`DUP`/`TRANSFER`
rights. A driver process receives them as handles from its parent, and clients talk to it over a
Channel.
