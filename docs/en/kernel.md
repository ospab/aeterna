# Kernel internals

This page describes how the kernel keeps its shared state consistent, and how tasks, handles,
file descriptors and console input work. Source: `core/`, `mm/`, `vfs/`.

## Locks

All primitives are in `core/sync.rs`.

| Type | Use |
|---|---|
| `IrqSpinLock<T>` | Disables interrupts, then takes an atomic lock. Safe to share with interrupt handlers. |
| `Mutex<T>` | Task context only. Yields the CPU while contended, so sections may be long. |
| `OnceCell<T>` | A global written once and read without a lock (heap start, memory info). |
| `IrqCounter` | A counter or index shared with interrupt handlers. A plain relaxed atomic. |
| `irq_save` / `irq_restore` / `without_interrupts` | A bare interrupt-off section, no data attached. |

`static mut` is not used for shared state in `core/`, `mm/` and `vfs/`. What remains
(driver register blocks, NIC rings, the TCP table) is touched only from one context, or
under the `NET_BUSY` rule described below.

### Rules

1. A holder of an `IrqSpinLock` is never interrupted on its own CPU. An interrupt handler may
   therefore take any lock that task code takes.
2. Keep the section short. No I/O, no waiting, no `sys_yield`, no `park` with a lock held.
   The kernel panics if a task sleeps while holding a spinlock.
3. Locks have a rank. Take them in increasing rank order. The kernel tracks the held ranks and
   panics on a violation, on recursion, and when a lock stays held for about 200 million spins.
4. HEAP is the innermost lock, so allocating while holding any other lock is allowed. Code
   inside the allocator must not take any other lock.
5. `Mutex` is for sections that call into the VFS or a disk. Never use it from an interrupt
   handler, and never wait for the contender inside the section.
6. Use `try_lock` in a handler that can also run from a fault path (panic, page fault).

### Ranks

| Rank | Lock | Protects |
|---|---|---|
| 5 | OBJ | kernel objects and handle tables |
| 10 | SCHED | task table, per-task file descriptor table |
| 15 | VFS | mount table, disk-sync state |
| 20 | DEV | state shared with interrupt handlers: keyboard paste ring, console stdin, ARP and DNS caches, UDP mailboxes |
| 22 | TIME | clock state |
| 25 | NUMA | node table |
| 30 | VMM | page-table edits |
| 35 | PMM | frame bitmap |
| 40 | HEAP | kernel heap |

If you add a lock, pick the rank by what it calls while held. A lock that allocates must be
below HEAP; one that maps pages must be below VMM.

### Network stack

The packet path and the NIC drivers still run lock-free. Their rule is `NET_BUSY`: task code
that touches the rings or the TCP table raises the counter (`BusyGuard`, `poll_rx`,
`send_raw`), and the NIC interrupt handler acknowledges the device but does not drain the
receive ring while the counter is non-zero. Data that both a handler and a task read, such as
the ARP and DNS caches and the UDP mailboxes, are behind `IrqSpinLock`.

## Scheduler

`core/scheduler/mod.rs`. One run queue over a table of 64 task control blocks, preemptive,
driven by the local APIC timer. Equal priorities are served round-robin.

A task is either a kernel thread (ring 0, created by `spawn_named`) or a ring-3 process
(created by `spawn_user_task`). The ring never depends on the priority.

Each task has:

- its own kernel stack (16 KiB), so a blocking system call is safe; the scheduler sets
  `TSS.RSP0` and the SYSCALL stack on every switch;
- an XSAVE (or FXSAVE) area for FPU and SIMD state;
- an address space, for ring-3 processes;
- a handle table and a file descriptor table (below);
- a state: Ready, Running, Waiting, Dead.

`park(deadline)` puts the running task to sleep until `wake(pid)` or the deadline. The idle
loop reaps dead tasks: it takes them off the table and frees the kernel stack, the address
space, owned pages and handles (`teardown`). The file descriptor table is dropped with the
task control block, which closes every descriptor.

`SCHED` is held only while the table is read or changed. Never call into the VFS or the
allocator of another subsystem from inside `with_current_fds`.

## Objects and handles

`core/object.rs`. Each process has a handle table of up to 256 entries. A handle is
`(generation << 16) | (slot + 1)`, carries rights and refers to an object: Process, Thread,
Channel, Notification, Reply, MemoryRegion, MmioRegion, Interrupt, IoPortRange or Resource.
An object lives while a handle or an in-flight message refers to it. Process exit closes all
its handles. Details and numbers: [System call ABI](syscall-abi.md).

## File descriptors

`core/fd.rs`. Every task has its own table in its control block.

- fd 0, 1, 2 are stdin, stdout and stderr. They always exist, are not stored in the table and
  cannot be closed. The system call layer routes them to the console (or to the shell's pipe
  or redirect).
- fd 3 and up are VFS files. An entry holds the absolute path, the offset and the access mode.
  The table holds at most 64 descriptors including the three standard ones.
- `open`, `read`, `write`, `seek` and `close` in `vfs/mod.rs` look up the descriptor of the
  calling task with `with_current_fds`, copy what they need, and do the file I/O after the
  scheduler lock is released.
- A new process starts with an empty table. A kernel thread has a table as well; DOOM uses
  its own and closes leftovers with `close_all_vfs_fds`.

A descriptor does not survive its process: when the task is reaped, its table is dropped. The
offset is per descriptor, so two processes reading the same file do not disturb each other.

## Console input for ring-3 programs

`read(0, ...)` in a program started by the shell goes through `syscall_read`:

1. If the shell's stdin is a pipe or a here-string, the data comes from there. An exhausted
   source returns 0 (end of input).
2. Otherwise `core/stdin.rs` runs a line discipline over the keyboard. The call sleeps
   (yielding the CPU) until a line is complete, then returns up to `len` bytes of it. The rest
   stays for the next read, so a program may read one byte at a time.

Editing keys while the line is typed:

| Key | Effect |
|---|---|
| Enter | ends the line; the newline is part of the data |
| Backspace | removes the last character |
| Ctrl+U | removes the whole line |
| Ctrl+D | on an empty line: end of input (read returns 0); otherwise ends the line without a newline |
| Ctrl+C | echoes `^C` and drops the line; see below |

Typed characters are echoed straight to the console, not through the shell's stdout, so a
redirect does not swallow the echo. Only printable ASCII is accepted; a line is at most 1024
bytes.

Ctrl+C: the keyboard interrupt handler sets a flag when it sees the key. The shell waits for
its foreground program in a loop (`run_elf` in `src/userspace/plum/exec.rs`), notices the flag
and kills the process with signal 9; the exit status is 130. The blocked `read` never
returns to the program. The stdin state belongs to one pid and is cleared when another process
reads, so leftover input of a killed program is not given to the next one.

When no ring-3 program is in the foreground, the shell reads the keyboard itself with its own
line editor (history, completion, Ctrl+A/E/K/W). The two paths do not share state.

## Boot tests

`core/selftest.rs` runs with the kernel parameter `selftest=sched` (or `selftest=all`): lock
rules, and several tasks working on their own descriptor tables under preemption. Ring-3 tests in `src/main.rs` check that no
frames are left allocated after the test processes exit.
