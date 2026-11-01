# Developing for ospab.os

This is the guide for people who want to write code for ospab.os: a program, a game, a driver, a
shell command, or a change in the kernel. It is written for someone who has used the system
(see [Getting started](../getting-started.md)) and knows some Rust.

| Page | What it covers |
|---|---|
| [Your first program](first-program.md) | Create a crate, build it, pack it, install it in a VM, debug it. |
| [liboos reference](liboos.md) | Every public function of the ring 3 runtime, with examples. |
| [Writing a game](games.md) | Screen, raw keyboard, sound, frame pacing, heap size. |
| [Kernel hacking](kernel-hacking.md) | Code map; adding a shell command, a system call or a driver. |
| [Drivers in ring 3](drivers.md) | Driver packages, `devmgr`, `libdriver`, writing a driver (e1000 example). |
| [Testing](testing.md) | Build commands, the smoke test, QEMU command lines, host tests, tools. |
| [Contributing](../../../CONTRIBUTIONS.md) | Workflow, commit style, license, bug reports, rules for AI agents. |

## What you can write

| Kind | Where it lives | Runs in | State |
|---|---|---|---|
| Program or package | `apps/<name>/` | ring 3 | Works. The normal way to add software. |
| Game or emulator | `apps/<name>/`, optionally with a `<name>-core` crate | ring 3 | Works. Full-screen, raw keyboard, sound. `drift` and `beeb` are examples. |
| GUI application | `apps/<name>/` against `gui/` (`oos-ui`) | desktop in the kernel; ring 3 build only paints into memory | Partly. See [GUI applications](../gui-apps.md). |
| Shell script | any file on `$PATH`, or `bash file.sh` | the shell (ring 0) | Works. See [Shell](../shell.md). |
| Shell command | `src/userspace/axon/`, `src/userspace/plum/`, `src/terminal.rs` | ring 0 | Works. Needs a rebuild of the kernel. |
| Driver (package) | `apps/drivers/<name>/` | ring 3 | Works for PCI devices; `drv-e1000` is the example. No kernel rebuild. See [Drivers in ring 3](drivers.md). |
| Driver (in the kernel) | `drivers/`, `net/`, `src/xhci/` | ring 0 | Works. Needs a rebuild of the kernel. |
| Kernel subsystem | `core/`, `mm/`, `vfs/`, `arch/`, `fs/aeternafs/` | ring 0 | Works. |
| Boot loader | `boot/` | firmware, then long mode | Works. See [Boot](../boot.md). |
| Host tool | `tools/` | your PC | `tmt` (packages) and `oosfs` (AeternaFS images). |

## How much runs in ring 0

Be clear about this before you choose where to put your code.

Today ospab.os is a monolithic kernel that is being turned into a microkernel. The shell (`plum`),
the coreutils (`ls`, `grep`, ...), the editor, `tomato`, `curl`, the console, every driver, the
network stack, the filesystem and the desktop run inside the kernel, in ring 0. A bug in any of
them can crash the machine.

What runs in ring 3 today:

- programs installed from `.tmt` packages (everything in `apps/`);
- the test programs in `user/`, which the kernel starts during the boot self-test.

The kernel has the mechanisms to move more out: handles with rights, IPC, shared memory, and
interrupts, I/O ports and device memory as handles. A ring 3 UART driver (`user/uartdrv`) proves
that. The services themselves have not moved yet. That is stage 3 of the
[ROADMAP](../../../ROADMAP.md) (in Russian): `seed` as the first real process, then the console,
storage, network, sound and so on, one at a time.

What this means for you:

- A program in `apps/` is isolated. A crash kills that process and the shell prints the exit
  status. This is the safe place to experiment.
- A ring 3 program today sees a small part of the system: files by path, the console, the screen,
  the raw keyboard, sound, a clock, memory. It has no network, no directory listing, no way to
  start other programs and no environment variables. [liboos reference](liboos.md) lists what is
  missing. If you need one of these, the work is in the kernel: [Kernel hacking](kernel-hacking.md).
- Code in `drivers/`, `net/`, `vfs/` or `src/userspace/` is ring 0. Treat it like a kernel: no
  panics on bad input, follow the [locking rules](../kernel.md).

## Where to start

- Want to ship a tool or a game: [Your first program](first-program.md), then
  [liboos reference](liboos.md) and [Writing a game](games.md).
- Want a new shell command with no new system call: [Kernel hacking](kernel-hacking.md),
  "Add a shell command".
- Want hardware support: [Kernel hacking](kernel-hacking.md), "Add a driver".
- Want to fix something: [Testing](testing.md) and [Contributing](../../../CONTRIBUTIONS.md).

Background reading: [Architecture](../architecture.md), [System call ABI](../syscall-abi.md),
[Kernel internals](../kernel.md), [Building](../building.md).
