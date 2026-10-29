# ospab.os documentation

English is the primary language of the documentation; [Русская версия](../ru/README.md) is a
translation and may lag behind.

## Using the system

- [Getting started](getting-started.md): run ospab.os in VMware or QEMU, the first commands.
- [Installation](installation.md): install to a disk, install alongside Windows and Linux, boot it.
- [Shell and tools](shell.md): the `plum` shell, coreutils, keys, clipboard, serial console.
- [Packages](packages.md): `tomato`, the signed repository, writing and packaging programs.
- [Networking and OSTP](networking.md): addresses, `curl`, DNS, time, the OSTP client.
- [olang](olang.md): the `ol` interpreter for the olang language, what differs from the original.
- [Hardware](hardware.md): supported devices and recommended VM settings.

## Developing the system

- [Building](building.md): toolchain, build targets, ISO and disk images, the smoke test.
- [Architecture](architecture.md): boot flow, rings, memory, scheduler, kernel objects and IPC.
- [System call ABI](syscall-abi.md): numbers, registers, objects and rights.
- [GUI](gui.md): the UI toolkit and the plan for the compositor.

Project-level documents stay in the repository root: [ROADMAP.md](../../ROADMAP.md) (plan, in
Russian), [AUDIT.md](../../AUDIT.md) (honest state of the code), [CONTRIBUTIONS.md](../../CONTRIBUTIONS.md).

## Conventions

- Commands you type in ospab.os are shown after a `#` prompt; commands for your PC are shown
  without one.
- "Ring 0" is the kernel, "ring 3" is user programs. "ISO N" or "build #N" is the number shown
  by `uname -a`.
