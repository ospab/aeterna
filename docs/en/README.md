# ospab.os documentation

The documentation is written in English first. The [Russian version](../ru/README.md) is a
translation and can lag behind.

## Using the system

- [Getting started](getting-started.md): run ospab.os in VMware or QEMU, the first commands.
- [Installation](installation.md): install to a disk, install alongside Windows and Linux, boot it.
- [Shell and tools](shell.md): the `plum` shell, coreutils, keys, clipboard, serial console.
- [Packages](packages.md): `tomato`, the signed repository, writing and packaging programs.
- [Networking and OSTP](networking.md): addresses, `curl`, DNS, time, the OSTP client.
- [olang](olang.md): the `ol` interpreter for the olang language, what differs from the original.
- [beeb](beeb.md): BBC Micro emulator (bring your own MOS ROM and disc images).
- [drift](drift.md): space trading and combat game with a story campaign.
- [Hardware](hardware.md): supported devices and recommended VM settings.

## Developing for ospab.os

Start with the [developer guide](dev/README.md).

- [Overview](dev/README.md): what you can write, where it lives, how much runs in ring 0.
- [Your first program](dev/first-program.md): create a crate, build, package, install, debug.
- [liboos reference](dev/liboos.md): the API of ring 3 programs, with examples and error codes.
- [Writing a game](dev/games.md): screen, raw keyboard, sound, frame pacing, heap size.
- [Kernel hacking](dev/kernel-hacking.md): code map; add a shell command, a system call, a driver.
- [Testing](dev/testing.md): build targets, smoke test, QEMU command lines, host tests, tools.
- [Contributing](../../CONTRIBUTIONS.md): workflow, commit style, license, bug reports, AI-agent rules.

## Developing the system

- [Building](building.md): toolchain, build targets, ISO and disk images, the smoke test.
- [Architecture](architecture.md): boot flow, rings, memory, scheduler, kernel objects and IPC.
- [System call ABI](syscall-abi.md): numbers, registers, objects and rights.
- [GUI](gui.md): the UI toolkit and the plan for the compositor.

Project-level documents stay in the repository root: [ROADMAP.md](../../ROADMAP.md) (plan, in
Russian), [AUDIT.md](../../AUDIT.md) (state of the code, also in Russian),
[CONTRIBUTIONS.md](../../CONTRIBUTIONS.md).

## Conventions

- Commands you type in ospab.os are shown after a `#` prompt; commands for your PC are shown
  without one.
- "Ring 0" is the kernel, "ring 3" is user programs. "ISO N" or "build #N" is the number shown
  by `uname -a`.
