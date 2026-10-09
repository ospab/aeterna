<div align="center">

# ospab.os

### A microkernel operating system for x86-64, written in Rust

[![Language](https://img.shields.io/badge/Language-Rust%20%28no__std%29-f74c00?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64-0366d6?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-AGPL--3.0-2ea44f?style=flat-square)](LICENSE)

[English](README.md) · [Русский](README_ru.md)

</div>

**ospab.os** is a closed, vertically integrated operating system built from scratch in Rust.
Its kernel is called **AETERNA**. The system does not try to be compatible with Linux or Windows:
the kernel, drivers, network stack, shell and tools are all written together and designed as one
whole. It is part of the ospab ecosystem and will ship native, low-level support for the
[OSTP](https://github.com/ospab/ostp) transport.

> **Status: research system, mid-redesign.** Everything below is split into *what works today*
> and *where it is going*. The kernel is being rebuilt from a single-address-space monolith into a
> real microkernel. See [AUDIT.md](AUDIT.md) for an honest state of the code and
> [ROADMAP.md](ROADMAP.md) for the plan.

---

## What works today

| Area | State |
|---|---|
| Boot | Limine protocol, hybrid BIOS/UEFI ISO; runs in QEMU and VMware Workstation |
| CPU | GDT + TSS, IDT, APIC timer (1 kHz), preemptive scheduler, SSE |
| Memory | 4-level page tables, per-task address spaces, kernel heap |
| Ring 3 | SYSCALL/SYSRET path works; one test process round-trips (milestone 1) |
| Storage | ATA PIO, AHCI, NVMe; GPT; UEFI disk installer (GPT + FAT32 + LFN) |
| Filesystem | VFS + RamFS with deferred persistence to disk |
| Network | RTL8139, RTL8169, e1000, virtio-net; ARP, IPv4, ICMP, UDP, TCP, DHCP, DNS, SNTP, TLS client |
| Audio | AC97, ES1371, Intel HDA |
| Input / video | PS/2 keyboard and mouse, UEFI framebuffer, VMware SVGA |
| Userland | `plum` shell, `grape` editor, `tomato` package manager, `seed` init, coreutils, DOOM |

**Important:** apart from the ring-3 test process, all of the above currently runs in ring 0, in
one address space. There is no process isolation yet, and the capability model is not enforced.

## Where it is going

- **Microkernel.** The kernel keeps only address spaces, threads, scheduling, IPC, interrupts and
  capabilities. Drivers, the network stack, filesystems and the console become isolated user-space
  servers that talk over IPC. A crashing driver is restarted, not a kernel panic.
- **Capabilities instead of root.** A process can only touch what it holds a handle to.
- **Own bootloader.** A small UEFI loader in Rust replaces Limine.
- **liboos** — the user-space runtime, and a Rust target (`x86_64-unknown-oos`) for building
  programs for ospab.os.
- **Native OSTP** in the network server, so the whole system can route through an OSTP tunnel.

## Building

Requirements: Rust nightly with `rust-src`, and for the ISO: `xorriso`, `mtools`, `mkfs.vfat`
(on Windows, build the ISO from WSL).

```bash
./build.sh kernel   # kernel only — fast compile check
./build.sh          # kernel + DOOM + bootable hybrid ISO in isos/
```

## Running

```bash
qemu-system-x86_64 -cdrom isos/ospab-os-v2-N.iso -m 512M -serial stdio
```

VMware Workstation: attach the ISO as a CD/DVD drive. Kernel diagnostics go to the serial port
(COM1); the terminal is drawn on the framebuffer.

## Project layout

```
arch/x86_64/   CPU setup, interrupts, TSS, framebuffer, serial, keyboard, mouse, Limine glue
core/          scheduler, syscalls, IPC, capabilities
mm/            physical frames, page tables, kernel heap
drivers/       storage, PCI, audio, GPU
net/           NIC drivers and the network stack
vfs/           VFS, RamFS, on-disk sync
src/           kernel entry, terminal, installer, DOOM glue
userland/      grape, tomato, seed (still compiled into the kernel)
doom_engine/   doomgeneric + freestanding libc shim
```

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).
