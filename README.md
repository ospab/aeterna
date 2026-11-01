<div align="center">

# ospab.os

### A microkernel operating system for x86-64, written in Rust

[![Language](https://img.shields.io/badge/Language-Rust%20%28no__std%29-f74c00?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64-0366d6?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-AGPL--3.0-2ea44f?style=flat-square)](LICENSE)

[English](README.md) · [Русский](README_ru.md) · [Documentation](docs/en/README.md) · [Документация](docs/ru/README.md)

</div>

ospab.os is a closed, vertically integrated operating system written from scratch in Rust.
Its kernel is called AETERNA. It makes no attempt to run Linux or Windows programs: the
bootloader, kernel, drivers, network stack, shell, package manager and tools are written
together and fit each other. It belongs to the ospab ecosystem and speaks the
[OSTP](https://github.com/ospab/ostp) transport natively.

> **Status: research system, mid-redesign.** The kernel is moving from a single-address-space
> monolith to a real microkernel. Ring-3 processes, kernel objects, capabilities and IPC already
> work. Most drivers and the shell still run inside the kernel. The plan is in
> [ROADMAP.md](ROADMAP.md), the unflattering state of the code is in [AUDIT.md](AUDIT.md).

---

## What works today

| Area | State |
|---|---|
| Boot | Own loader ospab-boot for BIOS and UEFI (menu, memory test, FAT and ISO9660 readers); hybrid ISO that boots from CD and USB on both |
| Install | Full-screen installer: erase a disk, or install alongside Windows and Linux on the existing ESP |
| CPU | GDT/TSS, IDT, APIC timer, preemptive scheduler, per-task kernel stacks, XSAVE (AVX state) |
| Memory | Bitmap frame allocator, 4-level paging, per-process address spaces, NX, SMEP/SMAP |
| Ring 3 | ELF programs on the `x86_64-unknown-oos` target with the liboos runtime |
| Microkernel | Kernel objects, per-process handle tables with rights, synchronous IPC, notifications |
| Storage | ATA PIO, AHCI, NVMe, virtio-blk; GPT; persistence of the writable filesystem layer |
| Network | e1000, RTL8139/8169, virtio-net, AMD PCnet (VMware vlance), vmxnet3; IPv4, TCP, UDP, DHCP, DNS, NTP, TLS 1.3 client |
| OSTP | Native client: share links, subscriptions, UDP and UoT transports |
| Audio | Intel HDA, AC97, ES1371/ES1373 (VMware), ES1370 |
| Input / video | PS/2 and USB (xHCI) keyboard and mouse, VMware mouse, UEFI framebuffer, VMware SVGA II |
| Host integration | VMware clipboard (Ctrl+V, `clip`), console input over the serial port |
| Shell | `plum`: variables, pipes, redirects, control flow, functions, scripts; coreutils; Ctrl+C |
| Packages | `tomato` with the signed repository tmt.ospab.org; SDK for your own programs |
| Power and time | ACPI power-off and reset; system clock counts from the ospab epoch, 2012-08-09 |

Apart from ring-3 programs, everything above runs in ring 0 today. Moving drivers, the network
stack and the console into isolated servers is the next roadmap stage.

## Quick start

1. Download an ISO from the releases or build one (see below).
2. In VMware Workstation create a VM: Other 64-bit, firmware UEFI (Secure Boot off),
   USB controller USB 3.x. Attach the ISO and boot.
3. In the console try `help`, `tutor`, `uname -a`, `tomato update`, `install`.

Full guide: [docs/en/getting-started.md](docs/en/getting-started.md).

## Building

Requirements: Rust nightly with `rust-src`; for the ISO also `xorriso`, `mtools` and
`mkfs.vfat` (on Windows, build the ISO from WSL).

```bash
./build.sh kernel   # kernel only, fast compile check
./build.sh          # bootable hybrid ISO in isos/ospab-os-v2-N.iso
./build.sh image    # GPT disk image with ospab-boot, no WSL needed
```

The build number `N` appears in `uname -a`. Details: [docs/en/building.md](docs/en/building.md).

## Documentation

| | |
|---|---|
| [Getting started](docs/en/getting-started.md) | Running in VMware and QEMU, first steps |
| [Building](docs/en/building.md) | Toolchain, build targets, smoke test |
| [Installation](docs/en/installation.md) | Installer modes, dual boot, boot instructions |
| [Architecture](docs/en/architecture.md) | Boot flow, rings, memory, scheduler, kernel objects |
| [Shell and tools](docs/en/shell.md) | plum, coreutils, keys, clipboard |
| [Packages](docs/en/packages.md) | tomato, the `.tmt` format, the repository, the SDK |
| [Networking and OSTP](docs/en/networking.md) | Network stack, `ip`, `curl`, `ostp` |
| [Hardware](docs/en/hardware.md) | Supported devices and VM settings |
| [Developing for ospab.os](docs/en/dev/README.md) | Write a program, a game, a driver; liboos API, testing, contributing |

## Project layout

```
arch/x86_64/   CPU setup, interrupts, TSS, framebuffer, serial, keyboard, mouse, boot protocols
boot/          ospab-boot loader (BIOS and UEFI) and its config
core/          scheduler, syscalls, kernel objects, IPC, ELF loader
mm/            frame allocator, page tables, user copies, heap
drivers/       storage, audio, GPU, VMware integration
net/           NIC drivers, the network stack, TLS, OSTP
vfs/           VFS, RamFS, copy-on-write root, disk sync
src/           kernel entry, console, installer, time, shell and coreutils
user/          liboos runtime and built-in ring-3 programs
apps/          SDK workspace for packaged programs
gui/           software UI toolkit (in progress)
tools/         mkimage, tmt packer and repository tools
docs/          documentation in English (docs/en) and Russian (docs/ru)
```

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only). Bundled fonts in `gui/fonts`
are under the SIL Open Font License.
