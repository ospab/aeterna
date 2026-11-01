# Changelog

Notable changes to ospab.os / AETERNA.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.1.0] - 2026-03-07 - TCP stack and network fixes

### Added

- TCP stack (`net/tcp.rs`), a full RFC 793 implementation:
  - State machine: Closed, SynSent or Listen, SynReceived, Established, FinWait1/2, TimeWait or CloseWait, LastAck, back to Closed
  - 3-way handshake (SYN, SYN-ACK, ACK) and data transfer with seq/ack tracking
  - FIN teardown (active and passive close), RST handling in every state
  - Retransmit timer (3 s) and an 8 KiB ring-buffer receive queue per connection
  - 16-slot connection table, no heap allocation
  - Public API: `tcp_connect`, `tcp_listen`, `tcp_accept`, `tcp_send`, `tcp_recv`, `tcp_recv_nb`, `tcp_close`
- IPv4 TCP dispatch: protocol 6 goes to `tcp::handle_tcp()` from `ipv4::handle_ipv4()`.
- Hardware link detection that reads real registers instead of returning true:
  - RTL8139: MediaStatusRegister (0x58) bit 2 (clear means link OK)
  - Intel e1000: STATUS register bit 1 (LU, link up)
  - RTL8169: PHY Status register (0x6C) bit 1
- `net::link_up()` asks the active NIC for its hardware link state.
- RX/TX byte counters: `net::rx_bytes()` and `net::tx_bytes()` are atomics updated on every frame.
- `traceroute` (`axon net_tools`): ICMP TTL-based route discovery with `-m` and `-w` flags.

### Fixed

- `ifconfig` and `ip` no longer print a hardcoded `UP BROADCAST RUNNING MULTICAST`:
  - the interface name is the real driver name (RTL8139, Intel e1000, RTL8169/8111);
  - the UP or DOWN flag comes from the hardware link register;
  - when ARP times out, the broadcast-MAC gateway fallback is marked `(broadcast fallback)`;
  - RX/TX packet and byte counters are shown.
- `netstat`: the Status column shows the real hardware link state (it was always "Up").
- `signal_pid` and `signal_thread` dispatch on the signal number: SIGCONT sets Ready, SIGSTOP sets Waiting, anything else sets Dead.
- `env CMD` parses `KEY=VAL` overrides, runs the command and restores the environment.
- `tomato --tmt pack` prints a `[SIMULATION MODE]` warning for empty package manifests.
- Removed fake indicators from `seed log`, `df`, `top` and `netdiag`.

### Changed

- `net/mod.rs`: added `pub mod tcp`, `link_up()`, `rx_bytes()`, `tx_bytes()`.

---

## v1.1.0 (earlier notes) - architecture and installer

- Microkernel separation: network, drivers and the virtual filesystem moved out of ring 0 into userspace domains.
- VirtIO-Net driver: the stub is replaced by a working VirtIO 1.0 driver with PCI probing, BAR parsing and device feature negotiation.
- Copy-on-write VFS: the `FileSystem` trait is implemented for the CoW (overlay) filesystem, with writes kept strictly in the upper layer.
- Installer: the `aeterna-install` disk installer got a new minimalist interface with accurate progress bars.
- Bootloader: the Limine configuration now detects the native display resolution and uses it.

---

## v1.0.0 - initial release

The first stable release of the AETERNA microkernel. It boots from a hybrid BIOS/UEFI live ISO
through Limine. It ships an interactive shell with 30+ commands, a UEFI disk installer, a DOOM
port and the userland tools.

### Kernel and architecture

- x86-64 bare metal: Long Mode, SSE/FPU (CR4 `0x660`), GDT with TSS, IDT with 256 handlers
- PIC: 8259 remapped to IRQ 32–47; PIT IRQ 0 at 100 Hz; PS/2 keyboard on IRQ 1
- Memory: bitmap physical allocator, 128 MiB kernel heap (`linked_list_allocator`), 4-level PML4 page tables
- Boot protocol: Limine 10.8.2, framebuffer via GOP, HHDM, memory map
- Framebuffer: 8×16 VGA bitmap font, 32-bit BGRA pixel format
- Serial: COM1 115200 8N1, structured boot log with `[OK]` and `[FAIL]` markers
- FPU save and restore: `fxsave`/`fxrstor` in all interrupt stubs

### Storage drivers

- ATA PIO: polling, 28-bit LBA, read, write, identify, error recovery
- AHCI SATA: PCI BAR5, HBA reset, NCQ port init, DMA read and write, flush cache command
- NVMe: PCI BAR0, admin queue setup, I/O queue pair, PRP-based transfers, namespace identify, flush

### Audio drivers

- AC97: Intel ICH-compatible, DMA BDL ring, 44100 Hz VRA, mixer volume control
- ES1371: Ensoniq AudioPCI and Creative CT5880 (VMware Workstation native)
- Common API: the `soundtest` command plays a 440 Hz sine wave

### Network stack

- RTL8139: PCI NIC, DMA TX/RX ring buffers, interrupt-driven receive
- Intel e1000: PRO/1000 Gigabit Ethernet, descriptor rings, EEPROM MAC read
- Protocols: Ethernet, ARP (TTL cache), IPv4 (header checksum), ICMP, UDP, SNTP
- `ping -c N <ip>`: round-trip time in microseconds from the TSC
- `ntpdate`: one-shot SNTP sync over UDP/123

### Virtual filesystem

- VFS: POSIX-style trait layer, mount table, path resolution
- RamFS: in-memory `BTreeMap<String, RamNode>` behind a `spin::Mutex`
- Deferred sync: a dirty flag and a 182-tick PIT timer trigger serialisation to LBA 2048 of the boot disk
- Boot recovery: RamFS is deserialised from LBA 2048 if the magic header is present
- Standard directories: `/etc`, `/proc`, `/dev`, `/home`, `/tmp`, `/sys`, `/boot`, `/var`
- 27+ nodes created at boot: `/etc/hosts`, `/etc/motd`, plumrc, seed config and others
- C FFI for DOOM: `rust_vfs_open/read/write/close/seek/rename/access/opendir`

### UEFI disk installer

- GPT: protective MBR, primary and backup GPT headers, CRC32 per spec
- FAT32 ESP: dynamic sectors-per-cluster formula (at least 65525 clusters, EDK2 compatible)
- LFN support: `lfn_checksum()`, `lfn_entry()`, UCS-2LE encoding; short name `LIMINE~1CON`
- Installed files: `/EFI/BOOT/BOOTX64.EFI`, `/boot/KERNEL`, `/limine.conf`
- Multiple controllers: NVMe, then AHCI, then ATA, taken in that order
- Verification: reads back MBR, GPT, VBR, FAT[0..7] and the EFI MZ magic before reporting success
- Disk flush: three explicit `disk_flush()` calls, after GPT, after the ESP files and before verification
- Serial trace: every installer step is logged to COM1 with hex dump helpers

### Userland tools

- plum, a POSIX shell: variables (`$VAR`, `${VAR}`, `$?`), `export`, `alias`, `source`,
  `if/then/else/fi`, `for/while/do/done`, functions, `$(( ))`, `$( )`, `/etc/plum/plumrc`
- grape, a full-screen nano-style editor: title, status and help bars, `Ctrl+O/X/K/U/W/G/T`,
  arrow keys, PgUp/PgDn, search with wrap-around, block cursor, directories created on save
- tomato, the package manager: `-S/-R/-Q/-Qi/-Ss/-Sy/-Syu`; a built-in repository of 10 packages;
  installed packages tracked in `/var/lib/tomato/`
- seed, the init system: 9 services (`kernel`, `vfs`, `scheduler`, `console`, `serial`,
  `keyboard`, `network`, `storage`, `plum`); policies `always`, `once`, `manual`; `/etc/seed/init.conf`
- tutor, an interactive tutorial: `intro`, `fs`, `net`, `mem`, `kernel`, `commands`

### Terminal

- 30+ built-in commands: `ls`, `cat`, `cd`, `pwd`, `mkdir`, `touch`, `rm`, `echo` (`>` and `>>`),
  `ping`, `ifconfig`, `ntpdate`, `free`, `lsmem`, `lspci`, `lsblk`, `fdisk`, `dmesg`,
  `version`, `uname`, `about`, `whoami`, `hostname`, `date`, `uptime`,
  `install`, `reboot`, `shutdown`, `poweroff`, `halt`, `sync`,
  `export`, `alias`, `unalias`, `env`, `set`, `unset`, `type`, `source`
- Command history (16-entry ring, Up and Down), tab completion, Ctrl+C interrupt, Ctrl+L clear
- All output is mirrored to the COM1 serial port

### DOOM

- doomgeneric port: 640×400 rendering on the UEFI framebuffer, 32-bit BGRA
- A freestanding C runtime (`malloc`, `free`, `printf`, `sprintf`, `memcpy`, `memmove`,
  `memset`, `qsort`, `sqrt`, `atan2` and others) tied to the kernel heap through `#[no_mangle]` FFI
- PS/2 keyboard with scancode-to-DOOM translation; F1–F10 menu navigation
- Saves and loads at `/doom/doomsav{0-5}.dsg` through the VFS, persisted by the deferred disk sync

### Build system

- `build.sh` compiles DOOM C (`gcc -nostdlib`), builds the kernel (`cargo build --release`),
  strips debug info (`llvm-objcopy --strip-debug`, output about 6 MB), then builds the hybrid ISO (`xorriso`)
- `bash build.sh kernel` builds only the kernel and skips the ISO
- Zero-warning policy on every commit

---

## [0.x] - pre-release development

Internal development series. Not tagged publicly.
