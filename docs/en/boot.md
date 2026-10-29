# Boot

ospab-boot is the only loader of ospab.os. It has two front-ends that share one code base:

| Front-end | Directory | Firmware |
|---|---|---|
| UEFI | `boot/uefi` | UEFI (x86-64), `BOOTX64.EFI` |
| BIOS | `boot/bios` | legacy BIOS (INT 13h extensions, VBE 2.0), 64-bit CPU |
| Shared | `boot/common` | config parser, menu, memory test, video mode choice, ELF loader, page tables, kernel hand-off |

The kernel does not know which loader started it. Both build the same `BootInfo`
(`arch/x86_64/boot/ospab_proto.rs`) and jump to the kernel.

## Boot flow (UEFI)

1. The firmware starts `OSPABLDR.EFI` (installed: `\EFI\BOOT\BOOTX64.EFI`, or `\EFI\ospab\OSPABLDR.EFI`
   when installed alongside other systems).
2. The loader finds the boot volume: the device it was started from, then every FAT file system,
   then every block device with ISO9660. The volume must contain `ospab.cfg` or `/boot/KERNEL`.
3. It reads the config (search order below), parses it strictly and builds the entry list.
4. Menu: shown when there is more than one visible entry, or when the config has errors.
5. The chosen entry runs. For type `ospab`:
   1. read the kernel ELF and the modules into memory;
   2. map the kernel at its linked addresses, build the page tables (HHDM);
   3. pick the GOP mode (`resolution`), find the ACPI RSDP;
   4. fill `BootInfo`, call ExitBootServices, convert the memory map;
   5. enable EFER.NXE, load CR3, jump to the kernel entry.

## Boot flow (BIOS)

Stage 1 is one 512-byte sector. Stage 2 is about 85 KiB (`boot/bios`).

1. The BIOS loads sector 0 of the boot drive (MBR), or the El Torito boot image of a CD, to
   `0x7C00`. This is **stage 1**. It reads stage 2 with INT 13h extensions to `0x8000` (the
   drive's sector size is taken from INT 13h AH=48h, so 512-byte and 2048-byte sectors both work)
   and jumps to it in real mode with DL = boot drive.
2. **Stage 2, real mode:** enables A20, loads a GDT, builds identity page tables for the first
   4 GiB (2 MiB pages), and enters long mode.
3. **Stage 2, 64-bit Rust** (`boot/bios/src/main.rs`). The code runs at `0x8000` with the stack,
   page tables and a 2 MiB heap at `0x200000`. BIOS services are called through a thunk
   (`rm.S`): it leaves long mode, runs `int n` in real mode with a register block, and returns.
   Interrupts stay off in long mode; they are on only during the `int`.
4. It calibrates the TSC with the PIT, reads the E820 memory map (E801 and INT 15h AH=88h as
   fallbacks) and looks for ACPI S5 (see Power off below).
5. **Boot volume**, on the boot drive only, in this order: ISO9660 on the whole device (a CD, or
   the hybrid ISO on a stick), FAT32 in the partitions of the GPT or MBR, FAT32 without a partition
   table. The volume must contain `/boot/ospab.cfg` or `/boot/KERNEL`.
6. The config is read from `/boot/ospab.cfg` and parsed by the shared parser. Entries that do not
   exist on BIOS are dropped: `firmware`, `efi-chainload` and `poweroff` when no ACPI S5 was found.
7. The menu is drawn in VGA text mode 3 (80x25), keys come from INT 16h. The menu code is the same
   as in the UEFI front-end.
8. The chosen entry runs. For type `ospab`:
   1. read the kernel ELF and the modules into free RAM above 5 MiB and below 4 GiB;
   2. map the kernel at its linked addresses, build the page tables (HHDM), the same code as UEFI;
   3. set the VBE mode (see Video below), find the RSDP in the EBDA or `0xE0000..0xFFFFF`;
   4. turn on SSE (CR0.EM = 0, CR4.OSFXSR, CR4.OSXMMEXCPT);
   5. build the memory map from E820 plus what the loader allocated; low memory (below 1 MiB) and
      the loader's own memory are `BOOTLOADER_RECLAIMABLE`;
   6. enable EFER.NXE, load CR3, jump to the kernel entry.

### Video (BIOS)

The menu uses text mode. The framebuffer for the kernel is a VBE 2.0 linear mode with 32 bits per
pixel, set right before the jump. The mode comes from the `resolution` key:

| Value | Mode |
|---|---|
| `WxH`, `hd`, `fullhd`, `2k`, `4k` | that size, or the closest available mode |
| `max` | the largest mode, limited to the monitor's native size when EDID is known |
| `auto` (default) | the monitor's native size (EDID through VBE function 4F15h); without EDID, the mode closest to 1024x768 |
| `keep` | same as `auto` (the BIOS console is text mode, so there is nothing to keep) |

If a BIOS offers no 32-bit linear mode, the kernel starts without a framebuffer.

### Reboot and power off (BIOS)

Reboot: keyboard controller reset (port `0x64`, `0xFE`), then port `0xCF9`, then a triple fault.
Power off: ACPI S5. The loader reads the FADT, takes `PM1a_CNT_BLK`/`PM1b_CNT_BLK`, and the
`SLP_TYP` values from the `_S5_` object of the DSDT. It switches to ACPI mode through `SMI_CMD`
when needed. If the tables or `_S5_` are missing, the Power off entry is hidden.

## Disk and ISO layout

### Installed disk (GPT, written by the installer in "Erase entire disk" mode)

| LBA | Contents |
|---|---|
| 0 | protective MBR (type `0xEE`) with the **stage 1** boot code in bytes 0..445 |
| 1 | GPT header |
| 2..33 | GPT partition entries |
| 34..2047 | **BIOS boot partition** (type `21686148-6449-6E6F-744E-656564454649`): stage 2, raw, about 85 KiB of 1 MiB |
| 2048.. | EFI System Partition, FAT32: `/EFI/BOOT/BOOTX64.EFI`, `/boot/KERNEL`, `/boot/ospab.cfg` |
| after the ESP | root partition `AETERNA` |
| last sectors | backup GPT |

Why a BIOS boot partition and not the gap after the MBR: on GPT the gap between the entries and the
first partition is exactly LBA 34..2047. A partition entry marks it as used, so partitioning tools
leave it alone. Stage 1 finds stage 2 through a fixed field: the 64-bit start LBA at offset `0x40`
of the sector, in sectors of the boot drive. The installer writes `34` there. The 16-bit count at
`0x48` is set by the linker.

The same disk boots on UEFI (the firmware reads the ESP) and on BIOS (the BIOS reads the MBR).
`./build.sh image` writes the same layout with `tools/mkimage.rs --bios`.

### Alongside other systems

"Install alongside" never writes MBR boot code, so it is **refused on BIOS** (the installer says
why). Boot the live ISO in UEFI mode for it, or choose "Erase entire disk".

### Hybrid ISO (`scripts/mkiso.sh`, made by `./build.sh`)

| Where | Contents |
|---|---|
| system area (ISO bytes 0..511) | MBR = stage 1, with the position of stage 2 patched in at `0x40`; xorriso adds the protective partition table and a GPT |
| GPT partition 2 (type EF00) | the EFI system image: FAT16, `BOOTX64.EFI`, kernel, `ospab.cfg`, `bios.img` |
| ISO9660 tree | `/boot/bios.img`, `/boot/KERNEL`, `/boot/ospab.cfg`, `/EFI/BOOT/BOOTX64.EFI`, `/EFI/OSPAB/OSPABLDR.EFI`, `/boot/boot.cat` |
| El Torito, BIOS | `/boot/bios.img`, no emulation, 4 sectors (stage 1 plus padding), boot info table |
| El Torito, UEFI | GPT partition 2 (no second copy of the image) |

`/boot/bios.img` is stage 1 (offset 0, padded to 2048 bytes) followed by stage 2 (offset `0x800`).
All three ways to start work:

- **CD, BIOS:** the El Torito image runs stage 1 with the sector after it (from the boot info
  table) as stage 2. The loader reads the kernel from the ISO9660 tree.
- **USB stick (`dd` of the ISO), BIOS:** the BIOS runs the MBR. Stage 1 reads stage 2 from
  `bios.img` inside the ISO through the patched LBA. The loader finds ISO9660 on the whole device.
- **CD or USB, UEFI:** the firmware starts `\EFI\BOOT\BOOTX64.EFI` from the El Torito entry or
  the EFI partition.

The EFI image is FAT16 and below 32 MiB on purpose: the El Torito sector count is 16 bits, and
OVMF rejects a larger FAT volume.

## Booting from USB on real hardware

1. Write the ISO as a raw image. Rufus: choose the ISO, then in the write-mode dialog pick
   "DD Image mode". Linux/macOS: `sudo dd if=ospab-os-v2-N.iso of=/dev/sdX bs=4M status=progress && sync`.
   Do not use "ISO mode" in Rufus.
2. Ventoy is not supported. Ventoy replaces the boot structures and starts the ISO through its own
   loader; ospab-boot cannot find its files there.
3. Turn Secure Boot off. `BOOTX64.EFI` is not signed.
4. Pick the stick in the firmware boot menu. On UEFI machines choose the entry named "UEFI: <stick>"; on
   BIOS machines the plain device name ("USB-HDD").
5. The early screen, in order:
   - the ospab-boot menu (text, 80x25), or the line `Booting '...' from FAT volume` / `... ISO9660 volume`
     when the timer has no menu to show;
   - the kernel boot log: one `[  OK  ]` line per subsystem (CPU, display, memory, ...), then the shell.
     The last `OK` line on screen is the last step that finished. TODO: document the early progress
     bar once the kernel has a fixed one.
   A black screen with nothing, not even the menu, means the firmware did not start the loader:
   check the boot mode (UEFI/BIOS) and that the stick was written in DD mode.
6. Serial output (115200 8N1, COM1) carries the same log when the screen stays black.

## BootInfo contract

Defined in `arch/x86_64/boot/ospab_proto.rs` (version 1), shared by loader and kernel.

| Item | Value |
|---|---|
| RDI | physical address of `BootInfo` |
| RSI | magic `OSPABOOT` (`0x544F4F4241504F53`) |
| RDX | HHDM offset (`0xFFFF800000000000`) |
| CPU state | long mode, CPL0, IF=0, DF=0, SSE enabled, 64 KiB+ stack with a zero return address |
| Addresses | all physical; the kernel adds the HHDM offset |
| HHDM | RAM up to max(4 GiB, highest RAM), read/write, plus the framebuffer |
| Kernel | PT_LOAD segments at their linked addresses, physically contiguous, 4 KiB pages |
| Memory map | sorted, no overlaps; framebuffer is its own region |
| Command line | NUL-terminated, from the entry (or the edited line) |
| Modules | path, size, address, name of each `module` line |
| `firmware` | `1` BIOS, `2` UEFI |

A kernel started without a valid `BootInfo` prints a message on COM1 and halts.

## Config file

Search order (UEFI): `ospab.cfg` next to the loader (same directory), then `/boot/ospab.cfg`, then
built-in defaults (one entry that boots `/boot/KERNEL`). BIOS: `/boot/ospab.cfg`, then the
built-in defaults. The first file found is used alone.

Format: INI-like text, `key = value`, `[section]` headers, `#` comment lines (whole line only).
Sections were chosen over a flat list because each entry has its own keys and validation per
type needs a clear entry boundary. The first line that matters is `version = 1`.

### Global keys (before any header, or under `[global]`)

| Key | Values | Default | Meaning |
|---|---|---|---|
| `version` | `1` | required | format version |
| `timeout` | `0`..`3600`, `off` | `5` | seconds before the default boots. `0`: no menu unless a key is waiting. `off`: wait forever |
| `default` | entry id | first visible entry | entry that boots on timeout |
| `remember_last` | yes/no | yes | UEFI only: preselect the last booted `ospab`/`efi-chainload` entry (UEFI variable `OspabLastEntry`). BIOS has no storage for it and ignores the key |
| `resolution` | `auto`, `max`, `keep`, `WxH`, `hd`, `fullhd`, `2k`, `4k` | `auto` | graphics mode handed to the kernel |
| `serial` | yes/no | no | mirror loader messages to COM1. The BIOS front-end also logs to COM1 until the config is read |
| `theme` | `dark`, `light`, `mono` | `dark` | menu colors |

`remember_last` needs writable firmware variables. Where they are not stored, `default` is used.
Memory test, reboot, power off and firmware entries are never remembered.

### Entry keys (`[entry <id>]`)

The id is 1..32 characters of letters, digits, `-`, `_`, `.`, unique.

| Key | Types | Meaning |
|---|---|---|
| `title` | all | text in the menu, 1..60 characters, required |
| `type` | all | `ospab`, `efi-chainload`, `memtest`, `firmware`, `reboot`, `poweroff`; required |
| `kernel` | ospab | absolute path of the kernel ELF, default `/boot/KERNEL` |
| `cmdline` | ospab, memtest | command line, max 255 bytes |
| `module` | ospab | `<absolute path> [name]`; repeatable, max 16 |
| `path` | efi-chainload | absolute path of an EFI application on a FAT volume |
| `hidden` | all | yes: not shown in the menu (can still be `default`) |

Entry types by front-end:

| Type | UEFI | BIOS |
|---|---|---|
| `ospab`, `memtest`, `reboot` | yes | yes |
| `poweroff` | yes | only when ACPI S5 is found |
| `firmware`, `efi-chainload` | yes | dropped silently |

### Errors

Every unknown section or key, bad value, duplicate key, key that does not fit the entry type,
missing `version`, `title` or `type`, unknown `default` and missing `path` is reported with its
line number at the top of the menu and on the serial console. Entries that can still be used stay
usable. With errors the menu is always shown and never boots by itself.

### Example

```
version = 1
[global]
timeout = 5
default = ospab
[entry ospab]
title = ospab.os
type = ospab
kernel = /boot/KERNEL
[entry win]
title = Windows
type = efi-chainload
path = /EFI/Microsoft/Boot/bootmgfw.efi
```

To add an entry, append a block like this to `/boot/ospab.cfg` on the ESP (alongside install:
`\EFI\ospab\ospab.cfg`). A second kernel is another `ospab` entry with its own `kernel` path.
The `win` entry above shows on UEFI only.

## Menu keys

| Key | Action |
|---|---|
| Up, Down, Home, End, `k`, `j` | select |
| Enter | boot the selected entry |
| `1`..`9` | boot that entry at once |
| `e` | edit the command line of the selected `ospab` or `memtest` entry; Enter boots with it once, Esc cancels. Nothing is saved |
| any key | stops the countdown |

## Entries of an installed system

| Entry | Command line | Notes |
|---|---|---|
| ospab.os | (empty) | default, first |
| ospab.os Desktop | `session=desktop` | desktop session, logout returns to the console |
| ospab.os (debug) | `debug=1 selftest=ipc persist=ro` | detail log on screen and serial; IPC self-tests; the saved filesystem layer is read but never written |
| Memory test | `passes=1` | see below |
| Firmware settings | | UEFI only: sets `OsIndications` BOOT_TO_FW_UI and resets; says so if the firmware lacks it |
| Reboot | | firmware ResetSystem (UEFI) or the methods above (BIOS) |
| Power off | | firmware ResetSystem (UEFI) or ACPI S5 (BIOS) |

The installed menu has no Live or Installer entry. The live ISO adds Live and Installer
(`mode=live`, `mode=installer`) and loads three modules for the installer: the kernel, the UEFI
loader (`/EFI/OSPAB/OSPABLDR.EFI`) and the BIOS image (`/boot/bios.img`).
Kernel parameters: `debug=1`, `persist=ro`, `selftest=ipc|mem|all`, `session=desktop`, `mode=`.
`selftest=mem` needs a second serial port (COM2).

## Memory test

A loader feature, not a kernel mode: the tester is `boot/common/memtest.rs`.
Per pass: walking ones and zeros (8 shifts each), address in address (plus complement),
moving inversions (`0x55..`, `0x00FF..`, up then down), random pattern (plus complement).
Screen: progress bar, current test, pass, time, error count; Esc aborts. The result screen
shows PASSED / FAILED / ABORTED, the amount tested and the first 16 errors (address, expected,
actual, test); it is also printed to serial when `serial = yes`.
Options in the entry command line: `passes=N` (1..99), `limit=MiB`, `inject=1` (flip one bit
after the first write, to check that errors are reported).

- **UEFI:** allocates free RAM above 1 MiB from the firmware in 32 MiB chunks, tests each chunk
  and frees it, so firmware and loader memory is never overwritten (memory the firmware holds is
  not tested).
- **BIOS:** tests the E820 usable ranges directly, in 32 MiB chunks. Not tested: the first 5 MiB
  (BIOS data and the loader itself). RAM above 4 GiB is tested too; the loader extends its page
  tables for it first.

## Building the loader

| Part | Command |
|---|---|
| everything | `./build.sh` (see [Building](building.md)) |
| UEFI | `cd boot/uefi && cargo build --release` |
| BIOS | `scripts/bios-image.sh [OUT]` (writes `boot/bios/target/bios.img`) |

The BIOS front-end is `no_std` Rust for the target `x86_64-unknown-none` (`build-std`). The
real-mode code is `global_asm!` (`boot/bios/src/rm.S`); no external assembler is needed. The
linker script `boot/bios/link.ld` puts stage 1 at `0x7C00` and stage 2 at `0x8000`.
lld writes a raw binary by address, so `scripts/bios-image.sh` moves stage 2 to offset `0x800`
with `dd`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Menu shows configuration errors | fix the listed lines in `ospab.cfg`; it will not autoboot until fixed |
| "no volume with ospab.cfg or /boot/KERNEL" | the loader does not see the boot volume; check the ESP (UEFI) or that the BIOS boots the right drive (BIOS reads the boot drive only, and FAT32 only) |
| "ospab-boot: cannot read stage2" | stage 1 could not read stage 2: the BIOS has no INT 13h extensions, or the BIOS boot partition was overwritten |
| Menu skipped on an installed disk | one visible entry or `timeout = 0`; hold a key at power-on for `timeout = 0` |
| Last choice not remembered | UEFI: firmware variables are not persistent (some VMs, OVMF without a vars file). BIOS: not supported |
| Firmware entry says unsupported | the firmware does not offer BOOT_TO_FW_UI; use its boot key |
| No Firmware or Power off entry on BIOS | by design: no firmware setup entry on BIOS; Power off needs ACPI S5 |
| Black screen after the menu | UEFI: try `resolution = keep`. BIOS: try `resolution = 1024x768`; a BIOS without 32-bit VBE modes boots without a framebuffer |
| USB stick does not boot on BIOS | some BIOSes want an active partition in the MBR; use the BIOS boot menu's "USB-HDD" mode |

## Status and limits

- UEFI and BIOS front-ends exist; both boot from CD, from USB and from an installed disk. The BIOS
  path was tested in QEMU (SeaBIOS) only, not on real BIOS hardware yet.
- The text menu is ASCII only. BIOS: VGA text, 80x25.
- BIOS reads the boot drive only. FAT32 and ISO9660 (no Rock Ridge or Joliet names: short uppercase
  names match case-insensitively, `;1` is ignored). FAT12/16 are not read by the BIOS front-end.
- BIOS loads everything below 4 GiB. The kernel itself maps all RAM through the HHDM.
- A config error stops autoboot by design.
