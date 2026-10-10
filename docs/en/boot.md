# Boot

ospab-boot is the loader of ospab.os. Today it runs on UEFI only (`boot/uefi`). The live ISO
still carries Limine (BIOS and UEFI); ospab-boot is an extra entry there. A BIOS front-end is
not written yet.

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

## BootInfo contract

Defined in `arch/x86_64/boot/ospab_proto.rs` (version 1), shared by loader and kernel.

| Item | Value |
|---|---|
| RDI | physical address of `BootInfo` |
| RSI | magic `OSPABOOT` (`0x544F4F4241504F53`) |
| RDX | HHDM offset (`0xFFFF800000000000`) |
| CPU state | long mode, CPL0, IF=0, DF=0, 64 KiB+ stack with a zero return address |
| Addresses | all physical; the kernel adds the HHDM offset |
| HHDM | RAM up to max(4 GiB, highest RAM), read/write, plus the framebuffer |
| Kernel | PT_LOAD segments at their linked addresses, physically contiguous, 4 KiB pages |
| Memory map | sorted, no overlaps; framebuffer is its own region |
| Command line | NUL-terminated, from the entry (or the edited line) |
| Modules | path, size, address, name of each `module` line |

## Config file

Search order: `ospab.cfg` next to the loader (same directory), then `/boot/ospab.cfg`, then
built-in defaults (one entry that boots `/boot/KERNEL`). The first file found is used alone.

Format: INI-like text, `key = value`, `[section]` headers, `#` comment lines (whole line only).
Sections were chosen over a flat list because each entry has its own keys and validation per
type needs a clear entry boundary. The first line that matters is `version = 1`.

### Global keys (before any header, or under `[global]`)

| Key | Values | Default | Meaning |
|---|---|---|---|
| `version` | `1` | required | format version |
| `timeout` | `0`..`3600`, `off` | `5` | seconds before the default boots. `0`: no menu unless a key is waiting. `off`: wait forever |
| `default` | entry id | first visible entry | entry that boots on timeout |
| `remember_last` | yes/no | yes | preselect the last booted `ospab`/`efi-chainload` entry (UEFI variable `OspabLastEntry`) |
| `resolution` | `auto`, `max`, `keep`, `WxH` | `auto` | graphics mode handed to the kernel |
| `serial` | yes/no | no | mirror loader messages to COM1 |
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
| ospab.os | (empty) | default |
| ospab.os Desktop | `session=desktop` | desktop session, logout returns to the console |
| ospab.os (debug) | `debug=1 selftest=ipc persist=ro` | detail log on screen and serial; IPC self-tests; the saved filesystem layer is read but never written |
| Memory test | `passes=1` | see below |
| Firmware settings | | sets `OsIndications` BOOT_TO_FW_UI and resets; says so if the firmware lacks it |
| Reboot, Power off | | firmware ResetSystem |

The live ISO adds Live and Installer (`mode=live`, `mode=installer`).
Kernel parameters: `debug=1`, `persist=ro`, `selftest=ipc|mem|all`, `session=desktop`, `mode=`.
`selftest=mem` needs a second serial port (COM2).

## Memory test

A loader feature, not a kernel mode: the tester is `boot/common/memtest.rs`. It allocates free
RAM above 1 MiB from the firmware in 32 MiB chunks, tests each chunk and frees it, so firmware
and loader memory is never overwritten (memory the firmware holds is not tested).
Per pass: walking ones and zeros (8 shifts each), address in address (plus complement),
moving inversions (`0x55..`, `0x00FF..`, up then down), random pattern (plus complement).
Screen: progress bar, current test, pass, time, error count; Esc aborts. The result screen
shows PASSED / FAILED / ABORTED, the amount tested and the first 16 errors (address, expected,
actual, test); it is also printed to serial when `serial = yes`.
Options in the entry command line: `passes=N` (1..99), `limit=MiB`, `inject=1` (flip one bit
after the first write, to check that errors are reported).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Menu shows configuration errors | fix the listed lines in `ospab.cfg`; it will not autoboot until fixed |
| "no volume with ospab.cfg or /boot/KERNEL" | the loader does not see the boot volume; check the ESP contents |
| Menu skipped on an installed disk | one visible entry or `timeout = 0`; hold a key at power-on for `timeout = 0` |
| Last choice not remembered | firmware variables are not persistent (some VMs, OVMF without a vars file) |
| Firmware entry says unsupported | the firmware does not offer BOOT_TO_FW_UI; use its boot key |
| Black screen after the menu | try `resolution = keep` |

## Status and limits

- UEFI only. BIOS stage2, a Limine-free hybrid ISO and a USB-bootable image are planned.
- The text menu uses the firmware console (ASCII only).
- A config error stops autoboot by design.
