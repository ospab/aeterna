# Getting started

## What you need

- An ISO: `isos/ospab-os-v2-N.iso` from a build (see [Building](building.md)) or a release.
- VMware Workstation (the main test target) or QEMU.

## VMware Workstation

Create a new virtual machine with these settings:

| Setting | Value | Why |
|---|---|---|
| Guest operating system | **Other**, version **Other 64-bit** | "Other" (32-bit) starts 32-bit UEFI firmware, which cannot load a 64-bit loader |
| Firmware | **BIOS** or **UEFI** (Secure Boot **off**) | ospab-boot has a BIOS and a UEFI front-end; it is not signed, so Secure Boot must stay off |
| USB controller | **USB 3.x** | USB keyboards and mice need the xHCI driver; USB 2 (EHCI/UHCI) is not supported yet |
| Hard disk | NVMe, SATA or IDE, 2 GB or more | all three are supported |
| Network adapter | NAT | e1000, vlance and vmxnet3 all work |
| Sound card | default | ES1371 |
| Guest isolation | copy and paste **enabled** | lets Ctrl+V paste the Windows clipboard |
| SCSI controller | none, or LSI Logic | the BusLogic controller is refused for 64-bit guests |

Attach the ISO to the CD/DVD drive and power on. ospab-boot shows a menu for 5 seconds, in either firmware mode:

- **ospab.os Live**: the full system running from the CD.
- **ospab.os Desktop**: the desktop session.
- **ospab.os Installer**: starts the installer directly.
- **ospab.os (debug)**, **Memory test**, **Reboot**, **Power off**; **Firmware settings** on UEFI only.

The installer's "Erase entire disk" mode makes a disk that boots on both BIOS and UEFI. "Install
alongside other systems" needs UEFI and is refused when the live system runs on BIOS.

## QEMU

```
qemu-system-x86_64 -cdrom isos/ospab-os-v2-N.iso -m 512M -serial stdio
```

This starts the BIOS path (SeaBIOS). For a USB stick instead of a CD: `-drive file=isos/ospab-os-v2-N.iso,format=raw,if=none,id=u -device qemu-xhci -device usb-storage,drive=u`.

Useful additions: `-cpu max` (AVX, SMEP/SMAP, RDRAND), `-device intel-hda -device hda-duplex`
for sound, `-device qemu-xhci -device usb-kbd` for a USB keyboard, and a UEFI firmware such as
OVMF via `-drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd`.

## The boot log

Each boot step prints one status line on the screen and on the serial port:

```
[  OK  ] Network: Intel e1000, 10.0.2.15 via DHCP
[  --  ] NVMe: no controller
[ WARN ] ...
[ FAIL ] ...
```

`--` means optional hardware is not present, which is normal. The boot ends with
`[  OK  ] Ring 3 self-test: N checks passed` and `[  OK  ] Console: ready`.

## First commands

```
# help                 all commands; help <cmd> for details
# tutor                a short guided tour
# uname -a             kernel version and build number
# date                 local time; date -e prints seconds since 2012-08-09
# ip addr              network address
# curl ipinfo.io       a real HTTPS request
# tomato -Sy           sync the package repository
# install              install to a disk
# shutdown             power off through ACPI
```

Next: [Installation](installation.md), [Shell and tools](shell.md).
