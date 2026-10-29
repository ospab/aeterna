# Hardware

ospab.os is developed and tested in VMware Workstation and QEMU. Real hardware is untested.

| Class | Supported | Notes |
|---|---|---|
| Firmware | UEFI (x86-64) and legacy BIOS, both through ospab-boot | the ISO and an installed disk boot on both; "install alongside" needs UEFI |
| CPU | x86-64; uses SSE2, XSAVE/AVX, NX, SMEP/SMAP, RDRAND when present | one core (no SMP yet) |
| Disks | ATA PIO (IDE), AHCI (SATA), NVMe, virtio-blk | first NVMe controller, namespace 1; 512-byte and 4K sectors |
| Network | Intel e1000 family, RTL8139, RTL8169/8111, virtio-net, AMD PCnet (VMware vlance), VMware vmxnet3 | IPv4 only |
| Audio | Intel HDA, AC97, Ensoniq ES1371/ES1373/CT5880, ES1370 | 16-bit stereo, polled DMA |
| Input | PS/2 keyboard and mouse, USB keyboard and mouse through xHCI (incl. hubs), VMware absolute mouse | no EHCI/UHCI, no hot-plug |
| Video | UEFI GOP and BIOS VBE 2.0 (32-bit linear) framebuffer, VMware SVGA II | software rendering |
| Platform | ACPI (power-off, reset, power button), PCI, CMOS RTC, PIT, local APIC timer | |
| Host integration | VMware backdoor: clipboard, absolute mouse, autofit (GuestRPC) | |

## Recommended VMware settings

See the table in [Getting started](getting-started.md#vmware-workstation). The essentials:
Other 64-bit, UEFI without Secure Boot, USB 3.x, copy and paste enabled, no BusLogic SCSI.

## Display modes and autofit

The boot loader sets the first mode (the `resolution` key in its config; on a laptop it takes the
GOP mode, for example 1920x1080). After boot the kernel can change it at run time only on the
**VMware SVGA II** adapter (VMware, and QEMU with `-vga vmware`). Other machines keep the boot
mode: `display list` shows just that one.

| Item | Behaviour |
|---|---|
| Modes | any WxH from 640x480 up to the device limit and its video memory (32 bpp needs `W*H*4` bytes); the width is rounded down to a multiple of 8 (the adapter shears rows otherwise: 1366 becomes 1360) |
| Presets | 1024x768, 1280x720 (`hd`), 1280x800, 1280x1024, 1366x768, 1600x900, 1920x1080 (`fullhd`), 2560x1440 (`2k`), 3840x2160 (`4k`); only those that fit are listed |
| Switch | `display set fullhd` or Settings → Display. The framebuffer address, size and pitch are reprogrammed; the console is redrawn; the desktop lays out again |
| Saved | `/etc/display.conf` (`mode=`, `auto=`, `scale=`), applied after the console starts |
| Console font | 8x16, scaled by an integer: automatically 2x from 2560 px wide (`display scale 1\|2\|auto`) |

**Autofit** makes the guest follow the VMware window, like VMware Tools. The kernel opens the
GuestRPC channels over the backdoor (port 0x5658, command 0x1E): it tells the host
`tools.capability.resolution_set 1` on an RPCI channel and answers `Resolution_Set <w> <h>` with
`OK ` on a TCLO channel. It is polled from the console idle loop and the desktop loop, at most
every 100 ms, and is on by default under VMware. `display set` turns it off; `display auto` turns
it back on. Autofit needs the VMware option View → Autofit Guest and is a no-op outside VMware.
Without VMware Tools the host may still not send `Resolution_Set`; then `display set` works as
usual. The serial log shows every step with the `[DISPLAY]` tag (channel open, capabilities,
requests, mode changes).

## Diagnostics

Every driver logs to the first serial port with a tag such as `[AHCI]`, `[NVME]`, `[XHCI]`,
`[HDA]`, `[e1000]`. In VMware add a serial port that writes to a file to read it; in QEMU use
`-serial stdio` or `-serial file:boot.log`.
