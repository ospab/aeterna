# Hardware

ospab.os is developed and tested in VMware Workstation and QEMU. Real hardware is untested.

| Class | Supported | Notes |
|---|---|---|
| Firmware | UEFI (x86-64), legacy BIOS through Limine on the ISO | the installed system boots via UEFI only |
| CPU | x86-64; uses SSE2, XSAVE/AVX, NX, SMEP/SMAP, RDRAND when present | one core (no SMP yet) |
| Disks | ATA PIO (IDE), AHCI (SATA), NVMe, virtio-blk | first NVMe controller, namespace 1; 512-byte and 4K sectors |
| Network | Intel e1000 family, RTL8139, RTL8169/8111, virtio-net, AMD PCnet (VMware vlance), VMware vmxnet3 | IPv4 only |
| Audio | Intel HDA, AC97, Ensoniq ES1371/ES1373/CT5880, ES1370 | 16-bit stereo, polled DMA |
| Input | PS/2 keyboard and mouse, USB keyboard and mouse through xHCI (incl. hubs), VMware absolute mouse | no EHCI/UHCI, no hot-plug |
| Video | UEFI GOP framebuffer, VMware SVGA II | software rendering |
| Platform | ACPI (power-off, reset, power button), PCI, CMOS RTC, PIT, local APIC timer | |
| Host integration | VMware backdoor: clipboard, absolute mouse | |

## Recommended VMware settings

See the table in [Getting started](getting-started.md#vmware-workstation). The essentials:
Other 64-bit, UEFI without Secure Boot, USB 3.x, copy and paste enabled, no BusLogic SCSI.

## Diagnostics

Every driver logs to the first serial port with a tag such as `[AHCI]`, `[NVME]`, `[XHCI]`,
`[HDA]`, `[e1000]`. In VMware add a serial port that writes to a file to read it; in QEMU use
`-serial stdio` or `-serial file:boot.log`.
