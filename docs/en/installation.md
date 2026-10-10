# Installation

Run `install` in the live system, or pick **ospab.os Installer** in the boot menu. The installer
is a full-screen wizard: Welcome → Disk → Options → Confirm → Install → Done. Esc goes back; Esc or
`q` quits on any page before anything is written.

The installed system boots through UEFI only, so the machine (or VM) must use UEFI firmware.

## Mode 1: erase a disk

The whole disk is repartitioned:

| Partition | Contents |
|---|---|
| EFI System Partition (FAT32) | `\EFI\BOOT\BOOTX64.EFI` (ospab-boot), `\boot\KERNEL`, `\boot\ospab.cfg` |
| AETERNA | the saved writable filesystem layer (persistence) |

You choose the disk, the ESP size, a host name and a locale, then confirm by typing `yes`. The
installer copies the files, verifies them by reading them back (9 checks) and offers **Reboot
now**.

## Mode 2: install alongside other systems

For a disk that already holds Windows and/or Linux. The installer:

- reads and checks both copies of the GPT and lists the existing partitions;
- creates **one** new `AETERNA` partition in the largest free gap;
- adds a folder `\EFI\ospab\` (loader, config, kernel) to the **existing** FAT32 ESP;
- never moves, resizes or overwrites other partitions, and never touches `\EFI\Microsoft`,
  `\EFI\BOOT` or the folders of other systems;
- never writes UEFI NVRAM variables.

Before writing it shows a dry run listing every sector range and file it will write, and you
confirm by typing `install`. Every write is checked against that list.

It refuses, with an explanation and without writing anything, if the disk uses MBR only, if the
backup GPT is damaged, if there is no free space or no ESP, if the ESP is not FAT32, or if
`\EFI\ospab` already exists. It does not shrink partitions: free space first with Windows Disk
Management or a Linux partition tool.

### Booting the system installed alongside

The firmware does not know about the new loader, so choose one of these:

- **Firmware boot menu**: "Boot from file" → the ESP → `\EFI\ospab\OSPABLDR.EFI`.
- **GRUB** (from your Linux): add to `/etc/grub.d/40_custom`, then run `update-grub`:
  ```
  menuentry "ospab.os" {
      insmod part_gpt
      insmod fat
      search --file --set=root /EFI/ospab/OSPABLDR.EFI
      chainloader /EFI/ospab/OSPABLDR.EFI
  }
  ```
- **efibootmgr** (from Linux) creates a firmware boot entry; use the disk and ESP partition
  number shown by `lsblk`:
  ```
  sudo efibootmgr -c -d /dev/sdX -p N -L ospab.os -l '\EFI\ospab\OSPABLDR.EFI'
  ```

## After installation

- Disconnect the ISO, otherwise the firmware boots the CD again.
- The boot log shows `Boot loader: ospab-boot`, and `Persistence:` reports the saved area.
- Changes in the filesystem are written to disk by `sync` and automatically about every
  10 seconds.

## Known limits

- Disks with 4096-byte logical sectors are refused in alongside mode.
- If the machine has both SATA and NVMe disks, persistence uses the SATA disk.
- In VMware the final "Reboot now" may hang the VM; powering it off and on is safe, the
  installation is already complete.
