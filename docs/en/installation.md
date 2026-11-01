# Installation

Run `install` in the live system, or pick **ospab.os Installer** in the boot menu. The installer
is a full-screen wizard: Welcome → Disk → Options → Confirm → Install → Done. Esc goes back; Esc or
`q` quits on any page before anything is written.

The first page offers three modes. Press `L` on the first page to switch the installer between
English and Russian.

A disk made by **Mode 1** boots on both BIOS and UEFI machines. **Mode 2** (alongside) needs UEFI:
it is refused when the live system runs on BIOS, because it would have to replace the boot code in the
MBR of the other systems. Both modes work from a live system started on UEFI. **Mode 3** (upgrade)
works on both.

## Options

Modes 1 and 2 show six option pages between Disk and Confirm. Enter edits or continues, the arrow
keys change a value, Esc goes back. Nothing is written until the summary page is confirmed.

1. **Account.** Host name, user name, password (optional, asked twice) and automatic login.
   There is no root user: the account only names the user and, if a password is set, protects the
   login. The password is stored as a salted SHA-256 hash in `/etc/passwd`, never as text.
2. **Language and region.** Installer language, system locale, keyboard layout (applies at once),
   time zone and the mode of the hardware clock (UTC, or local time when Windows is installed).
3. **Disk layout.** ESP size and the size of the AETERNA data partition (default: all free space).
   Mode 2 shows the free gap instead.
4. **Boot.** Default menu entry, menu timeout and screen resolution. They are written to `ospab.cfg`.
5. **Network.** DHCP or a static address, mask, gateway and DNS server, and whether the clock is set
   over NTP.
6. **Packages.** Packages found on the installation medium (`/packages/*.tmt`) that are installed
   into the new system without a network.

The summary page lists the disk layout, the files written to the ESP, the account, the options and
the files of the saved layer. The installer also writes `/var/log/install.log`.

On the installed system:

- With automatic login off, the console asks `login:` and `password:`. With it on, the user is logged
  in at once. The prompt is `name@host:path$` and the home directory is `/home/name`.
- The live system uses a user named `live` without a password.
- The settings are plain files in the saved layer: `/etc/hostname`, `/etc/passwd`, `/etc/login.conf`,
  `/etc/locale`, `/etc/keyboard`, `/etc/timezone`, `/etc/rtc_mode`, `/etc/network.conf`.

## Mode 1: erase a disk

The whole disk is repartitioned:

| Partition | Contents |
|---|---|
| MBR (sector 0) | protective MBR with the BIOS boot code (stage 1 of ospab-boot) |
| BIOS boot partition (LBA 34..2047, 1 MiB) | stage 2 of ospab-boot, for BIOS machines |
| EFI System Partition (FAT32) | `\EFI\BOOT\BOOTX64.EFI` (ospab-boot), `\boot\KERNEL`, `\boot\ospab.cfg` |
| AETERNA | the saved writable filesystem layer (persistence) |

You choose the disk and the options above, then confirm by typing `yes`. The
installer copies the files, verifies them by reading them back (10 checks, including the BIOS boot code) and offers **Reboot
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

On BIOS the welcome page shows "Not available on BIOS" and does not continue. The layout of both modes
and the BIOS boot flow are described in [Boot](boot.md).

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

## Mode 3: upgrade an existing installation

Replaces the loader, the kernel and `ospab.cfg` on the ESP of a system made by this installer
(whole-disk layout or alongside). The installer finds installations by the identity record in the
AETERNA partition, lets you pick one and shows exactly what it will write. You confirm by typing
`upgrade`.

- The old kernel is kept as `KERNEL.OLD` and the new `ospab.cfg` has the entry
  **ospab.os (previous)** that boots it. An older `KERNEL.OLD` is dropped.
- Timeout, default entry, resolution, theme and extra entries of the old `ospab.cfg` are kept.
- The AETERNA partition (account, settings, packages, your files), the GPT and all other
  partitions are never written. Writes outside the ESP are refused.
- Order: new files into free clusters, the FAT, the directory entries (the switch), then a
  read-back of everything.

Later updates come from the network with `tomato upgrade`, see [Packages](packages.md) and
[Boot](boot.md).

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
