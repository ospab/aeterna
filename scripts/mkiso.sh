#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Hybrid BIOS + UEFI ISO with ospab-boot.
#
#   scripts/mkiso.sh [OUT.iso]      (run in WSL/Linux after the kernel, boot/uefi and boot/bios are built;
#                                    ./build.sh does all of that)
#
# What is inside:
#   El Torito BIOS   boot/bios.img (stage1 + stage2, no emulation, boot info table)
#   El Torito UEFI   FAT16 image with BOOTX64.EFI, the kernel, ospab.cfg and bios.img; it is
#                    also appended as GPT partition 2 (type EF00), and El Torito points at that
#                    partition, so the image exists once
#   ISO9660 tree     the same files, for the BIOS loader on CD and for browsing
#   USB (dd)         MBR = stage1 of ospab-boot with the position of stage2 patched in (offset 0x40),
#                    plus the GPT of the appended partition. BIOS boots the MBR, UEFI the ESP.
# Requires: xorriso, mtools, mkfs.vfat, dd.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL="${KERNEL:-$ROOT/target/x86_64-ospab/release/ospab_os}"
LOADER="${LOADER:-$ROOT/boot/uefi/target/x86_64-unknown-uefi/release/ospab_boot.efi}"
BIOS="${BIOS:-$ROOT/boot/bios/target/bios.img}"
CFG="${CFG:-$ROOT/boot/ospab.cfg}"
OUT="${1:-$ROOT/isos/ospab-os-v2.iso}"
for f in "$KERNEL" "$LOADER" "$BIOS" "$CFG"; do
    [ -f "$f" ] || { echo "missing $f (./build.sh builds everything)" >&2; exit 1; }
done

STAGE="${ISO_ROOT:-$(mktemp -d /tmp/ospab-iso.XXXXXX)}"
rm -rf "$STAGE"; mkdir -p "$STAGE"
[ -n "$ISO_ROOT" ] || trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/root/EFI/BOOT" "$STAGE/root/EFI/OSPAB" "$STAGE/root/boot"
cp "$LOADER" "$STAGE/root/EFI/BOOT/BOOTX64.EFI"
cp "$LOADER" "$STAGE/root/EFI/OSPAB/OSPABLDR.EFI"
cp "$KERNEL" "$STAGE/root/boot/KERNEL"
cp "$CFG"    "$STAGE/root/boot/ospab.cfg"
cp "$BIOS"   "$STAGE/root/boot/bios.img"

# EFI system image: FAT16 (firmware reads FAT12/16/32 on removable media), payload + 4 MiB, at least
# 16 MiB. It must stay below 32 MiB: the El Torito sector count is 16 bits (65535 sectors) and
# some firmware (OVMF) refuses a FAT volume larger than that.
PAYLOAD_KB=$(du -sk "$STAGE/root" | cut -f1)
IMG_MB=$(( PAYLOAD_KB / 1024 + 4 ))
[ "$IMG_MB" -lt 16 ] && IMG_MB=16
[ "$IMG_MB" -gt 31 ] && { echo "payload too big for the 31 MiB EFI image ($PAYLOAD_KB KiB)" >&2; exit 1; }
IMG="$STAGE/efiboot.img"
dd if=/dev/zero of="$IMG" bs=1M count="$IMG_MB" status=none
mkfs.vfat -F 16 -n OSPAB "$IMG" >/dev/null
export MTOOLS_SKIP_CHECK=1
mmd -i "$IMG" ::/EFI ::/EFI/BOOT ::/EFI/OSPAB ::/boot
mcopy -i "$IMG" "$STAGE/root/EFI/BOOT/BOOTX64.EFI"   ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$IMG" "$STAGE/root/EFI/OSPAB/OSPABLDR.EFI" ::/EFI/OSPAB/OSPABLDR.EFI
mcopy -i "$IMG" "$STAGE/root/boot/KERNEL"            ::/boot/KERNEL
mcopy -i "$IMG" "$STAGE/root/boot/ospab.cfg"         ::/boot/ospab.cfg
mcopy -i "$IMG" "$STAGE/root/boot/bios.img"          ::/boot/bios.img

# MBR template for the USB case: the first sector of bios.img (stage1).
dd if="$BIOS" of="$STAGE/mbr.bin" bs=512 count=1 status=none

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
xorriso -as mkisofs -quiet -R -J -V OSPAB_OS \
    -c boot/boot.cat \
    -b boot/bios.img -no-emul-boot -boot-load-size 4 -boot-info-table \
    -eltorito-alt-boot -e --interval:appended_partition_2:all:: -no-emul-boot \
    -isohybrid-mbr "$STAGE/mbr.bin" \
    -append_partition 2 0xef "$IMG" -appended_part_as_gpt \
    -o "$OUT" "$STAGE/root"

# USB boot: tell the MBR copy of stage1 where stage2 is (bios.img + 2048 bytes), in 512-byte sectors.
LBA=$(xorriso -indev "$OUT" -find /boot/bios.img -exec report_lba 2>/dev/null | awk '/File data lba:/ {print $6; exit}')
[ -n "$LBA" ] || { echo "cannot find boot/bios.img in the ISO" >&2; exit 1; }
S2=$(( (LBA + 1) * 4 ))
perl -e "print pack('Q<', $S2)" | dd of="$OUT" bs=1 seek=64 conv=notrunc status=none
echo "ISO: $OUT ($(du -h "$OUT" | cut -f1)), BIOS + UEFI, ospab-boot (boot/bios.img at LBA $LBA)"
