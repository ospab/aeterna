#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# UEFI-only ISO with ospab-boot and no Limine.
#
#   scripts/mkiso-uefi.sh [OUT.iso]      (run in WSL/Linux after ./build.sh kernel or image)
#
# Everything the loader needs (BOOTX64.EFI, the kernel, ospab.cfg) is inside the El Torito
# EFI FAT image, so the firmware finds it the same way from a CD and from a USB stick
# (isohybrid GPT). The ISO9660 tree carries the same files for the installer and for
# browsing. Requires: xorriso, mtools, mkfs.vfat.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL="$ROOT/target/x86_64-ospab/release/ospab_os"
LOADER="$ROOT/boot/uefi/target/x86_64-unknown-uefi/release/ospab_boot.efi"
CFG="$ROOT/boot/ospab.cfg"
OUT="${1:-$ROOT/isos/ospab-os-v2-uefi.iso}"
for f in "$KERNEL" "$LOADER" "$CFG"; do
    [ -f "$f" ] || { echo "missing $f (build first: ./build.sh kernel; cd boot/uefi && cargo build --release)" >&2; exit 1; }
done

STAGE="$(mktemp -d /tmp/ospab-uefi-iso.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/root/EFI/BOOT" "$STAGE/root/EFI/OSPAB" "$STAGE/root/boot"
cp "$LOADER" "$STAGE/root/EFI/BOOT/BOOTX64.EFI"
cp "$LOADER" "$STAGE/root/EFI/OSPAB/OSPABLDR.EFI"
cp "$KERNEL" "$STAGE/root/boot/KERNEL"
cp "$CFG"    "$STAGE/root/boot/ospab.cfg"

# EFI system image: payload size + 8 MiB headroom, FAT32 needs at least ~33 MiB.
PAYLOAD_KB=$(du -sk "$STAGE/root" | cut -f1)
IMG_MB=$(( PAYLOAD_KB / 1024 + 8 ))
[ "$IMG_MB" -lt 40 ] && IMG_MB=40
IMG="$STAGE/root/boot/efiboot.img"
dd if=/dev/zero of="$IMG" bs=1M count="$IMG_MB" status=none
mkfs.vfat -F 32 -n OSPAB "$IMG" >/dev/null
export MTOOLS_SKIP_CHECK=1
mmd -i "$IMG" ::/EFI ::/EFI/BOOT ::/EFI/OSPAB ::/boot
mcopy -i "$IMG" "$STAGE/root/EFI/BOOT/BOOTX64.EFI"   ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$IMG" "$STAGE/root/EFI/OSPAB/OSPABLDR.EFI" ::/EFI/OSPAB/OSPABLDR.EFI
mcopy -i "$IMG" "$STAGE/root/boot/KERNEL"            ::/boot/KERNEL
mcopy -i "$IMG" "$STAGE/root/boot/ospab.cfg"         ::/boot/ospab.cfg

mkdir -p "$(dirname "$OUT")"
xorriso -as mkisofs -quiet -R -J -V OSPAB_OS \
    -e boot/efiboot.img -no-emul-boot \
    -append_partition 2 0xef "$IMG" -appended_part_as_gpt \
    -o "$OUT" "$STAGE/root"
echo "ISO: $OUT ($(du -h "$OUT" | cut -f1)), UEFI only, ospab-boot"
