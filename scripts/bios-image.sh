#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Build the BIOS front-end of ospab-boot (boot/bios) and write bios.img:
#   offset 0x000  stage1 (512 bytes: boot sector / MBR / El Torito boot image)
#   offset 0x800  stage2 (loaded by stage1 to 0x8000)
# The linker puts stage2 at 0x400 (see boot/bios/link.ld); this moves it to the second
# 2048-byte CD sector.
#
#   scripts/bios-image.sh [OUT]       default OUT: boot/bios/target/bios.img
# Works in Git Bash and WSL. Needs cargo (nightly with rust-src) and dd.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/boot/bios/target/bios.img}"
( cd "$ROOT/boot/bios" && env -u RUSTFLAGS cargo +nightly build --release )
RAW="$ROOT/boot/bios/target/x86_64-unknown-none/release/ospab_bios"
mkdir -p "$(dirname "$OUT")"
dd if=/dev/zero of="$OUT" bs=512 count=4 status=none
dd if="$RAW" of="$OUT" bs=512 count=1 conv=notrunc status=none
dd if="$RAW" of="$OUT" bs=512 skip=2 seek=4 conv=notrunc status=none
echo "BIOS image: $OUT ($(stat -c%s "$OUT") bytes)"
