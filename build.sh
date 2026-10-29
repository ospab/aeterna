#!/usr/bin/env bash
# Build script for ospab.os v2 (AETERNA): kernel, ospab-boot (BIOS + UEFI), ISO and disk image.
#
# Usage:
#   ./build.sh           - kernel + both loaders + hybrid ISO (BIOS + UEFI, bootable from CD and USB)
#                          isos/ospab-os-v2-N.iso; needs xorriso and mtools (use WSL on Windows)
#   ./build.sh kernel    - build the kernel only
#   ./build.sh image     - kernel + both loaders + GPT disk image isos/ospab-os-v2-N.img
#                          (BIOS boot partition + FAT32 ESP; no WSL or xorriso needed)
#
# Env:
#   TARGET               - rust target of the kernel (e.g. x86_64-unknown-none; empty = custom json)
#   ISO_ROOT             - staging directory for the ISO (default: a temp dir)
#   ISO_PATH             - output ISO path (default: isos/ospab-os-v2-N.iso)
#
# Requires: cargo (nightly, rust-src), dd; for the ISO also xorriso, mtools (mcopy, mmd), mkfs.vfat
# Documentation: docs/en/building.md
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
ISOS_DIR="$PROJECT_ROOT/isos"
TARGET="${TARGET:-}"
BUILD_ISO=true
BUILD_IMAGE=false
[ "$1" = "kernel" ] && BUILD_ISO=false
[ "$1" = "image" ] && { BUILD_ISO=false; BUILD_IMAGE=true; }

# --- Auto-increment ISO number ---
mkdir -p "$ISOS_DIR"
# Images share the numbering, so a build number is never reused between .iso and .img
LAST_NUM=$(ls -1 "$ISOS_DIR"/ospab-os-v2-*.iso "$ISOS_DIR"/ospab-os-v2-*.img 2>/dev/null | sed 's/.*ospab-os-v2-\([0-9]*\)\.[a-z]*$/\1/' | sort -n | tail -1)
if [ -z "$LAST_NUM" ]; then
    NEXT_NUM=1
else
    NEXT_NUM=$((LAST_NUM + 1))
fi
ISO_NAME="ospab-os-v2-${NEXT_NUM}.iso"
ISO_PATH_OVERRIDE="${ISO_PATH:-}"
# ISO_PATH may be overridden so parallel builds do not race for the same number
ISO_PATH="${ISO_PATH:-$ISOS_DIR/$ISO_NAME}"

# Build number shown by `uname -a`: the ISO/image number for numbered builds, "dev" for
# kernel-only builds and test builds written to a custom ISO_PATH.
if [ -z "${OSPAB_BUILD:-}" ]; then
    if [ -n "$ISO_PATH_OVERRIDE" ] || { [ "$BUILD_ISO" = false ] && [ "$BUILD_IMAGE" = false ]; }; then
        OSPAB_BUILD=dev
    else
        OSPAB_BUILD=$NEXT_NUM
    fi
fi
export OSPAB_BUILD

echo "=== Building ospab.os v2 (AETERNA) - build #$NEXT_NUM ==="
cd "$PROJECT_ROOT"

# --- Build DOOM C engine (if not already built) ---
DOOM_LIB="$PROJECT_ROOT/target/doom/libdoom.a"
if [ ! -f "$DOOM_LIB" ]; then
    echo "--- Building DOOM C engine ---"
    mkdir -p "$PROJECT_ROOT/target/doom"
    bash "$PROJECT_ROOT/doom_engine/build_doom.sh" "$PROJECT_ROOT/target/doom" || {
        echo "WARN: DOOM build failed; continuing without DOOM support"
    }
fi

# --- Build user programs (user/, target x86_64-unknown-oos, runtime liboos) ---
# Must run without RUSTFLAGS: it would override user/.cargo/config.toml (linker script).
echo "--- Building user programs ---"
( cd "$PROJECT_ROOT/user" && env -u RUSTFLAGS cargo +nightly build --release ) || {
    echo "ERROR: user programs failed to build" >&2
    exit 1
}

# --- Build kernel (custom target needs build-std; -A warnings avoids nightly ICE on bin crate) ---
export RUSTFLAGS="${RUSTFLAGS:--A warnings}"
# DOOM (target/doom/libdoom.a) is linked by build.rs
echo "--- Building kernel ---"
if [ -n "$TARGET" ]; then
    cargo +nightly build --release --target "$TARGET"
    KERNEL_BIN="$PROJECT_ROOT/target/$TARGET/release/ospab_os"
else
    cargo +nightly build --release
    # .cargo/config sets target = x86_64-ospab.json and build-std
    KERNEL_BIN="$PROJECT_ROOT/target/x86_64-ospab/release/ospab_os"
fi

if [ ! -f "$KERNEL_BIN" ]; then
    echo "ERROR: Kernel binary not found: $KERNEL_BIN" >&2
    exit 1
fi

echo "Kernel built: $KERNEL_BIN"

# Strip debug symbols to reduce ESP footprint
if command -v llvm-objcopy &>/dev/null; then
    llvm-objcopy --strip-debug "$KERNEL_BIN"
    echo "Stripped (llvm-objcopy): $(stat -c%s "$KERNEL_BIN" 2>/dev/null || stat -f%z "$KERNEL_BIN") bytes"
elif command -v objcopy &>/dev/null; then
    objcopy --strip-debug "$KERNEL_BIN"
    echo "Stripped (objcopy): $(stat -c%s "$KERNEL_BIN" 2>/dev/null || stat -f%z "$KERNEL_BIN") bytes"
else
    echo "Note: no objcopy found — kernel not stripped"
fi

[ "$BUILD_ISO" = false ] && [ "$BUILD_IMAGE" = false ] && exit 0

# --- Loaders: both have their own .cargo/config.toml, so RUSTFLAGS must not leak in ---
echo "--- Building UEFI loader (boot/uefi) ---"
( cd "$PROJECT_ROOT/boot/uefi" && env -u RUSTFLAGS cargo +nightly build --release ) || {
    echo "ERROR: UEFI loader failed to build" >&2
    exit 1
}
LOADER_EFI="$PROJECT_ROOT/boot/uefi/target/x86_64-unknown-uefi/release/ospab_boot.efi"

echo "--- Building BIOS loader (boot/bios) ---"
BIOS_IMG="$PROJECT_ROOT/boot/bios/target/bios.img"
bash "$PROJECT_ROOT/scripts/bios-image.sh" "$BIOS_IMG" || {
    echo "ERROR: BIOS loader failed to build" >&2
    exit 1
}

# --- GPT disk image: BIOS boot partition + FAT32 ESP, no extra tools ---
if [ "$BUILD_IMAGE" = true ]; then
    # Host tool, built with plain rustc so it ignores the kernel's .cargo/config.toml
    MKIMAGE="$PROJECT_ROOT/target/mkimage"
    case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) MKIMAGE="$MKIMAGE.exe" ;; esac
    if [ ! -f "$MKIMAGE" ] || [ "$PROJECT_ROOT/tools/mkimage.rs" -nt "$MKIMAGE" ]; then
        echo "--- Building mkimage ---"
        mkdir -p "$PROJECT_ROOT/target"
        rustc -O --edition 2021 "$PROJECT_ROOT/tools/mkimage.rs" -o "$MKIMAGE"
    fi
    IMG_PATH="$ISOS_DIR/ospab-os-v2-${NEXT_NUM}.img"
    echo "--- Creating disk image ---"
    "$MKIMAGE" "$IMG_PATH" --bios "$BIOS_IMG" \
        "EFI/BOOT/BOOTX64.EFI=$LOADER_EFI" \
        "EFI/OSPAB/OSPABLDR.EFI=$LOADER_EFI" \
        "boot/KERNEL=$KERNEL_BIN" \
        "boot/bios.img=$BIOS_IMG" \
        "boot/ospab.cfg=$PROJECT_ROOT/boot/ospab.cfg"
    echo ""
    echo "DONE. Image: $IMG_PATH (BIOS and UEFI)"
    echo "Run (BIOS):  qemu-system-x86_64 -drive file=\"$IMG_PATH\",format=raw -m 512M -serial stdio"
    echo "Run (UEFI):  add -drive if=pflash,format=raw,readonly=on,file=<edk2-x86_64-code.fd>"
    echo "VMware: convert with qemu-img convert -O vmdk; firmware BIOS or UEFI"
    exit 0
fi

# --- Hybrid ISO: El Torito BIOS + UEFI, MBR/GPT for USB sticks ---
export PATH="$PATH:/usr/sbin:/sbin"
for tool in xorriso mcopy mkfs.vfat; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "ERROR: $tool not found. The ISO needs xorriso, mtools and mkfs.vfat: run ./build.sh in WSL/Linux," >&2
        echo "       or use ./build.sh image (disk image, no extra tools)." >&2
        exit 1
    }
done
echo "--- Creating hybrid ISO ---"
KERNEL="$KERNEL_BIN" LOADER="$LOADER_EFI" BIOS="$BIOS_IMG" CFG="$PROJECT_ROOT/boot/ospab.cfg" \
    bash "$PROJECT_ROOT/scripts/mkiso.sh" "$ISO_PATH"

echo ""
echo "DONE. ISO: $ISO_PATH"
echo "Run (BIOS):  qemu-system-x86_64 -cdrom \"$ISO_PATH\" -m 512M -serial stdio"
echo "Run (UEFI):  add -drive if=pflash,format=raw,readonly=on,file=<edk2-x86_64-code.fd>"
echo "Write to USB: sudo dd if=\"$ISO_PATH\" of=/dev/sdX bs=4M status=progress && sync"
