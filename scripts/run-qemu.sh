#!/usr/bin/env bash
# Run ospab.os in QEMU with the full set of devices the kernel has drivers for.
#
#   scripts/run-qemu.sh                 # newest ISO, BIOS, e1000, HDA audio, AHCI disk, window
#   scripts/run-qemu.sh --uefi          # boot through UEFI (edk2) instead of BIOS
#   scripts/run-qemu.sh --vmware        # devices close to a VMware Workstation VM
#   scripts/run-qemu.sh --nic pcnet --audio ac97 --disk nvme
#   scripts/run-qemu.sh --headless      # no window; serial to the terminal
#   scripts/run-qemu.sh --help
#
# Logs go to target/qemu/: serial.log (kernel log), and the monitor listens on
# telnet 127.0.0.1:$MONITOR_PORT (sendkey / screendump / info ...).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QEMU_DIR="${QEMU_DIR:-/d/Toolz/qemu}"
QEMU="$QEMU_DIR/qemu-system-x86_64.exe"
QEMU_IMG="$QEMU_DIR/qemu-img.exe"
[ -x "$QEMU" ] || QEMU="$(command -v qemu-system-x86_64 || true)"
[ -x "$QEMU_IMG" ] || QEMU_IMG="$(command -v qemu-img || true)"
[ -n "$QEMU" ] || { echo "qemu-system-x86_64 not found (set QEMU_DIR)" >&2; exit 1; }

# ── defaults ────────────────────────────────────────────────────────────────
ISO=""
FIRMWARE=bios        # bios | uefi
NIC=e1000            # e1000 | pcnet | rtl8139 | rtl8169 | virtio | vmxnet3 | none
AUDIO=hda            # hda | ac97 | es1370 | none
AUDIO_BACKEND=dsound # dsound | sdl | wav | none
WAV_FILE=""
DISK=ahci            # ahci | nvme | ide | none
DISK_SIZE=2G
VGA=std              # std | vmware | virtio
MEM=1G
SMP=1
ACCEL=tcg            # tcg | whpx
DISPLAY_OPT=""       # empty = QEMU default window
SERIAL=file          # file | stdio
MONITOR_PORT=55555
USB=yes
EXTRA=()

usage() {
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

Options:
  --iso PATH          ISO to boot (default: newest isos/ospab-os-v2-N.iso)
  --uefi | --bios     firmware (default: bios)
  --nic MODEL         e1000 | pcnet | rtl8139 | rtl8169 | virtio | vmxnet3 | none   (default: $NIC)
  --audio MODEL       hda | ac97 | es1370 | none                                    (default: $AUDIO)
  --wav FILE          record audio output to FILE instead of playing it
  --disk MODEL        ahci | nvme | ide | none  (image: target/qemu/disk.qcow2)    (default: $DISK)
  --disk-size SIZE    size when the disk image is created                          (default: $DISK_SIZE)
  --vga MODEL         std | vmware | virtio                                         (default: $VGA)
  --vmware            VMware-like set: vmware VGA, pcnet NIC, ac97 audio, ahci disk
  --mem SIZE          RAM (default: $MEM)
  --smp N             CPUs (default: $SMP; the kernel uses only one for now)
  --whpx              hardware acceleration via Windows Hypervisor Platform (faster, less exact)
  --headless          no window; implies --serial stdio
  --serial stdio      kernel log to this terminal instead of target/qemu/serial.log
  --no-usb            no xHCI controller / USB tablet
  --monitor-port N    telnet monitor port (default: $MONITOR_PORT; 0 = off)
  -- ARGS...          pass the rest straight to QEMU
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --iso) ISO="$2"; shift ;;
        --uefi) FIRMWARE=uefi ;;
        --bios) FIRMWARE=bios ;;
        --nic) NIC="$2"; shift ;;
        --audio) AUDIO="$2"; shift ;;
        --wav) AUDIO_BACKEND=wav; WAV_FILE="$2"; shift ;;
        --disk) DISK="$2"; shift ;;
        --disk-size) DISK_SIZE="$2"; shift ;;
        --vga) VGA="$2"; shift ;;
        --vmware) VGA=vmware; NIC=pcnet; AUDIO=ac97; DISK=ahci ;;
        --mem) MEM="$2"; shift ;;
        --smp) SMP="$2"; shift ;;
        --whpx) ACCEL=whpx ;;
        --headless) DISPLAY_OPT="none"; SERIAL=stdio ;;
        --serial) SERIAL="$2"; shift ;;
        --no-usb) USB=no ;;
        --monitor-port) MONITOR_PORT="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; EXTRA=("$@"); break ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 1 ;;
    esac
    shift
done

# Windows QEMU wants Windows paths.
winpath() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else echo "$1"; fi; }

# ── ISO ─────────────────────────────────────────────────────────────────────
if [ -z "$ISO" ]; then
    ISO="$(ls "$ROOT"/isos/ospab-os-v2-*.iso 2>/dev/null | sed 's/.*-\([0-9]*\)\.iso$/\1 &/' | sort -n | tail -1 | cut -d' ' -f2- || true)"
fi
[ -n "$ISO" ] && [ -f "$ISO" ] || { echo "no ISO found; build one with ./build.sh (WSL) or pass --iso" >&2; exit 1; }

OUT="$ROOT/target/qemu"
mkdir -p "$OUT"

ARGS=(-m "$MEM" -smp "$SMP" -cpu max -no-reboot)
if [ "$ACCEL" = whpx ]; then
    ARGS+=(-accel whpx -accel tcg,tb-size=256)
else
    ARGS+=(-accel tcg,tb-size=256)
fi

# Firmware
if [ "$FIRMWARE" = uefi ]; then
    CODE="$QEMU_DIR/share/edk2-x86_64-code.fd"
    [ -f "$CODE" ] || { echo "UEFI firmware not found: $CODE" >&2; exit 1; }
    ARGS+=(-drive "if=pflash,format=raw,readonly=on,file=$(winpath "$CODE")")
fi

# Boot medium
ARGS+=(-cdrom "$(winpath "$ISO")" -boot d)

# Disk (for the installer and persistence)
if [ "$DISK" != none ]; then
    IMG="$OUT/disk.qcow2"
    if [ ! -f "$IMG" ]; then
        [ -n "$QEMU_IMG" ] || { echo "qemu-img not found; use --disk none" >&2; exit 1; }
        "$QEMU_IMG" create -f qcow2 "$(winpath "$IMG")" "$DISK_SIZE" >/dev/null
        echo "created $IMG ($DISK_SIZE)"
    fi
    ARGS+=(-drive "id=disk0,if=none,format=qcow2,file=$(winpath "$IMG")")
    case "$DISK" in
        ahci) ARGS+=(-device ahci,id=ahci0 -device ide-hd,drive=disk0,bus=ahci0.0) ;;
        nvme) ARGS+=(-device nvme,drive=disk0,serial=ospab0001) ;;
        ide)  ARGS+=(-device ide-hd,drive=disk0) ;;
        *) echo "unknown disk model: $DISK" >&2; exit 1 ;;
    esac
fi

# Network (user-mode: guest 10.0.2.15, gateway 10.0.2.2, DNS 10.0.2.3)
if [ "$NIC" != none ]; then
    ARGS+=(-netdev user,id=n0)
    case "$NIC" in
        e1000)   ARGS+=(-device e1000,netdev=n0) ;;
        pcnet)   ARGS+=(-device pcnet,netdev=n0) ;;
        rtl8139) ARGS+=(-device rtl8139,netdev=n0) ;;
        rtl8169) ARGS+=(-device rtl8169,netdev=n0) ;;
        virtio)  ARGS+=(-device virtio-net-pci,netdev=n0) ;;
        vmxnet3) ARGS+=(-device vmxnet3,netdev=n0) ;;
        *) echo "unknown nic model: $NIC" >&2; exit 1 ;;
    esac
else
    ARGS+=(-nic none)
fi

# Audio
if [ "$AUDIO" != none ]; then
    if [ "$AUDIO_BACKEND" = wav ]; then
        ARGS+=(-audiodev "wav,id=a0,path=$(winpath "$WAV_FILE")")
    else
        ARGS+=(-audiodev "$AUDIO_BACKEND,id=a0")
    fi
    case "$AUDIO" in
        hda)    ARGS+=(-device intel-hda -device hda-duplex,audiodev=a0) ;;
        ac97)   ARGS+=(-device AC97,audiodev=a0) ;;
        es1370) ARGS+=(-device ES1370,audiodev=a0) ;;
        *) echo "unknown audio model: $AUDIO" >&2; exit 1 ;;
    esac
fi

# Video
ARGS+=(-vga "$VGA")
[ -n "$DISPLAY_OPT" ] && ARGS+=(-display "$DISPLAY_OPT")

# USB (xHCI + absolute pointer)
[ "$USB" = yes ] && ARGS+=(-device qemu-xhci,id=xhci -device usb-tablet,bus=xhci.0)

# Serial = kernel log
if [ "$SERIAL" = stdio ]; then
    ARGS+=(-serial stdio)
else
    ARGS+=(-serial "file:$(winpath "$OUT/serial.log")")
fi

# Monitor
[ "$MONITOR_PORT" != 0 ] && ARGS+=(-monitor "telnet:127.0.0.1:$MONITOR_PORT,server,nowait")

echo "ISO:      $ISO"
echo "Firmware: $FIRMWARE   NIC: $NIC   Audio: $AUDIO ($AUDIO_BACKEND)   Disk: $DISK   VGA: $VGA   Accel: $ACCEL"
[ "$SERIAL" = file ] && echo "Serial:   $OUT/serial.log"
[ "$MONITOR_PORT" != 0 ] && echo "Monitor:  telnet 127.0.0.1 $MONITOR_PORT"

exec "$QEMU" "${ARGS[@]}" "${EXTRA[@]}"
