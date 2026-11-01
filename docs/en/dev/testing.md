# Testing

ospab.os is tested in four layers: host tests of the `no_std` crates on your PC, a headless boot
in QEMU with the smoke test, boot-time self-tests inside the kernel, and manual runs in QEMU and
VMware. The main test target is VMware Workstation.

## Build commands

From the repository root, in Git Bash, WSL or Linux:

```bash
./build.sh kernel   # kernel only, build number "dev": the fast compile check
./build.sh image    # kernel + both loaders + GPT disk image isos/ospab-os-v2-N.img (no WSL)
./build.sh          # kernel + both loaders + hybrid ISO isos/ospab-os-v2-N.iso (needs xorriso, mtools, mkfs.vfat)
```

On Windows the ISO is built in WSL:

```
wsl.exe -d Debian -e bash -lc 'cd /mnt/d/ospab-projects/ospab.os-v2 && ./build.sh'
```

Details are in [Building](../building.md). Things that matter when testing:

- `N` is the next free number among `isos/ospab-os-v2-*.iso` and `*.img`. Every full build takes
  one. For a test build that must not take a number, set `ISO_PATH` to a path outside `isos/`:
  `ISO_PATH=/tmp/test.iso ./build.sh`. The build number is then `dev`. `ISO_ROOT` is the staging
  directory (give parallel builds different ones), `OSPAB_BUILD` forces the number, `NIGHTLY`
  selects the toolchain (`build.sh` prefers the GNU nightly on Windows if it is installed), and
  `TARGET` replaces the kernel target.
- `./build.sh kernel` also builds the programs in `user/` first, because the kernel embeds them
  for its self-tests.
- `uname -a` in the guest shows the build number, the short commit (`+` for uncommitted changes)
  and the date. Check it when behaviour looks stale. A Windows build and a WSL build that share
  `target/` can leave an old kernel behind.
- `scripts/mkiso.sh [OUT.iso]` assembles an ISO from already built parts (env `KERNEL`, `LOADER`,
  `BIOS`, `CFG`, `ISO_ROOT`, `PKG_DIR`). It packs the `.tmt` files from `apps/dist/` (at most 13)
  into the ISO for the installer. An old `apps/dist/` ends up in your ISO.
- `scripts/bios-image.sh [OUT]` builds the BIOS loader image (default
  `boot/bios/target/bios.img`). `scripts/checksum.sh <file> [output-dir]` writes SHA-256,
  SHA-512 and MD5 checksums of a file.

## Run in QEMU

`scripts/run-qemu.ps1` (PowerShell 7) and `scripts/run-qemu.sh` start the newest ISO with a full
set of devices. The kernel log goes to `target/qemu/serial.log`, and the QEMU monitor listens on
`telnet 127.0.0.1 55555`.

```powershell
.\scripts\run-qemu.ps1                          # BIOS, e1000, HDA audio, AHCI disk, window
.\scripts\run-qemu.ps1 -Uefi -VMware            # UEFI; vmware VGA, pcnet, AC97, AHCI
.\scripts\run-qemu.ps1 -Nic pcnet -Audio ac97 -Disk nvme
.\scripts\run-qemu.ps1 -Headless                # no window, serial on this console
.\scripts\run-qemu.ps1 -Wav C:\temp\out.wav     # record the audio output
```

Options (the shell script uses `--name value`): `-Iso`, `-Uefi`, `-Nic e1000|pcnet|rtl8139|rtl8169|virtio|vmxnet3|none`,
`-Audio hda|ac97|es1370|none`, `-AudioBackend dsound|sdl|none`, `-Wav FILE`, `-Disk ahci|nvme|ide|none`,
`-DiskSize 2G`, `-Vga std|vmware|virtio`, `-VMware`, `-Mem 1G`, `-Smp N`, `-Whpx`, `-Headless`,
`-SerialToConsole`, `-NoUsb`, `-MonitorPort N`, `-QemuDir DIR` (or the `QEMU_DIR` variable); extra
arguments are passed to QEMU. The disk image is `target/qemu/disk.qcow2`, created on first use.
The scripts assume QEMU in `D:\Toolz\qemu` unless you pass `-QemuDir`.

### The command lines behind the scripts

BIOS, serial log in the terminal:

```
qemu-system-x86_64 -m 512M -cpu max -cdrom isos/ospab-os-v2-N.iso -boot d -serial stdio
```

UEFI: add read-only firmware. QEMU for Windows ships `share/edk2-x86_64-code.fd`, Linux packages
call it `OVMF_CODE.fd`:

```
-drive if=pflash,format=raw,readonly=on,file=edk2-x86_64-code.fd
```

A disk (create it once with `qemu-img create -f qcow2 disk.qcow2 2G`). Pick one controller:

```
-drive id=disk0,if=none,format=qcow2,file=disk.qcow2
-device ide-hd,drive=disk0                                  # IDE (ATA PIO)
-device ahci,id=ahci0 -device ide-hd,drive=disk0,bus=ahci0.0  # AHCI
-device nvme,drive=disk0,serial=ospab0001                   # NVMe
-device virtio-blk-pci,drive=disk0                          # virtio-blk
```

A raw `.img` from `./build.sh image` boots as a disk: `-drive file=isos/ospab-os-v2-N.img,format=raw`.

Network (user mode; the guest is 10.0.2.15, the gateway and your PC are 10.0.2.2, DNS is 10.0.2.3):

```
-netdev user,id=n0 -device e1000,netdev=n0     # also pcnet, rtl8139, rtl8169, virtio-net-pci, vmxnet3
```

Audio (use `dsound` on Windows, `sdl` or `pa` elsewhere):

```
-audiodev dsound,id=a0 -device intel-hda -device hda-duplex,audiodev=a0
-audiodev dsound,id=a0 -device AC97,audiodev=a0
-audiodev dsound,id=a0 -device ES1370,audiodev=a0
```

Capture the sound into a WAV file instead of playing it (then check level and frequency in the
file, as for `apps/tone`):

```
-audiodev wav,id=a0,path=out.wav -device intel-hda -device hda-duplex,audiodev=a0
```

USB keyboard and tablet, display and monitor:

```
-device qemu-xhci,id=xhci -device usb-tablet,bus=xhci.0 -device usb-kbd
-vga std            # or: -vga vmware (run-time mode changes and autofit)
-display none       # headless
-monitor telnet:127.0.0.1:55555,server,nowait
```

Useful monitor commands: `sendkey ctrl-c`, `screendump shot.png -f png`, `info registers`,
`quit`. For `selftest=mem` the kernel needs a second serial port:
`-serial file:com1.log -serial file:com2.log`.

Kernel parameters come from the boot menu entry. The "ospab.os (debug)" entry uses
`mode=live debug=1 selftest=ipc persist=ro`. In the menu, `e` edits the command line of the
selected entry for one boot. Other parameters: `selftest=mem|sched|all` and `session=desktop`
(see [Boot](../boot.md)).

Speed: `-accel tcg,tb-size=256` is accurate and slow. `-accel whpx` (Windows) or `-accel kvm`
(Linux) are fast. A game that is smooth in VMware may be slow in TCG.

## The smoke test

`scripts/smoke-test.ps1` (PowerShell 7) boots an ISO headless in QEMU, waits for the line
`[  OK  ] Console: ready` on the serial port, types commands by `sendkey` through the monitor,
takes a screenshot, optionally types `shutdown`, and decides PASS or FAIL. It does not build the
ISO. Exit code 0 means PASS.

```powershell
& scripts\smoke-test.ps1                                     # newest ISO, BIOS, no disk
& scripts\smoke-test.ps1 -Firmware uefi -Disk ide -Audio hda
& scripts\smoke-test.ps1 -Commands "date -e","uname -a" -Shutdown
& scripts\smoke-test.ps1 -Iso isos\ospab-os-v2-179.iso -Nic virtio -TimeoutSec 180
```

| Parameter | Values | Default | Meaning |
|---|---|---|---|
| `-Iso` | path | newest `isos\ospab-os-v2-N.iso` | image to boot |
| `-Firmware` | `bios`, `uefi` | `bios` | UEFI uses read-only pflash firmware |
| `-Disk` | `none`, `ide`, `ahci`, `nvme` | `none` | a temporary 256 MB qcow2, removed afterwards |
| `-Nic` | `e1000`, `pcnet`, `vmxnet3`, `virtio` | `e1000` | user-mode network |
| `-Audio` | `none`, `hda`, `ac97`, `es1370` | `none` | null audio backend |
| `-TimeoutSec` | 10 to 3600 | 120 | wait for the ready line |
| `-Commands` | strings | none | typed after boot, each followed by Enter, 1.5 s apart |
| `-Shutdown` | switch | off | type `shutdown`; FAIL if QEMU is still running after 20 s |

Use `&` or an interactive `pwsh` when `-Commands` has several values; `pwsh -File` does not
bind comma-separated arrays. QEMU runs with 512 MB and `-no-reboot`.

The verdict is FAIL when the ready line never appears, when any serial line begins with
`[ FAIL ]`, when a line contains `panic`, `PANIC` or `EXCEPTION`, when QEMU exits unexpectedly,
or, with `-Shutdown`, when it does not exit. The script prints all status lines and writes
`serial.log`, `screendump.png` and the QEMU output to a time-stamped directory; it prints the
path.

The paths of QEMU, `qemu-img`, the UEFI firmware and the output directory are variables at the
top of the script (`$QemuExe`, `$QemuImg`, `$PflashFw`, `$OutRoot`). They are set for one
machine. Edit them before use, in particular `$PflashFw` for `-Firmware uefi`.

The smoke test checks the boot, not your feature. Add a `-Commands` line that exercises it
and read the screenshot and the log.

## Boot-time self-tests

Every boot runs ring 3 checks and prints `[  OK  ] Ring 3 self-test: N checks passed`:
a process round trip, two tasks with blocking calls, user pointer validation, AVX state, an ELF
program and a check that no frames leaked after the processes exit. More groups are opt-in,
by kernel parameter:

| Parameter | Runs |
|---|---|
| `selftest=ipc` | IPC and handle tests (`user/ipcsrv`, `user/ipcclient`) |
| `selftest=mem` | shared memory and the ring 3 COM2 driver (`user/memtest`, `user/uartdrv`); needs a second serial port |
| `selftest=sched` | lock rules and tasks with their own descriptor tables (`core/selftest.rs`) |
| `selftest=all` | all of them; groups can be combined: `selftest=ipc,mem` |

Shell commands that test things from inside the running system: `ring3test`, `testmode` (shows
the panic and fault screens without crashing), `verify_mem`, `verify_sched`, `verify_net`,
`verify_audio`, `soundtest`, `bench`.

When you add a feature that a ring 3 program can reach, add a case to the self-tests or a small
test program in `apps/` (see [Kernel hacking](kernel-hacking.md)).

## Reading the serial log

Everything the kernel does is on the first serial port (COM1). In QEMU: `-serial stdio` or
`-serial file:serial.log`. In VMware: add a serial port, "Use output file", and read the file
while the VM runs. The log is also the first thing to attach to a bug report.

```
[ .... ] Network                          a step has started
[  OK  ] Network: Intel e1000, 10.0.2.15 via DHCP
[  --  ] NVMe: no controller              optional hardware is not there: normal
[ WARN ] ... / [ FAIL ] ...               a problem; FAIL fails the smoke test
[DRV] Audio: probing / active             driver registry
[NET] / [AUDIO] / [ES1371] / [e1000]      detail lines of one subsystem
[RING3] ...                               self-test details
[SYSCALL] exit(0)                         a ring 3 process ended with this status
[CRITICAL] Process 7 name at 0x...        a ring 3 process faulted and was killed
[FATAL] CPU Exception: ...                a kernel fault; Fault RIP follows
```

What a ring 3 program prints with `println!` is on the serial port too. With `debug=1` the
detail lines also go to the screen. Search the saved log with `grep -n "FAIL\|CRITICAL\|FATAL"`.

## Host tests of the no_std crates

The cores of the larger programs and the filesystem are plain `no_std` crates and have ordinary
`cargo test` suites that run on your PC. They are the fastest way to find logic bugs.

The repository's `.cargo/config.toml` selects the kernel target, and `apps/.cargo/config.toml`
selects the ring 3 target. Override this in one of two ways:

- run cargo from a directory outside the repository and pass `--manifest-path`, or
- stay in the repository, use the **stable** toolchain and pass `--target <your host triple>`.

On Windows without the C++ Build Tools use the GNU host:

```
cargo +stable-x86_64-pc-windows-gnu test --manifest-path apps/beeb-core/Cargo.toml --target x86_64-pc-windows-gnu --release
cargo +stable-x86_64-pc-windows-gnu test --manifest-path apps/drift-core/Cargo.toml --target x86_64-pc-windows-gnu --release
cargo +stable-x86_64-pc-windows-gnu test --manifest-path fs/aeternafs/Cargo.toml --target x86_64-pc-windows-gnu --release
```

On Linux use `--target x86_64-unknown-linux-gnu`, or drop `--target` and run from outside the
repository. Do not use nightly inside the repository: its `build-std` setting breaks the host
build with a "duplicate lang item" error. `RUSTFLAGS` should not be set.

| Crate | Tests |
|---|---|
| `apps/beeb-core` | CPU, video, VIA, keyboard, disc and sound-chip unit tests (about 20) |
| `apps/drift-core` | unit tests and `tests/harness.rs`: scripted play of menus, launch, docking, trading, combat, saving, death and the ending. It writes screenshots as PPM files into `$DRIFT_SHOTS` (default `target/drift-shots` relative to the current directory when the test runs, which is the crate directory) |
| `fs/aeternafs` | `model` (random operations against an in-memory model), `crash` (power cut after every block write), `corrupt` (bit flips), `perf` (ignored) |

### Ignored tests and their environment variables

These need files that are not in the repository, or take long. Run them with `-- --ignored
--nocapture` and the variables set.

**beeb boot test**, `apps/beeb-core/tests/boot.rs`, test `boot_and_shoot`. It boots the machine and
saves screenshots as PNG files. The MOS ROM is yours; never add it to the repository.

```powershell
$env:BEEB_MOS = 'C:\roms\os12.rom'
$env:BEEB_OUT = 'C:\temp\beeb'
$env:BEEB_SHOTS = '60,300'
cargo +stable-x86_64-pc-windows-gnu test --manifest-path apps/beeb-core/Cargo.toml --target x86_64-pc-windows-gnu --release --test boot -- --ignored --nocapture
```

| Variable | Meaning |
|---|---|
| `BEEB_MOS` | path to the 16 KiB MOS ROM. Required: the test returns at once without it |
| `BEEB_OUT` | directory for `beeb_NNNNN.png` (default: the current directory) |
| `BEEB_FRAMES` | frames to run (default 300) |
| `BEEB_SHOTS` | comma-separated frame numbers to save; the last frame is always saved |
| `BEEB_KEYS` | key script, `frame:KeyName:d` for down and `frame:KeyName:u` for up, comma separated |
| `BEEB_BASIC` | a language ROM, inserted in slot 15 |
| `BEEB_SSD` | a disc image |
| `BEEB_SHIFT_BREAK` | set (any value) to reset with Shift held, which boots the disc |
| `BEEB_FAKE_LOADER` | `echo` or any other value: a tiny test ROM instead of a language |
| `BEEB_TRACE`, `BEEB_TRACEFRAME`, `BEEB_JITTER` | debug traces |

**beeb audio test**, `apps/beeb-core/tests/sound.rs`, test `boot_audio` (`--test sound`). Same
`BEEB_MOS`, `BEEB_FRAMES` (default 600), `BEEB_KEYS`, `BEEB_BASIC`, `BEEB_SSD`, `BEEB_SHIFT_BREAK`;
`BEEB_WIN` is the analysis window in frames (default 25) and `BEEB_WAV` a file to write the
audio to. It prints the level and zero-crossing frequency of each window.

**6502 conformance**, in `apps/beeb-core/src/cpu.rs`: `klaus_functional` needs `KLAUS_BIN` (path
to the functional test binary, optionally `KLAUS_SUCCESS`, a hex address, default 3469) and
`klaus_decimal` needs `KLAUS_DEC_BIN` (optionally `KLAUS_DEC_DONE`). Run with `--lib -- --ignored
klaus`. The binaries are third-party files and stay out of the repository.

**drift screenshots**: set `DRIFT_SHOTS` to choose where the harness writes `*.ppm` and `*.wav`.
There are no ignored drift tests.

**AeternaFS performance**:
`cargo test --release --test perf -- --ignored --nocapture --test-threads=1` in `fs/aeternafs`
(100 000 small files, then a 1 GiB file). `AETERNA_PERF_DIR` selects the directory for the
1 GiB image.

## Host tools

**tmt**, the package tool (`tools/tmt`). Build it with `bash tools/tmt/build.sh`, which writes
`tools/tmt/bin/tmt` (`.exe` on Windows). It uses the stable toolchain.

```
tmt keygen [--force] [--key FILE] [--pub FILE]
tmt pack <manifest.toml> [-o OUTDIR] [--set KEY=VALUE]
tmt list <file.tmt>
tmt verify <file.tmt>
tmt repo add <repo-dir> <file.tmt>...
tmt repo index <repo-dir>
tmt repo sign <repo-dir> [--key FILE]
tmt repo verify <repo-dir> [--pub FILE]
```

The default signing key is `%USERPROFILE%\.ospab\tmt.key` (`$HOME/.ospab/tmt.key`). It is the
release key: do not copy, print or commit it, and do not run `keygen --force` over it. For
tests use `--key` with a key of your own. `tools/tmt/e2e-qemu.ps1` is an end-to-end test of
`tomato` against good and tampered repositories in QEMU; its header explains the setup.

**oosfs**, AeternaFS images (`tools/oosfs`). Build:

```
cd tools/oosfs
cargo +stable-x86_64-pc-windows-gnu build --release --target x86_64-pc-windows-gnu
```

(The `--target` is needed inside the repository; see above.) Usage:

```
oosfs mkfs <image> --size 2G [--label L]
oosfs ls|cat|get|put|rm|mkdir|mv|stat|info <image> ...
oosfs put <image> <src> <dest> [-r]
oosfs snap create|list|delete|rollback <image> [name]
oosfs fsck <image> [--deep]
```

`--offset <bytes>` or `--part N` (GPT, 512-byte sectors) works on a partition inside a disk
image. In Git Bash, paths that start with `/` are rewritten by MSYS; set
`MSYS_NO_PATHCONV=1` or use PowerShell. See [AeternaFS](../aeternafs.md).

**mkimage** (`tools/mkimage.rs`) is built and called by `./build.sh image`.

## VMware notes

- Create the VM as in [Getting started](../getting-started.md): Other 64-bit, BIOS or UEFI with
  Secure Boot off, USB 3.x, NVMe or SATA disk, NAT, sound card, no BusLogic SCSI.
- Attach the ISO. To test a disk image, convert it:
  `qemu-img convert -O vmdk isos/ospab-os-v2-N.img disk.vmdk`.
- Add a serial port that writes to a file for the log. Edit the `.vmx` while the VM is off.
- Graphics are the VMware SVGA II adapter. Run-time mode changes and autofit work only there.
  A program that draws must call `screen::flush()`.
- Sound is an Ensoniq ES1371 by default. Check HDA and AC97 in QEMU.
- Copy and paste with the host (Ctrl+V) needs "guest isolation: copy and paste" enabled.
- Test every change that touches boot, display, input or sound in VMware. QEMU is a good first
  filter and not a replacement.
