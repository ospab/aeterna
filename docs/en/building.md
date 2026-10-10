# Building

## Requirements

- Rust **nightly** with the `rust-src` component (the kernel and user programs use `build-std`
  and JSON target specifications).
- Stable Rust for the host tools (`tools/tmt`), selected automatically by its
  `rust-toolchain.toml`.
- For the ISO: `xorriso`, `mtools` and `mkfs.vfat`. On Windows these come from WSL; the kernel,
  user programs, loader and disk image build natively in Git Bash.
- For the DOOM build: a C compiler in WSL/Linux (`target/doom/libdoom.a` is reused once built).

## Build targets

```bash
./build.sh kernel   # kernel only: a fast compile check (build number "dev")
./build.sh          # kernel + loader + hybrid BIOS/UEFI ISO: isos/ospab-os-v2-N.iso
./build.sh image    # kernel + loader + GPT/FAT32 disk image: isos/ospab-os-v2-N.img (no WSL)
```

On Windows run the ISO build through WSL:

```
wsl.exe -d Debian -e bash -lc 'cd /mnt/d/ospab-projects/ospab.os-v2 && ./build.sh'
```

What `build.sh` does, in order: builds the ring-3 programs in `user/` (without `RUSTFLAGS`, which
would override their linker script), builds the kernel for `x86_64-ospab.json`, builds the
ospab-boot loader in `boot/uefi`, then assembles the ISO with Limine and our loader as an extra
menu entry, or the disk image with `tools/mkimage.rs`.

## Build number

`N` is the next free number among `isos/ospab-os-v2-*.iso` and `*.img`. It is compiled into the
kernel together with the short git commit (a `+` means uncommitted changes) and the UTC date:

```
# uname -a
AETERNA ospab 1.1.0 #181 e8f4f4f+ 2026-10-09 x86_64 ospab.os
```

Environment overrides:

| Variable | Effect |
|---|---|
| `ISO_PATH` | write the ISO to this path instead of the numbered name (the build number becomes `dev`) |
| `ISO_ROOT` | staging directory for the ISO tree; give parallel builds different ones |
| `OSPAB_BUILD` | force the build number |
| `LIMINE_BIN_DIR`, `LIMINE_CONF_SRC` | Limine binaries and config |

## Other parts

| Part | Command |
|---|---|
| ospab-boot loader | `cd boot/uefi && cargo build --release` |
| Packaged programs and repository | `bash apps/build.sh [repo DIR]` or `.\apps\build.ps1 [-Repo DIR]` |
| tmt host tool | `bash tools/tmt/build.sh` |
| GUI mockups (host) | see `gui/` |

## Smoke test

`scripts/smoke-test.ps1` boots an ISO headless in QEMU, waits for `Console: ready`, types
commands, takes a screenshot and fails on any `[ FAIL ]`, panic or exception:

```powershell
& scripts\smoke-test.ps1 -Firmware uefi -Disk ide -Audio hda -Commands "uname -a","date -e" -Shutdown
```

Parameters: `-Iso`, `-Firmware bios|uefi`, `-Disk none|ide|ahci|nvme`,
`-Nic e1000|pcnet|vmxnet3|virtio`, `-Audio none|hda|ac97|es1370`, `-TimeoutSec`, `-Commands`,
`-Shutdown`.

## Boot-time self-test

Every boot runs ring-3 checks (process round trip, two tasks with blocking system calls,
user-pointer validation, AVX state, an ELF program, frame leaks). The IPC checks are slower and
run only with the kernel command line option `selftest=ipc`.

## Tips

- If a Windows build and a WSL build share `target/`, WSL may reuse a stale kernel; check the
  build number in the boot log.
- Some sources use CRLF line endings. Git Bash `sed` and `grep` strip carriage returns, so prefer
  an editor or `perl` for scripted edits.
