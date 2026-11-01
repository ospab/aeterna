# Contributing to ospab.os

This file covers the workflow for patches, code conventions, licensing, bug reports and the rules
for AI agents. For how to write programs and drivers see the
[developer guide](docs/en/dev/README.md); for build and test commands see
[Building](docs/en/building.md) and [Testing](docs/en/dev/testing.md).

---

## Getting started

### Prerequisites

| Tool | Purpose |
|---|---|
| Rust nightly with `rust-src` | Kernel, loaders, ring 3 programs (`build-std`, JSON targets) |
| Rust stable | Host tools (`tools/tmt`, `tools/oosfs`) and host tests |
| `xorriso`, `mtools`, `mkfs.vfat` | Hybrid ISO. On Windows they come from WSL |
| QEMU | Testing. VMware Workstation is the main test target |
| `dd`, a C compiler in WSL/Linux | BIOS loader image, DOOM (optional) |

On Windows without the Visual C++ Build Tools use the GNU toolchain
(`nightly-x86_64-pc-windows-gnu`). The kernel uses the custom target `x86_64-ospab.json`; cargo
picks it up from `.cargo/config.toml`, and `rustup target add` is not needed.

### Clone and build

```bash
git clone https://github.com/ospab/aeterna.git
cd aeterna
git submodule update --init      # doom_engine
./build.sh kernel                # fast compile check
./build.sh                       # ISO: isos/ospab-os-v2-N.iso (in WSL/Linux)
```

`./build.sh image` makes a GPT disk image without WSL. Details: [Building](docs/en/building.md).

### Run

```bash
qemu-system-x86_64 -m 512M -cpu max -cdrom isos/ospab-os-v2-N.iso -serial stdio
```

`N` is the number of your build (`ls isos`). More devices (disk, network, sound, UEFI): the
scripts `scripts/run-qemu.ps1` and `scripts/run-qemu.sh`, and the command lines in
[Testing](docs/en/dev/testing.md).

---

## Codebase layout

The full map is in [Kernel hacking](docs/en/dev/kernel-hacking.md). In short:

| Path | Description |
|---|---|
| `src/main.rs` | `_start`, boot sequence, boot log, boot self-tests |
| `src/lib.rs` | library root, module declarations |
| `src/terminal.rs` | the console and its commands |
| `src/userspace/plum/` | the shell |
| `src/userspace/axon/` | coreutils and tools |
| `src/installer.rs`, `src/installer/` | disk installer |
| `src/pci.rs`, `src/acpi/`, `src/xhci/` | PCI, ACPI, USB |
| `arch/x86_64/` | GDT, IDT, PIC/APIC, keyboard, framebuffer, serial, panic |
| `core/` | scheduler, system calls, objects and handles, ELF loader, locks |
| `mm/` | physical memory, page tables, heap, user copies |
| `vfs/` | virtual filesystem, RamFS, overlay, `/proc`, persistence |
| `drivers/` | storage, audio, GPU, driver registry |
| `net/` | network drivers and stack, TLS, OSTP |
| `userland/grape/`, `userland/tomato/`, `userland/seed/` | editor, package manager, service table |
| `fs/aeternafs/` | AeternaFS v2 filesystem crate |
| `gui/` | `oos-ui` toolkit |
| `user/` | `liboos` and ring 3 test programs |
| `apps/` | ring 3 programs and packages (the SDK) |
| `boot/` | ospab-boot loader (BIOS, UEFI) |
| `tools/` | host tools: `tmt`, `oosfs`, `mkimage.rs` |
| `doom_engine/` | doomgeneric (git submodule) |

---

## Code conventions

### Rust

- `#![no_std]` in the kernel, `liboos` and the game cores. Use `extern crate alloc` for `Vec`,
  `String` and `BTreeMap`.
- Every public function and type gets a doc comment (`///`).
- Every `unsafe` block gets a `// SAFETY:` comment that states the invariant it relies on.
- Use `crate::` for internal paths.
- Do not use `static mut` for shared state in new code; follow the
  [locking rules](docs/en/kernel.md). Do not panic on bad input from ring 3 or from hardware.
- A driver that does not find its device returns `false`.

### Naming

| Item | Style | Example |
|---|---|---|
| Modules, functions, variables | `snake_case` | `init_driver`, `send_packet` |
| Types, traits, enums | `PascalCase` | `PacketBuffer`, `NetDriver` |
| Constants | `SCREAMING_SNAKE_CASE` | `MAX_PACKET_SIZE` |
| Files | `snake_case.rs` | `rtl8139.rs`, `ramfs.rs` |

### File organisation

- Each subsystem has its own directory with a `mod.rs`. Trait definitions may go in `trait.rs`.
- New files must be included by a `mod` line, or they are not compiled.
- Ring 3 programs go in `apps/<name>/`; the shell and coreutils are in `src/userspace/`.
- Architecture-specific code goes in `arch/x86_64/`.

### Logging

- Subsystem messages start with a bracketed tag: `[NET]`, `[AHCI]`, `[AUDIO]`.
- Serial messages end with `\r\n`.
- A driver reports its result with one boot status line (`boot_log!` in `src/main.rs`):
  `Ok`, `Warn`, `Fail`, `Absent` (optional hardware is not there), `Info`.
- Kernel event log entries go through `klog` and show up in `dmesg`.
- Remove debug traces before you send the change.

### License headers

The project is **AGPL-3.0-only** ([LICENSE](LICENSE)). Every source file starts with:

```rust
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Your Name
```

Kernel files use the block form (`/* SPDX-License-Identifier: AGPL-3.0-only ... */`). New crates
set `license = "AGPL-3.0-only"` in `Cargo.toml`.

---

## Third-party code and files

- Use code only if its license is compatible with AGPL-3.0-only and you can say where it comes
  from. Keep its notice and license text, and keep it in its own directory (`doom_engine/` is a
  git submodule with its own GPL-2.0 license).
- No third-party binaries in the repository: ROMs, disc images, game data (`*.rom`, `*.ssd`,
  `*.wad`), firmware, 6502 test suites. `.gitignore` already excludes them, together with `*.tmt`,
  `dist/`, `isos/` and `target/`. Programs ask the user for such files; tests read them from
  environment variables.
- Do not commit ISO images, logs or compiler crash dumps (`rustc-ice-*.txt`).
- Never commit or print signing keys. The package signing key `%USERPROFILE%\.ospab\tmt.key`
  belongs to the maintainers; test with your own keys.

---

## Where help is needed

The plan is in [ROADMAP.md](ROADMAP.md) (in Russian). Stage 3 is the main work: move services out
of ring 0, one at a time.

- Ring 3 services: `seed`, console, storage, network, sound as separate processes.
- Gaps in the ring 3 API ([liboos reference](docs/en/dev/liboos.md), "What does not exist yet"):
  directory listing, `stat`, `mkdir`, `unlink`, environment, starting programs, mouse input.
- Drivers: USB beyond xHCI, more NICs and audio codecs.
- Host tests for more `no_std` code, and tests for the shell and the VFS.
- Documentation: Russian pages that are missing (`drift`, `olang`, `kernel`), checks of the
  guides against the source.

### Good first contributions

- Add a coreutils-style command ([Kernel hacking](docs/en/dev/kernel-hacking.md), "Add a shell
  command").
- Write a small program or game as a package ([Your first program](docs/en/dev/first-program.md)).
- Add depth to the `tutor` topics.
- Add tests for `beeb-core`, `drift-core` or `aeternafs`.
- Fix an error in the docs.

---

## Workflow

1. **Branch** from `master`. One branch, one subject.
2. **Develop and test.** [Testing](docs/en/dev/testing.md) has the commands.
   - `./build.sh kernel` passes for every kernel change; the host tests pass for the crate you
     touched (`beeb-core`, `drift-core`, `aeternafs`).
   - Boot a build in QEMU, and in VMware if you touched boot, display, input or sound. Look at
     the serial log for `[ FAIL ]`, `[CRITICAL]` and `[FATAL]`.
   - The kernel build runs with warnings off, so for `apps/`, host crates and tools leave no new
     warnings.
   - Test builds must not take an ISO number: set `ISO_PATH` outside `isos/`.
3. **Commit.** Small, focused commits that build. Do not mix a refactor with a feature, and do not
   reformat files you do not change.
4. **Open a pull request** that says what changed and why, how you tested it (build, VM,
   firmware, devices), and includes the relevant serial log. Add screenshots if the screen
   output changes.

### Commit messages

The history uses one line per commit:

```
area: what changed, lower case, no full stop
```

```
apps/build.ps1: -Only to build, pack and upload selected packages; beeb 0.1.1
ring 3: sound output syscalls (audio_open/write/queued/close/volume)
fs/aeternafs: AeternaFS v2, a copy-on-write filesystem; tools/oosfs
boot: ospab-boot for BIOS, own hybrid ISO, Limine removed
tomato: apt-style commands (update, upgrade, install, remove, search, list, show, files)
```

- The area is the directory, crate, program or subsystem (`boot`, `apps`, `tomato`, `drift`,
  `ring 3`, `docs`). Use the word earlier commits in that area used.
- Put the reason and details in the body after an empty line.
- Older commits use `feat(scope):` and `fix(scope):`. Do not mix both styles in one pull request.
- Raise the version in `apps/pkg/<name>.toml` when the content of a package changes.

### Documentation

- English in `docs/en` is primary and `docs/ru` is the translation. A change in a command, a
  system call or a file format changes the English page in the same pull request; the Russian page
  follows. If you cannot write Russian, say in the pull request that the translation is missing.
- Keep `README.md` and `README_ru.md` in step with the docs tables.
- Style: plain technical language, short sentences, no marketing, no emoji. Say what does not
  exist yet. Verify commands and names against the source.

---

## Acceptance checklist

Boot a build and check at least:

- [ ] Boot ends with `[  OK  ] Console: ready` and no `[ FAIL ]` line (the smoke test checks this)
- [ ] `uname -a` shows the build you expect
- [ ] `ls /` returns the standard directory tree
- [ ] `ping 10.0.2.2` works in QEMU (if you changed network code)
- [ ] `grape /tmp/test.txt` opens, saves and exits cleanly (if you changed the editor)
- [ ] `seed status` runs (if you changed init)
- [ ] `tomato install` of a local `.tmt` and running the program (if you changed packages or `liboos`)
- [ ] `./build.sh kernel` passes

---

## Rules for AI agents

The rules in `CLAUDE.md` apply to every agent that works in this repository. A person who uses
an agent is responsible for what it does.

- Change files with the editor tools (Edit and Write), not with scripts that rewrite source
  (no Python, sed, awk or PowerShell edit scripts), and leave no helper scripts in the repository.
  If an edit does not apply, find out why: CRLF line endings, tabs, control characters.
- Agents do not run `git commit` or `git push`. The person in charge does.
- Stay inside the files the task names; others may be editing the rest.
- Do not read, print or copy the signing key `%USERPROFILE%\.ospab\tmt.key`.
- ROMs, disc images and other third-party binaries never go into the repository.
- Do not consume ISO numbers in `isos/`: test builds set `ISO_PATH` outside it.
- Never kill all QEMU processes, only the one you started.

---

## Reporting a bug

Open an issue in the GitHub repository (`github.com/ospab/aeterna`). Include:

1. **The build.** Output of `uname -a`:

   ```
   # uname -a
   AETERNA ospab 1.1.0 #181 e8f4f4f+ 2026-10-09 x86_64 ospab.os
   ```

   A `+` after the commit means local changes. Say how you got the ISO.
2. **The machine.** VMware or QEMU and its version, BIOS or UEFI, disk controller, network card,
   sound card, display mode, RAM. For real hardware, the model.
3. **What you did**, step by step from boot. For a program: package and version (`tomato list`).
4. **What you expected and what happened.** For a program, the exit status (`echo $?`).
5. **The serial log**, whole, from boot to the problem ([Testing](docs/en/dev/testing.md),
   "Reading the serial log"). `[ WARN ]`, `[ FAIL ]`, `[CRITICAL]` and `[FATAL]` lines matter
   most. `dmesg` shows the kernel event log.
6. **A screenshot** if the screen looks wrong; the panic screen shows the fault address.
7. **Whether it repeats**, and whether the previous build had the same problem.

Remove personal data from logs before you attach them.

---

## License

By contributing to ospab.os you agree to license your contributions under the
GNU Affero General Public License v3.0 (AGPL-3.0-only), see [LICENSE](LICENSE).
