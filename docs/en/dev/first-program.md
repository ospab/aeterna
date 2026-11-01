# Your first program

This page takes a program from an empty directory to a running process in a VM. The example,
`wordcount`, reads a file and prints the number of lines, words and bytes. Every step below was
checked against the repository.

## What you need

- Rust nightly with the `rust-src` component. Programs are built with `build-std` for the custom
  target `x86_64-unknown-oos` (`user/x86_64-unknown-oos.json`).

  ```
  rustup toolchain install nightly --component rust-src
  ```

- On Windows without the Visual Studio C++ Build Tools, use the GNU nightly. The build of
  `compiler_builtins` runs a build script on your PC and the MSVC toolchain cannot link it:

  ```
  rustup toolchain install nightly-x86_64-pc-windows-gnu --component rust-src
  ```

  Then write `cargo +nightly-x86_64-pc-windows-gnu` wherever this page says `cargo +nightly`.
  Cross-compiling needs no C compiler: the program is linked with `rust-lld`.
- An ISO of ospab.os and a VM ([Getting started](../getting-started.md)).
- `RUSTFLAGS` must not be set. It replaces the flags in `apps/.cargo/config.toml`, which carry the
  linker script, and the program will not link.

## 1. Create the crate

Programs live in the `apps/` workspace. Make a directory and two files:

`apps/wordcount/Cargo.toml`

```toml
[package]
name = "wordcount"
description = "Counts lines, words and bytes of a file"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
liboos = { path = "../../user/liboos" }
```

`apps/wordcount/src/main.rs`

```rust
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Your Name
//! wordcount: counts lines, words and bytes of a file.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use liboos::println;

liboos::entry!(main);

fn main(args: liboos::Args) -> i32 {
    let Some(path) = args.get(1) else {
        println!("usage: wordcount <file>");
        return 2;
    };
    let fd = liboos::open(path, 0);
    if fd < 0 {
        println!("wordcount: cannot open {} (error {})", path, fd);
        return 1;
    }
    let fd = fd as u64;
    let mut data: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = liboos::read(fd, &mut buf);
        if n < 0 {
            println!("wordcount: read error {}", n);
            liboos::close(fd);
            return 1;
        }
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n as usize]);
    }
    liboos::close(fd);

    let lines = data.iter().filter(|&&b| b == b'\n').count();
    let words = data.split(|b| b.is_ascii_whitespace()).filter(|w| !w.is_empty()).count();
    println!("{} lines, {} words, {} bytes", lines, words, data.len());
    0
}
```

Then add the crate to `members` in `apps/Cargo.toml`:

```toml
members = ["hello-tmt", "cowsay", "calc", ..., "wordcount"]
```

What the pieces do:

- `#![no_std]` and `#![no_main]`: there is no standard library and no Rust `main`. liboos
  provides `_start`, which sets up the heap and calls your function.
- `liboos::entry!(main)` registers `fn main(args: liboos::Args) -> i32`. The return value is the
  exit status. The shell shows it as `$?`.
- `extern crate alloc;` gives you `Vec`, `String`, `Box`, `format!`. The heap is set up before
  `main` and grows on demand.
- `println!` writes to standard output. A panic prints `panic: ...` and exits with status 101.
- `Args::get(0)` is the program name as typed in the shell, `get(1)` is the first argument.

The workspace profile uses `panic = "abort"` and `opt-level = "s"`. Do not change `panic`: there
is no unwinding.

## 2. Build

```
cd apps
cargo +nightly build --release -p wordcount
```

The binary is `apps/target/x86_64-unknown-oos/release/wordcount`, a static ELF linked at 4 MiB. The
first build also builds `core` and `alloc` for the target and takes a minute or two.

## 3. Write the package manifest

`apps/pkg/wordcount.toml`

```toml
name = "wordcount"
version = "0.1.0"
description = "Counts lines, words and bytes of a file"
arch = "x86_64"
depends = []

[[files]]
src = "../target/x86_64-unknown-oos/release/wordcount"
dest = "/usr/bin/wordcount"
```

- `src` is relative to the manifest, so `../target/...` is `apps/target/...`.
- `dest` must be an absolute path without `..`. `/usr/bin` is on the shell's `$PATH`
  (`/bin:/sbin:/usr/bin`).
- Package names use letters, digits, `-`, `_` and `.`, up to 63 characters.
- `version` is the package version, separate from the crate version. Raise it for every change you
  publish.

Anything else in the manifest is rejected: `tmt` knows only `name`, `version`, `description`,
`arch` (`any`, `x86_64`, `aarch64`), `depends`, `kind` and `[[files]]` with `src` and `dest`.

## 4. Pack

PowerShell 7, from the repository root:

```
.\apps\build.ps1 -Only wordcount
```

This builds the host tool `tmt` if needed, builds the crate, and packs `apps\pkg\wordcount.toml`
into `apps\dist\wordcount-0.1.0.tmt`. The cargo package and the manifest must have the same name,
because `-Only` selects both by it.

Git Bash, WSL or Linux:

```
bash apps/build.sh
```

`build.sh` has no `-Only`: it builds every crate in `apps/` and packs every manifest. To pack just
one, build it as in step 2 and run the packer yourself:

```
bash tools/tmt/build.sh                       # once, builds tools/tmt/bin/tmt
cd apps && ../tools/tmt/bin/tmt pack pkg/wordcount.toml -o dist
```

Useful checks: `tmt list apps/dist/wordcount-0.1.0.tmt` lists the files, `tmt verify` checks the
checksum.

On Windows `build.sh` and `build.ps1` use `nightly-x86_64-pc-windows-gnu` when it is installed,
like the kernel's `./build.sh`. The MSVC nightly needs the Visual C++ Build Tools to build
`compiler_builtins`; without them install the GNU one:
`rustup toolchain install nightly-x86_64-pc-windows-gnu --profile minimal -c rust-src`.

## 5. Get it into the VM

The VM needs a network (QEMU user networking and VMware NAT both work). Serve `apps/dist` from
your PC with any static file server. For example, with Python:

```
cd apps/dist
python -m http.server 8000
```

In the VM, download the package and install it. In QEMU's user networking the PC is `10.0.2.2`. In
VMware NAT it is the PC's address on the NAT network (VMnet8). Your firewall must allow the port.

```
# curl -o /tmp/wordcount.tmt http://10.0.2.2:8000/wordcount-0.1.0.tmt
# tomato install /tmp/wordcount.tmt
# echo "one two three" > /tmp/t.txt
# wordcount /tmp/t.txt
1 lines, 3 words, 14 bytes
# echo $?
0
```

(`curl -o FILE URL` works although the `curl` usage text does not list `-o`.)

`tomato install` treats a target that ends in `.tmt` or contains `/` as a local file. It checks the
checksum stored in the file. It does not check a signature: a local file is trusted because you
put it there.

`tomato list` shows installed packages, `tomato files wordcount` its files, `tomato remove
wordcount` removes it.

### Faster loop: run the ELF directly

While you are still changing the code, skip the package. Any ELF file can be run by path, with no
execute bit:

```
# curl -o /tmp/wc http://10.0.2.2:8000/wordcount
# /tmp/wc /tmp/t.txt
```

For that, serve the directory `apps/target/x86_64-unknown-oos/release/` instead. The RAM
filesystem is lost at reboot, and the saved layer is written only after a short delay, so
download again after a restart.

### Your own repository

To install by name (`tomato install wordcount`) you need a repository: `tmt repo add`, `tmt repo
index` and `tmt repo sign` (see [Packages](../packages.md)). The index must be signed with the key
whose public half is compiled into the system (`userland/tomato/repo_key.pub`). The maintainers'
private key is not in the repository. For your own tests, generate a key with `tmt keygen`, put
the public key in `userland/tomato/repo_key.pub` and build your own image. The default address is
`https://tmt.ospab.org/x86_64/`; `repo=<url>` lines in `/etc/tomato.conf` add others, and plain
`http://` is accepted for local testing. To get a package into the official repository, ask the
maintainers (see [Contributing](../../../CONTRIBUTIONS.md)).

## 6. Debug

- **Serial log.** The kernel log and everything a program prints to stdout and stderr also go to
  the serial port (COM1). In QEMU use `-serial stdio` or `-serial file:serial.log`. In VMware add
  a serial port that writes to a file. This is the first place to look. See [Testing](testing.md).
- **`println!`.** The simplest debugger. Output goes to the screen and the serial log. For
  stderr use `liboos::write(2, b"text\n")`; liboos has no `eprintln!`.
- **Exit status.** The shell puts it in `$?`:

  | Status | Meaning |
  |---|---|
  | 0 | success, or whatever your `main` returned |
  | 101 | Rust panic. The message is printed as `panic: ...` before the exit. |
  | 130 | Ctrl+C |
  | 139 | the kernel killed the process after a fault. The shell prints `terminated by the kernel (fault)` and the serial log has a line `[CRITICAL] Process N name at 0x.... Terminating.` with the faulting address. |
  | 126 | the file is not a loadable program; the shell says why |
  | 127 | command not found |

  The shell keeps only the low 8 bits of the status.
- **Faults.** A bad pointer in a system call returns an error (-10), it does not kill you. A bad
  access in your own code (null pointer, stack overflow, writing read-only memory) is a page fault
  and ends the process. The user stack is 64 KiB: do not put large arrays on it, use `Vec` or
  `Box`.
- **Hangs.** Ctrl+C stops a program that is blocked in a call or in the shell's wait loop. A
  program that owns the screen or the raw keyboard is stopped at its next `key_event`,
  `flush` or `sleep_ms`. A loop that calls none of them cannot be interrupted by Ctrl+C when the
  program owns the screen, so make the main loop call one of them.
- **`ps`** lists processes; `dmesg` shows the kernel log.

## Next

[liboos reference](liboos.md) describes what the program can do. If the program is a game, read
[Writing a game](games.md).
