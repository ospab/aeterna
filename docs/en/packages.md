# Packages

## Using tomato

```
# tomato update              download the package index and check its signature
# tomato search [text]       search the synced index
# tomato install calc          install a package and its dependencies
# tomato update && tomato upgrade             sync and upgrade installed packages
# tomato list               list installed packages (-Qi info, -Ql files)
# tomato remove calc          remove a package (refused while another package depends on it)
# tomato install file.tmt      install a local package file
```

The default repository is `https://tmt.ospab.org/x86_64/`. Add `repo=<url>` lines to
`/etc/tomato.conf` to use another one (plain `http://` is allowed for local testing).

## How packages are checked

- The index is signed with Ed25519. The public key is compiled into the system
  (`userland/tomato/repo_key.pub`). An index with a bad signature is refused, and the stored
  index is checked again every time it is used.
- Every package's size and SHA-256 are listed in the signed index and checked before anything is
  installed.
- `tomato remove` removes only the files the package installed.

Known gap: nothing stops someone from replaying an older index that was signed correctly.

## The .tmt format

A `.tmt` file is a package: a header with name, version, architecture, dependencies and
description, followed by the files with their destination paths and checksums. Build them with
the host tool `tmt`, or inside the system with `tomato --tmt pack`.

### Driver packages

A package with a `[driver]` table in its manifest is a driver for the device manager. Its files
are installed under `/usr/lib/drivers/<name>/` and `tmt pack` adds a `driver.conf` there. Old
packages and old `tomato` are not affected. Format and rules: [Drivers in ring 3](dev/drivers.md).

```toml
[driver]
match = ["pci:8086:100e", "pci-class:02:00"]   # vendor:device, or class:subclass (hex)
exec = "/usr/lib/drivers/e1000/drv-e1000"      # optional, default: the first file
```

## Updating the system

The package `ospab-base` is the system itself: the kernel, the UEFI loader and the BIOS loader.
Its version is the kernel version plus the build number (`1.1.0.191`); `uname -a` shows the
running build. The files are written to the EFI System Partition, not to the RAM filesystem.

```
# tomato update
# tomato upgrade            shows "system: 1.1.0.190 -> 1.1.0.191, reboot required"
# tomato upgrade -y         the same, without the question before the ESP is written
# tomato install ospab-base
# tomato system             running build, installed system package, boot counter
```

What `tomato upgrade` does for the system package:

1. Finds the ESP of this installation (a whole-disk install uses `\boot\`, an install alongside
   other systems uses `\EFI\ospab\`). If it cannot tell which ESP it booted from, it refuses.
2. Prints the files it will write and asks `[y/N]` (not with `-y`).
3. Writes `KERNEL.NEW` and the new loader as `.NEW` files, reads them back and compares.
4. Switches in one directory-entry write per file: `KERNEL` becomes `KERNEL.OLD` and `KERNEL.NEW`
   becomes `KERNEL`; the old loader is kept as `.OLD`. There is no moment without a bootable kernel.
5. Adds the entry "ospab.os (previous)" (boots `KERNEL.OLD`) to `ospab.cfg` if it is missing.
6. Writes the boot counter `UPDATE.ST` (2 tries). The new kernel clears it when its console is
   ready. If it does not do that twice, the loader boots the previous kernel on its own and says
   why in the menu. See [Boot](boot.md), "Updating the system".
7. On a whole-disk install with a BIOS boot partition, also writes the new BIOS stage 2 and the
   stage 1 boot code (the partition table in the MBR is kept).

Rules:

- Only the files above are written. Other files on the ESP (Windows, Linux) are never touched.
- The live system refuses: `tomato` there says that system updates need an installed system.
- A system package is accepted only from the signed repository. `tomato install file.tmt`
  refuses it, because the file's own checksum cannot detect a forgery.
- `tomato remove ospab-base` is refused.
- While an update is not confirmed yet (or after a fallback), a new update keeps the last known
  good `KERNEL.OLD` instead of replacing it with the unconfirmed kernel.

A system package is a normal `.tmt` with `kind=system` in its metadata. Its files do not have
paths; each has a role: `esp:kernel` (required), `esp:loader` (UEFI loader), `esp:bios`
(`bios.img`: stage 1 at 0, stage 2 at 0x800). Older packages have no `kind` and install as before.
Manifest (`apps/pkg/ospab-base.toml` is a template):

```toml
name = "ospab-base"
version = "1.1.0.191"
kind = "system"
[[files]]
src = "ospab_os"
dest = "esp:kernel"
```

Build it after `./build.sh`:

```
.\apps\build.ps1 -Base -Build 191 -Repo D:\ospab-projects\tmt-repo     # PowerShell
BASE=191 bash apps/build.sh repo /path/to/tmt-repo                      # Git Bash, WSL, Linux
```

`tmt pack <manifest> --set KEY=VALUE` replaces `@KEY@` in a manifest; the template uses
`@VERSION@`, `@KERNEL@`, `@LOADER@`, `@BIOS@`. Without `-Base` the template is not packed.
The kernel is about 10 MiB, so a system package may be up to 24 MiB and is not kept in the cache.

## Writing a program

Programs are Rust `no_std` binaries for the target `x86_64-unknown-oos`, linked with the
liboos runtime (`_start`, system calls, heap, `print!`). The `apps/` workspace is the SDK, and
`apps/README.md` walks through a new program. Examples: `hello-tmt`, `cowsay`, `calc`.

A package manifest (`apps/pkg/calc.toml`):

```toml
name = "calc"
version = "0.1.0"
description = "Command-line calculator"
arch = "x86_64"
depends = []

[[files]]
src = "../target/x86_64-unknown-oos/release/calc"
dest = "/usr/bin/calc"
```

Raise `version` for every change: published packages are cached as immutable.

## Building and publishing the repository

Windows (PowerShell 7):

```
.\apps\build.ps1 -Repo D:\ospab-projects\tmt-repo -Upload user@server
```

Git Bash, WSL or Linux:

```
bash apps/build.sh repo /path/to/tmt-repo
```

Both build the programs, pack them, add them to the repository and write the index. Then they
sign the index with `%USERPROFILE%\.ospab\tmt.key` (in WSL set `USERPROFILE=/mnt/c/Users/<you>`)
and verify the signature against the key compiled into the system. Upload the packages first,
then `index`, then `index.sig`.

Server setup (nginx, HTTPS through certbot) is in
[tools/tmt/deploy/README.md](../../tools/tmt/deploy/README.md). Back up the private key. If you
lose it, you have to generate a new key pair and ship a new system image.
