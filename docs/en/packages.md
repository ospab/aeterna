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

## How packages are protected

- The index is signed with Ed25519. The public key is compiled into the system
  (`userland/tomato/repo_key.pub`); an index whose signature does not match is refused, and the
  stored index is re-checked every time it is used.
- Every package's size and SHA-256 are listed in the signed index and checked before anything is
  installed.
- `tomato remove` removes only the files the package installed.

Known limit: there is no protection against replaying an older, correctly signed index.

## The .tmt format

A `.tmt` file is a package: a header with name, version, architecture, dependencies and
description, followed by the files with their destination paths and checksums. Build them with
the host tool `tmt`, or inside the system with `tomato --tmt pack`.

## Writing a program

Programs are Rust `no_std` binaries for the target `x86_64-unknown-oos`, linked with the
**liboos** runtime (`_start`, system calls, heap, `print!`). The `apps/` workspace is the SDK;
`apps/README.md` walks through a new program. Example programs: `hello-tmt`, `cowsay`, `calc`.

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

Both build the programs, pack them, add them to the repository, write the index, sign it with
`%USERPROFILE%\.ospab\tmt.key` (in WSL set `USERPROFILE=/mnt/c/Users/<you>`) and verify the
signature against the key compiled into the system. Upload packages first, then `index`, then
`index.sig`.

Server setup (nginx, HTTPS through certbot) is described in
[tools/tmt/deploy/README.md](../../tools/tmt/deploy/README.md). Keep a backup of the private key:
losing it means generating a new key pair and shipping a new system image.
