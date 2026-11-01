#!/usr/bin/env bash
# Build the sample programs and package them.
#
#   apps/build.sh            build every program in apps/ and pack each into apps/dist/*.tmt
#   apps/build.sh repo DIR   additionally assemble a signed repository in DIR
#                            (DIR/x86_64/{index,index.sig,*.tmt}); needs the signing key
#                            ~/.ospab/tmt.key  (tmt keygen)
#
# Requires: nightly cargo with rust-src (same as the kernel). Run from Git Bash / WSL / Linux.
set -e
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"

# 1. host packer
EXE=tmt; case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=tmt.exe;; esac
[ -x "$ROOT/tools/tmt/bin/$EXE" ] || bash "$ROOT/tools/tmt/build.sh"
TMT="$ROOT/tools/tmt/bin/$EXE"

# 2. programs (RUSTFLAGS must be unset: it would override .cargo/config.toml, which carries the linker script)
env -u RUSTFLAGS cargo +nightly build --release

# 3. packages
rm -rf dist && mkdir -p dist
for m in pkg/*.toml; do
    [ "$m" = "pkg/ospab-base.toml" ] && continue   # template, see BASE below
    "$TMT" pack "$m" -o dist
done

# 3b. system package ospab-base (kernel + loaders from the build outputs of ../build.sh):
#     BASE=<build number> apps/build.sh      version = kernel version + build number
if [ -n "${BASE:-}" ]; then
    VER="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$ROOT/Cargo.toml" | head -1)"
    K="$ROOT/target/x86_64-ospab/release/ospab_os"
    L="$ROOT/boot/uefi/target/x86_64-unknown-uefi/release/ospab_boot.efi"
    B="$ROOT/boot/bios/target/bios.img"
    for f in "$K" "$L" "$B"; do [ -f "$f" ] || { echo "missing $f (run ./build.sh first)" >&2; exit 1; }; done
    "$TMT" pack pkg/ospab-base.toml -o dist --set "VERSION=$VER.$BASE" --set "KERNEL=$K" --set "LOADER=$L" --set "BIOS=$B"
fi

# 4. optional repository
if [ "$1" = "repo" ]; then
    REPO="${2:?usage: build.sh repo DIR}"
    "$TMT" repo add "$REPO" dist/*.tmt
    "$TMT" repo index "$REPO"
    "$TMT" repo sign "$REPO"
    "$TMT" repo verify "$REPO" --pub "$ROOT/userland/tomato/repo_key.pub"
fi
