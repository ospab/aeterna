#!/usr/bin/env bash
# Build the host tool `tmt` (not for the OS: it runs on your PC) into tools/tmt/bin/.
#
# Plain `cargo build` in this directory would pick up the kernel's .cargo/config.toml
# (bare-metal target + build-std) from the repository root, so we pass the host triple
# explicitly; rust-toolchain.toml selects stable, where the [unstable] section is ignored.
set -e
cd "$(dirname "$0")"
HOST="$(rustc -vV | sed -n 's/^host: //p' | tr -d '\r')"
env -u RUSTFLAGS cargo build --release --target "$HOST"
mkdir -p bin
EXE=tmt; case "$HOST" in *windows*) EXE=tmt.exe;; esac
cp "target/$HOST/release/$EXE" "bin/$EXE"
echo "built tools/tmt/bin/$EXE"
