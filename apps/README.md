# ospab.os program SDK (apps/)

Small ring-3 programs built on `../user/liboos` (entry point, syscalls, heap, `print!`).

## Write a program
```
apps/<name>/Cargo.toml   # copy hello-tmt's; depends on liboos = { path = "../../user/liboos" }
apps/<name>/src/main.rs
```
```rust
#![no_std]
#![no_main]
use liboos::println;
liboos::entry!(main);
fn main(args: liboos::Args) -> i32 { println!("hi {}", args.len()); 0 }
```
`alloc` works (`extern crate alloc;`). Return value = exit status (`$?` in plum). Add the crate to `members` in `apps/Cargo.toml`.

## Build and package
```
bash apps/build.sh                 # nightly cargo; -> apps/dist/*.tmt via tools/tmt
bash apps/build.sh repo DIR        # also builds a signed repo in DIR (needs ~/.ospab/tmt.key)
```
Package manifest (`apps/pkg/<name>.toml`): name, version, description, arch, depends, and `[[files]]` with `src` (relative to the manifest) and `dest` (absolute path in the OS, e.g. `/usr/bin/<name>`).

## Run
`tomato -U dist/x.tmt` (or `tomato -S x` from a repository), then type the name: plum looks in `$PATH`
(`/bin:/sbin:/usr/bin`) and runs ELF files as ring-3 processes; Ctrl+C kills them.
Current limits: program stdout goes to the serial port (not the screen), no stdin, capabilities: serial + fs.

## GUI programs
GUI apps use the `oos-ui` application API (`gui/`, module `oos_ui::app`), not liboos directly.
The template is `hello-gui`: a library crate with the `Application` impl (also linked into the
kernel desktop) and a ring-3 `main.rs` (feature `ring3`, on by default).
```
apps/<name>/Cargo.toml   # copy hello-gui's: oos-ui + optional liboos, [features] ring3
apps/<name>/src/lib.rs   # impl oos_ui::app::Application
apps/<name>/src/main.rs  # liboos::entry!, hosts the app
```
Build and package like any program (`bash apps/build.sh`, add `pkg/<name>.toml`). Details,
widgets and events: `docs/en/gui-apps.md`; architecture and the ring-3 plan: `docs/en/gui.md`.
Limit: until the compositor has an IPC front end, a ring-3 GUI program renders into memory
(the hello-gui binary prints how many pixels it painted) instead of opening a window on screen.
