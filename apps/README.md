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
