// build.rs — AETERNA kernel build script
// Sets cfg flags based on available build artifacts:
//   doom_wad_present  — doom1.wad exists in project root → embed it
//   doom_supported    — target/doom/libdoom.a built → link DOOM engine

use std::path::Path;
use std::env;

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();

    // Check for doom1.wad (shareware / registered WAD)
    let wad = Path::new(&manifest).join("doom1.wad");
    if wad.exists() {
        println!("cargo:rustc-cfg=doom_wad_present");
        println!("cargo:rerun-if-changed=doom1.wad");
    }

    // Check for compiled DOOM C library
    let lib = Path::new(&manifest).join("target/doom/libdoom.a");
    if lib.exists() {
        println!("cargo:rustc-cfg=doom_supported");
        // Link only into the kernel crate (RUSTFLAGS would also hit core/alloc under build-std).
        println!("cargo:rustc-link-search=native={}", lib.parent().unwrap().display());
        println!("cargo:rustc-link-lib=static=doom");
    }
    // Relink the kernel whenever the DOOM C library is rebuilt.
    println!("cargo:rerun-if-changed=target/doom/libdoom.a");

    // First user program (built by build.sh from user/): embedded until the kernel
    // can load programs from the filesystem.
    let hello = Path::new(&manifest).join("user/target/x86_64-unknown-oos/release/hello");
    if hello.exists() {
        println!("cargo:rustc-cfg=user_hello");
        println!("cargo:rustc-env=OOS_USER_HELLO={}", hello.display());
    }
    println!("cargo:rerun-if-changed=user/target/x86_64-unknown-oos/release/hello");

    // Declare custom cfg names so rustc doesn't warn about unexpected_cfgs
    println!("cargo::rustc-check-cfg=cfg(doom_wad_present)");
    println!("cargo::rustc-check-cfg=cfg(doom_supported)");
    println!("cargo::rustc-check-cfg=cfg(user_hello)");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=target/doom/libdoom.a");

    // Pass linker script with absolute path so rust-lld can find it regardless
    // of what directory cargo invokes the linker from.
    let linker_script = Path::new(&manifest).join("linker.ld");
    if linker_script.exists() {
        println!("cargo:rustc-link-arg=-T{}", linker_script.display());
    }
}
