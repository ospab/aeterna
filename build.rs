// build.rs — AETERNA kernel build script
// Sets cfg flags based on available build artifacts:
//   doom_wad_present  — doom1.wad exists in project root → embed it
//   doom_supported    — target/doom/libdoom.a built → link DOOM engine

use std::path::Path;
use std::env;
use std::process::Command;

/// Build identity shown by `uname -a`: OSPAB_BUILD (number from build.sh, "dev"
/// otherwise), OSPAB_COMMIT (short git hash, "+" if tracked files are modified)
/// and OSPAB_BUILD_DATE (UTC).
fn build_identity(manifest: &str) {
    println!("cargo:rerun-if-env-changed=OSPAB_BUILD");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    let build = env::var("OSPAB_BUILD").unwrap_or_else(|_| "dev".into());
    println!("cargo:rustc-env=OSPAB_BUILD={}", build);

    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git").args(args).current_dir(manifest).output().ok()?;
        if !out.status.success() { return None; }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let mut commit = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into());
    if git(&["status", "--porcelain", "--untracked-files=no"]).map_or(false, |s| !s.is_empty()) {
        commit.push('+');
    }
    println!("cargo:rustc-env=OSPAB_COMMIT={}", commit);

    // Civil date from the Unix clock (days → y-m-d, H. Hinnant's algorithm).
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    println!("cargo:rustc-env=OSPAB_BUILD_DATE={:04}-{:02}-{:02}", y, m, d);
}

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    build_identity(&manifest);

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

    // IPC demo programs (user/ipcsrv, user/ipcclient): the boot self-test spawns both.
    let srv = Path::new(&manifest).join("user/target/x86_64-unknown-oos/release/ipcsrv");
    let cli = Path::new(&manifest).join("user/target/x86_64-unknown-oos/release/ipcclient");
    if srv.exists() && cli.exists() {
        println!("cargo:rustc-cfg=user_ipc");
        println!("cargo:rustc-env=OOS_USER_IPCSRV={}", srv.display());
        println!("cargo:rustc-env=OOS_USER_IPCCLIENT={}", cli.display());
    }
    println!("cargo:rerun-if-changed=user/target/x86_64-unknown-oos/release/ipcsrv");
    println!("cargo:rerun-if-changed=user/target/x86_64-unknown-oos/release/ipcclient");

    // Declare custom cfg names so rustc doesn't warn about unexpected_cfgs
    println!("cargo::rustc-check-cfg=cfg(doom_wad_present)");
    println!("cargo::rustc-check-cfg=cfg(doom_supported)");
    println!("cargo::rustc-check-cfg=cfg(user_hello)");
    println!("cargo::rustc-check-cfg=cfg(user_ipc)");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=target/doom/libdoom.a");

    // Pass linker script with absolute path so rust-lld can find it regardless
    // of what directory cargo invokes the linker from.
    let linker_script = Path::new(&manifest).join("linker.ld");
    if linker_script.exists() {
        println!("cargo:rustc-link-arg=-T{}", linker_script.display());
    }
}
