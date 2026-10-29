fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bins=-T{}/link.ld", dir);
    println!("cargo:rustc-link-arg-bins=--oformat=binary");
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=src/rm.S");
}
