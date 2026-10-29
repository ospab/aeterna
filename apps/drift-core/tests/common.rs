// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
#![allow(dead_code)]
use std::io::Write;
/// Screenshots go to $DRIFT_SHOTS, or to target/drift-shots next to the crate.
pub fn out_dir() -> String {
    std::env::var("DRIFT_SHOTS").unwrap_or_else(|_| String::from("target/drift-shots"))
}
pub fn save_ppm(name: &str, w: usize, h: usize, px: &[u32]) {
    let out = out_dir();
    let _ = std::fs::create_dir_all(&out);
    let mut f = std::fs::File::create(format!("{}/{}.ppm", out, name)).unwrap();
    write!(f, "P6\n{} {}\n255\n", w, h).unwrap();
    let mut buf = Vec::with_capacity(w * h * 3);
    for p in px.iter().take(w * h) {
        buf.push((p >> 16) as u8);
        buf.push((p >> 8) as u8);
        buf.push(*p as u8);
    }
    f.write_all(&buf).unwrap();
}
