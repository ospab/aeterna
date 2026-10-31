// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// CRC-32C (Castagnoli), slice-by-8, own implementation.

const POLY: u32 = 0x82F6_3B78;

const fn make() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut i = 0;
    while i < 256 {
        let mut c = t[0][i];
        let mut j = 1;
        while j < 8 {
            c = t[0][(c & 0xff) as usize] ^ (c >> 8);
            t[j][i] = c;
            j += 1;
        }
        i += 1;
    }
    t
}

static T: [[u32; 256]; 8] = make();

pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_append(0, data)
}

pub fn crc32c_append(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    let mut d = data;
    while d.len() >= 8 {
        let a = u32::from_le_bytes([d[0], d[1], d[2], d[3]]) ^ c;
        let b = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);
        c = T[7][(a & 0xff) as usize]
            ^ T[6][((a >> 8) & 0xff) as usize]
            ^ T[5][((a >> 16) & 0xff) as usize]
            ^ T[4][(a >> 24) as usize]
            ^ T[3][(b & 0xff) as usize]
            ^ T[2][((b >> 8) & 0xff) as usize]
            ^ T[1][((b >> 16) & 0xff) as usize]
            ^ T[0][(b >> 24) as usize];
        d = &d[8..];
    }
    for &x in d {
        c = T[0][((c ^ x as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vector() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
    }
}
