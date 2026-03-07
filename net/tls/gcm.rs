/*
 * AES-128-GCM AEAD — NIST SP 800-38D / RFC 5116
 *
 * Used for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02B).
 *
 * No heap allocation in core crypto path.
 * All key/IV/AAD parameters are fixed-size where possible.
 */

extern crate alloc;
use alloc::vec::Vec;

use super::aes::{key_expansion, aes128_encrypt_block};

// ─── GF(2^128) multiplication for GHASH ──────────────────────────────────────
//
// Standard right-to-left bit algorithm (NIST SP 800-38D §6.3).
// Polynomial: x^128 + x^7 + x^2 + x + 1  →  reduction constant R = 0xE1 ‖ 0^120

fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z  = [0u8; 16];
    let mut v  = *y;

    for i in 0..128 {
        // Bit i of X, MSB-first
        if (x[i / 8] >> (7 - (i % 8))) & 1 == 1 {
            for k in 0..16 { z[k] ^= v[k]; }
        }

        let lsb = v[15] & 1;

        // Right-shift V by 1 bit (big-endian 128-bit number)
        for k in (1..16).rev() {
            v[k] = (v[k] >> 1) | ((v[k - 1] & 1) << 7);
        }
        v[0] >>= 1;

        if lsb == 1 {
            v[0] ^= 0xE1; // reduce
        }
    }
    z
}

// ─── GHASH ────────────────────────────────────────────────────────────────────

/// GHASH_H(A, C) — authenticate additional data + ciphertext.
///
/// h = AES_K(0^128) (hash subkey, computed once by `gcm_init_h`).
/// Processes AAD `a` and ciphertext `c`, both padded to 16-byte blocks.
fn ghash(h: &[u8; 16], a: &[u8], c: &[u8]) -> [u8; 16] {
    let mut x = [0u8; 16];

    // Process AAD blocks
    let mut pos = 0;
    while pos < a.len() {
        let mut block = [0u8; 16];
        let n = core::cmp::min(16, a.len() - pos);
        block[..n].copy_from_slice(&a[pos..pos + n]);
        for k in 0..16 { x[k] ^= block[k]; }
        x = gf128_mul(&x, h);
        pos += 16;
    }

    // Process ciphertext blocks
    pos = 0;
    while pos < c.len() {
        let mut block = [0u8; 16];
        let n = core::cmp::min(16, c.len() - pos);
        block[..n].copy_from_slice(&c[pos..pos + n]);
        for k in 0..16 { x[k] ^= block[k]; }
        x = gf128_mul(&x, h);
        pos += 16;
    }

    // Final block: len(A) || len(C) in bits, big-endian u64 each
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&((a.len() as u64) * 8).to_be_bytes());
    len_block[8..16].copy_from_slice(&((c.len() as u64) * 8).to_be_bytes());
    for k in 0..16 { x[k] ^= len_block[k]; }
    x = gf128_mul(&x, h);

    x
}

// ─── GCTR (AES-CTR) ───────────────────────────────────────────────────────────

/// Increment the 32-bit big-endian counter in bytes 12..16 of an ICB.
fn inc32(icb: &mut [u8; 16]) {
    let ctr = u32::from_be_bytes([icb[12], icb[13], icb[14], icb[15]]);
    let new  = ctr.wrapping_add(1);
    icb[12..16].copy_from_slice(&new.to_be_bytes());
}

/// AES-CTR encrypt/decrypt in-place, starting counter = icb (J0+1 for the
/// first plaintext block; J0 is reserved for the auth tag).
fn gctr(rk: &[u32; 44], icb: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut ctr = *icb;
    let mut offset = 0;

    while offset < data.len() {
        let mut ks = ctr;
        aes128_encrypt_block(&mut ks, rk);

        let n = core::cmp::min(16, data.len() - offset);
        for k in 0..n {
            out.push(data[offset + k] ^ ks[k]);
        }

        inc32(&mut ctr);
        offset += n;
    }
    out
}

// ─── Public AES-128-GCM API ───────────────────────────────────────────────────

/// AES-128-GCM AEAD encryption.
///
/// `nonce`   — 12 bytes (4-byte implicit write IV ‖ 8-byte explicit nonce).
/// `aad`     — additional authenticated data (not encrypted).
/// `plain`   — plaintext to encrypt.
/// Returns `(ciphertext, tag[16])`.
pub fn aes128_gcm_encrypt(
    key:   &[u8; 16],
    nonce: &[u8; 12],
    plain: &[u8],
    aad:   &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let rk = key_expansion(key);

    // H = AES_K(0^128)
    let mut h = [0u8; 16];
    aes128_encrypt_block(&mut h, &rk);

    // J0 = nonce ‖ 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // Encrypt: J0+1, J0+2, ...
    let mut icb = j0;
    inc32(&mut icb);            // first encryption counter = J0+1
    let ciphertext = gctr(&rk, &icb, plain);

    // Auth tag = GHASH(H, AAD, ciphertext) XOR AES(K, J0)
    let g = ghash(&h, aad, &ciphertext);
    let mut ej0 = j0;
    aes128_encrypt_block(&mut ej0, &rk);

    let mut tag = [0u8; 16];
    for k in 0..16 { tag[k] = g[k] ^ ej0[k]; }

    (ciphertext, tag)
}

/// AES-128-GCM AEAD decryption + authentication.
///
/// Returns `Some(plaintext)` if the auth tag verifies, `None` otherwise.
pub fn aes128_gcm_decrypt(
    key:   &[u8; 16],
    nonce: &[u8; 12],
    cipher: &[u8],
    aad:    &[u8],
    tag:    &[u8; 16],
) -> Option<Vec<u8>> {
    let rk = key_expansion(key);

    // H = AES_K(0^128)
    let mut h = [0u8; 16];
    aes128_encrypt_block(&mut h, &rk);

    // J0 = nonce ‖ 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // Verify tag
    let g = ghash(&h, aad, cipher);
    let mut ej0 = j0;
    aes128_encrypt_block(&mut ej0, &rk);

    let mut expected = [0u8; 16];
    for k in 0..16 { expected[k] = g[k] ^ ej0[k]; }

    // Constant-time comparison
    let mut diff: u8 = 0;
    for k in 0..16 { diff |= expected[k] ^ tag[k]; }
    if diff != 0 { return None; }

    // Decrypt
    let mut icb = j0;
    inc32(&mut icb);
    Some(gctr(&rk, &icb, cipher))
}
