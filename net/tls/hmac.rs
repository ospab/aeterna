/*
 * HMAC-SHA256 (RFC 2104)
 *
 * Used by TLS 1.2 PRF and record MAC.
 */

use super::sha256::{Sha256, sha256};

const BLOCK_SIZE: usize = 64; // SHA-256 block size
const HASH_SIZE: usize = 32;

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // If key > block size, hash it first
    let mut k_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hk = sha256(key);
        k_block[..HASH_SIZE].copy_from_slice(&hk);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    // Zero-pad already done (k_block initialized to 0)

    // Inner: SHA256( (K ^ ipad) || data )
    let mut i_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        i_key[i] = k_block[i] ^ 0x36;
    }

    let mut inner = Sha256::new();
    inner.update(&i_key);
    inner.update(data);
    let inner_hash = inner.finalize();

    // Outer: SHA256( (K ^ opad) || inner_hash )
    let mut o_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        o_key[i] = k_block[i] ^ 0x5c;
    }

    let mut outer = Sha256::new();
    outer.update(&o_key);
    outer.update(&inner_hash);
    outer.finalize()
}
