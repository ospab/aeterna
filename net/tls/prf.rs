/*
 * TLS 1.2 PRF (RFC 5246 §5)
 *
 * PRF(secret, label, seed) = P_SHA256(secret, label + seed)
 * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
 *                         HMAC_hash(secret, A(2) + seed) + ...
 * where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
 */

use alloc::vec::Vec;
use super::hmac::hmac_sha256;

/// TLS 1.2 PRF: produces `out_len` bytes from (secret, label, seed).
pub fn prf(secret: &[u8], label: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    // Concatenate label + seed once
    let mut ls = Vec::with_capacity(label.len() + seed.len());
    ls.extend_from_slice(label);
    ls.extend_from_slice(seed);

    let mut result = Vec::with_capacity(out_len);

    // A(0) = label + seed
    // A(1) = HMAC(secret, A(0))
    let mut a = hmac_sha256(secret, &ls);

    while result.len() < out_len {
        // P_i = HMAC(secret, A(i) + label + seed)
        let mut a_plus_ls = Vec::with_capacity(32 + ls.len());
        a_plus_ls.extend_from_slice(&a);
        a_plus_ls.extend_from_slice(&ls);

        let p = hmac_sha256(secret, &a_plus_ls);

        let take = core::cmp::min(32, out_len - result.len());
        result.extend_from_slice(&p[..take]);

        // A(i+1) = HMAC(secret, A(i))
        a = hmac_sha256(secret, &a);
    }

    result
}
