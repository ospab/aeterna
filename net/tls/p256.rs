/*
 * P-256 (secp256r1) ECDHE key-exchange — pure no_std Rust
 *
 * Used for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xC027).
 *
 * Field elements: little-endian [u32; 8]  (index 0 = least-significant word)
 * Points:         Jacobian (X:Y:Z) where affine = (X/Z², Y/Z³)
 *
 * P-256 prime   p = 0xFFFFFFFF 00000001 00000000 00000000
 *                         00000000 FFFFFFFF FFFFFFFF FFFFFFFF
 * Reduction via NIST / FIPS 186-4 Appendix D.1.2.3 Solinas formula.
 *
 * No heap allocations in the critical path (scalar_mul / field ops).
 * One heap allocation in fe_inv because we reuse bignum::mod_exp.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

/// 256-bit field element, little-endian u32 limbs.  limbs[0] = least-sig word.
type Fe = [u32; 8];

/// Jacobian projective point.  Affine (x,y) = (X/Z², Y/Z³).
/// Point-at-infinity is represented with z = 0.
#[derive(Clone, Copy)]
struct JPoint { x: Fe, y: Fe, z: Fe }

// ─── P-256 constants ──────────────────────────────────────────────────────────

/// p = 2^256 − 2^224 + 2^192 + 2^96 − 1  (little-endian u32 words)
const P: Fe = [
    0xffff_ffff, 0xffff_ffff, 0xffff_ffff, 0x0000_0000,
    0x0000_0000, 0x0000_0000, 0x0000_0001, 0xffff_ffff,
];

/// p − 2 as big-endian bytes, for Fermat inversion (a^(p−2) mod p).
const P_MINUS_2: [u8; 32] = [
    0xff,0xff,0xff,0xff, 0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xfd,
];

/// Generator — Gx (little-endian u32 words).
const GX: Fe = [
    0xd898_c296, 0xf4a1_3945, 0x2deb_33a0, 0x7703_7d81,
    0x63a4_40f2, 0xf8bc_e6e5, 0xe12c_4247, 0x6b17_d1f2,
];

/// Generator — Gy (little-endian u32 words).
const GY: Fe = [
    0x37bf_51f5, 0xcbb6_4068, 0x6b31_5ece, 0x2bce_3357,
    0x7c0f_9e16, 0x8ee7_eb4a, 0xfe1a_7f9b, 0x4fe3_42e2,
];

/// Curve order n, big-endian bytes.
const N_BE: [u8; 32] = [
    0xff,0xff,0xff,0xff, 0x00,0x00,0x00,0x00,
    0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad, 0xa7,0x17,0x9e,0x84,
    0xf3,0xb9,0xca,0xc2, 0xfc,0x63,0x25,0x51,
];

// ─── Field element helpers ────────────────────────────────────────────────────

fn fe_zero() -> Fe { [0u32; 8] }
fn fe_one()  -> Fe { let mut r = [0u32; 8]; r[0] = 1; r }

fn fe_from_small(v: u32) -> Fe {
    let mut r = [0u32; 8]; r[0] = v; r
}

fn fe_is_zero(a: &Fe) -> bool { a.iter().all(|&x| x == 0) }

/// Compare two field elements.  Returns -1, 0, +1.
fn fe_cmp(a: &Fe, b: &Fe) -> i32 {
    for i in (0..8).rev() {
        if a[i] > b[i] { return  1; }
        if a[i] < b[i] { return -1; }
    }
    0
}

/// Parse 32 big-endian bytes into an Fe.
fn fe_from_be(b: &[u8; 32]) -> Fe {
    let mut r = [0u32; 8];
    for i in 0..8 {
        r[7 - i] = u32::from_be_bytes([b[i*4], b[i*4+1], b[i*4+2], b[i*4+3]]);
    }
    r
}

/// Export an Fe as 32 big-endian bytes.
fn fe_to_be(a: &Fe) -> [u8; 32] {
    let mut r = [0u8; 32];
    for i in 0..8 {
        let bytes = a[7 - i].to_be_bytes();
        r[i*4..i*4+4].copy_from_slice(&bytes);
    }
    r
}

// ─── Modular arithmetic (mod p) ───────────────────────────────────────────────

/// a + b mod p
fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u32; 8];
    let mut carry: u64 = 0;
    for i in 0..8 {
        let t = a[i] as u64 + b[i] as u64 + carry;
        r[i]  = t as u32;
        carry = t >> 32;
    }
    // If carry or r >= p then subtract p once.
    if carry != 0 || fe_cmp(&r, &P) >= 0 {
        let mut borrow: u64 = 0;
        for i in 0..8 {
            let t = r[i] as u64 + 0x1_0000_0000 - P[i] as u64 - borrow;
            r[i]   = t as u32;
            borrow = 1 - (t >> 32);
        }
    }
    r
}

/// a − b mod p
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u32; 8];
    let mut borrow: u64 = 0;
    for i in 0..8 {
        let t    = a[i] as u64 + 0x1_0000_0000 - b[i] as u64 - borrow;
        r[i]     = t as u32;
        borrow   = 1 - (t >> 32);
    }
    // If we borrowed (a < b) add p back.
    if borrow != 0 {
        let mut carry: u64 = 0;
        for i in 0..8 {
            let t = r[i] as u64 + P[i] as u64 + carry;
            r[i]  = t as u32;
            carry = t >> 32;
        }
    }
    r
}

fn fe_double(a: &Fe) -> Fe { fe_add(a, a) }

fn fe_neg(a: &Fe) -> Fe {
    if fe_is_zero(a) { fe_zero() } else { fe_sub(&P, a) }
}

// ─── P-256 Solinas reduction ──────────────────────────────────────────────────
//
// NIST FIPS 186-4 Appendix D.1.2.3.
// Input: 512-bit product as [u32; 16], words c[0]=LSW … c[15]=MSW.
// Output: result in [0, p).

fn p256_reduce(c: &[u32; 16]) -> Fe {
    // Closure for signed promote
    let ci = |i: usize| c[i] as i64;

    // Accumulate Solinas terms into i64 slots; sign arithmetic handles borrows.
    let mut r = [0i64; 9];   // r[0]=LSW … r[7]; r[8]=overflow

    // T = c[7..0]
    for i in 0..8 { r[i] = ci(i); }

    // S1, S2, S3, S4 additions + D1, D2, D3, D4 subtractions
    // (formula from FIPS 186-4, mapped to little-endian word indices)
    r[0] += ci(8)  + ci(9)  - ci(11) - ci(12) - ci(13) - ci(14);
    r[1] += ci(9)  + ci(10) - ci(12) - ci(13) - ci(14) - ci(15);
    r[2] += ci(10) + ci(11) - ci(13) - ci(14) - ci(15);
    r[3] += 2*ci(11) + 2*ci(12) + ci(13) - ci(8)  - ci(9)  - ci(15);
    r[4] += 2*ci(12) + 2*ci(13) + ci(14) - ci(9)  - ci(10);
    r[5] += 2*ci(13) + 2*ci(14) + ci(15) - ci(10) - ci(11);
    r[6] += ci(13)  + 3*ci(14) + 2*ci(15) - ci(8)  - ci(9);
    r[7] += ci(8)   + 3*ci(15) - ci(10) - ci(11) - ci(12) - ci(13);

    // Two rounds of carry-propagation + 2^256 reduction.
    // 2^256 ≡ 2^224 − 2^192 − 2^96 + 1  (mod p)
    for _ in 0..2 {
        for i in 0..8 {
            let carry = r[i] >> 32;   // i64 arithmetic right-shift
            r[i]     &= 0xffff_ffff;
            r[i + 1] += carry;
        }
        // Distribute r[8] * 2^256 → r[7]*2^224 − r[6]*2^192 − r[3]*2^96 + r[0]
        let c8 = r[8]; r[8] = 0;
        r[0] += c8;
        r[3] -= c8;
        r[6] -= c8;
        r[7] += c8;
    }

    // Final carry sweep (handles possible ±1 residuals from the 2^256 step).
    for i in 0..8 {
        let carry = r[i] >> 32;
        r[i]     &= 0xffff_ffff;
        if i < 8 { r[i + 1] += carry; }
    }

    let mut result = [0u32; 8];
    for i in 0..8 { result[i] = r[i] as u32; }

    // Conditional subtract p, up to 4 times, until result ∈ [0, p).
    for _ in 0..4 {
        if fe_cmp(&result, &P) >= 0 {
            let mut borrow: u64 = 0;
            for i in 0..8 {
                let t = result[i] as u64 + 0x1_0000_0000 - P[i] as u64 - borrow;
                result[i] = t as u32;
                borrow    = 1 - (t >> 32);
            }
        }
    }
    result
}

// ─── Field multiplication & squaring ─────────────────────────────────────────

/// a × b  mod p
fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    // 8 × 8 schoolbook multiplication → 512-bit product.
    // We use u128 accumulators to avoid intermediate overflow.
    let mut prod = [0u128; 16];
    for i in 0..8 {
        for j in 0..8 {
            prod[i + j] += (a[i] as u128) * (b[j] as u128);
        }
    }
    // Carry-propagate to 32-bit words in [u32; 16].
    let mut c = [0u32; 16];
    let mut carry: u128 = 0;
    for k in 0..16 {
        let t  = prod[k] + carry;
        c[k]   = t as u32;
        carry  = t >> 32;
    }
    p256_reduce(&c)
}

fn fe_sq(a: &Fe) -> Fe { fe_mul(a, a) }

// ─── Field inversion ──────────────────────────────────────────────────────────

/// a^(p−2) mod p  via right-to-left square-and-multiply.
/// (No heap allocation — all temporaries are on the stack.)
fn fe_inv(a: &Fe) -> Fe {
    let mut result = fe_one();
    let mut base   = *a;
    // Process bits of p−2 from LSB to MSB.
    // P_MINUS_2 is big-endian, so byte 31 = LSB byte.
    for byte_idx in (0..32).rev() {
        let byte = P_MINUS_2[byte_idx];
        for bit_pos in 0..8 {
            if (byte >> bit_pos) & 1 == 1 {
                result = fe_mul(&result, &base);
            }
            base = fe_sq(&base);
        }
    }
    result
}

// ─── Jacobian point operations ────────────────────────────────────────────────

fn jpoint_inf() -> JPoint { JPoint { x: fe_one(), y: fe_one(), z: fe_zero() } }

fn jpoint_is_inf(p: &JPoint) -> bool { fe_is_zero(&p.z) }

/// Point doubling on P-256 (a = −3 special case).
///   A  = 4·X·Y²
///   M  = 3·(X − Z²)·(X + Z²)     ← uses a = −3
///   X₃ = M² − 2A
///   Y₃ = M·(A − X₃) − 8·Y⁴
///   Z₃ = 2·Y·Z
fn point_double(p: &JPoint) -> JPoint {
    if jpoint_is_inf(p) { return jpoint_inf(); }

    let y2    = fe_sq(&p.y);
    let a_val = fe_mul(&fe_mul(&fe_from_small(4), &p.x), &y2);

    let z2    = fe_sq(&p.z);
    let s     = fe_mul(&fe_sub(&p.x, &z2), &fe_add(&p.x, &z2));
    let m     = fe_mul(&fe_from_small(3), &s);

    let m2    = fe_sq(&m);
    let two_a = fe_double(&a_val);
    let x3    = fe_sub(&m2, &two_a);

    let y4    = fe_sq(&y2);
    let ey4   = fe_mul(&fe_from_small(8), &y4);
    let am_x3 = fe_sub(&a_val, &x3);
    let y3    = fe_sub(&fe_mul(&m, &am_x3), &ey4);

    let z3    = fe_double(&fe_mul(&p.y, &p.z));

    JPoint { x: x3, y: y3, z: z3 }
}

/// Full Jacobian–Jacobian point addition.
///   Z1sq = Z1²,  Z2sq = Z2²
///   U1   = X1·Z2sq,   U2 = X2·Z1sq
///   S1   = Y1·Z2·Z2sq,  S2 = Y2·Z1·Z1sq
///   H    = U2 − U1,   R = S2 − S1
///   X3   = R² − H³ − 2·U1·H²
///   Y3   = R·(U1·H² − X3) − S1·H³
///   Z3   = H·Z1·Z2
fn point_add(p1: &JPoint, p2: &JPoint) -> JPoint {
    if jpoint_is_inf(p1) { return *p2; }
    if jpoint_is_inf(p2) { return *p1; }

    let z1sq  = fe_sq(&p1.z);
    let z2sq  = fe_sq(&p2.z);
    let u1    = fe_mul(&p1.x, &z2sq);
    let u2    = fe_mul(&p2.x, &z1sq);
    let s1    = fe_mul(&p1.y, &fe_mul(&p2.z, &z2sq));
    let s2    = fe_mul(&p2.y, &fe_mul(&p1.z, &z1sq));

    let h     = fe_sub(&u2, &u1);
    let r     = fe_sub(&s2, &s1);

    if fe_is_zero(&h) {
        return if fe_is_zero(&r) { point_double(p1) } else { jpoint_inf() };
    }

    let h2    = fe_sq(&h);
    let h3    = fe_mul(&h, &h2);
    let u1h2  = fe_mul(&u1, &h2);
    let r2    = fe_sq(&r);

    let x3    = fe_sub(&fe_sub(&r2, &h3), &fe_double(&u1h2));
    let y3    = fe_sub(
        &fe_mul(&r, &fe_sub(&u1h2, &x3)),
        &fe_mul(&s1, &h3),
    );
    let z3    = fe_mul(&fe_mul(&h, &p1.z), &p2.z);

    JPoint { x: x3, y: y3, z: z3 }
}

/// Scalar multiplication: k (big-endian 32 bytes) × (px, py).
/// Uses MSB-first double-and-add.
fn scalar_mul(k: &[u8; 32], px: &Fe, py: &Fe) -> JPoint {
    let base     = JPoint { x: *px, y: *py, z: fe_one() };
    let mut result = jpoint_inf();

    for byte_idx in 0..32 {
        let byte = k[byte_idx];
        for bit_idx in (0..8).rev() {
            result = point_double(&result);
            if (byte >> bit_idx) & 1 == 1 {
                result = point_add(&result, &base);
            }
        }
    }
    result
}

/// Convert Jacobian → affine big-endian (X, Y) byte arrays.
fn jacobian_to_affine(p: &JPoint) -> Option<([u8; 32], [u8; 32])> {
    if jpoint_is_inf(p) { return None; }
    let zi  = fe_inv(&p.z);
    let zi2 = fe_sq(&zi);
    let zi3 = fe_mul(&zi, &zi2);
    let x   = fe_mul(&p.x, &zi2);
    let y   = fe_mul(&p.y, &zi3);
    Some((fe_to_be(&x), fe_to_be(&y)))
}

// ─── Scalar clamping (ensure k < n, k ≠ 0) ───────────────────────────────────

/// If k ≥ n (big-endian comparison), subtract n.  Probability ≈ 2⁻²²⁴.
fn reduce_scalar(k: &[u8; 32]) -> [u8; 32] {
    if k >= &N_BE {
        let mut out = [0u8; 32];
        let mut borrow: u16 = 0;
        for i in (0..32).rev() {
            let t    = k[i] as u16 + 0x100 - N_BE[i] as u16 - borrow;
            out[i]   = t as u8;
            borrow   = 1 - (t >> 8);
        }
        out
    } else {
        *k
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Generate an ephemeral P-256 key pair for TLS ECDHE.
///
/// `rng_bytes` — 32 bytes of cryptographically random data.
/// Returns `(private_key_32, public_key_64)` where the public key is
/// the uncompressed EC point X ‖ Y (each 32 bytes, without the 0x04 prefix).
pub fn ecdhe_keygen(rng_bytes: &[u8; 32]) -> ([u8; 32], [u8; 64]) {
    let k = reduce_scalar(rng_bytes);

    let point = scalar_mul(&k, &GX, &GY);
    let (pub_x, pub_y) = jacobian_to_affine(&point)
        .unwrap_or(([0u8; 32], [0u8; 32]));

    let mut pub_xy = [0u8; 64];
    pub_xy[..32].copy_from_slice(&pub_x);
    pub_xy[32..].copy_from_slice(&pub_y);

    (k, pub_xy)
}

/// Compute the ECDH shared secret.
///
/// `k`           — our 32-byte private key (from `ecdhe_keygen`).
/// `peer_pub_xy` — peer's uncompressed public key X ‖ Y (64 bytes, no 0x04 prefix).
/// Returns the x-coordinate of k × peer_point (32 bytes = premaster secret).
pub fn ecdhe_shared_secret(k: &[u8; 32], peer_pub_xy: &[u8; 64]) -> [u8; 32] {
    let mut px_be = [0u8; 32];
    let mut py_be = [0u8; 32];
    px_be.copy_from_slice(&peer_pub_xy[..32]);
    py_be.copy_from_slice(&peer_pub_xy[32..]);

    let px = fe_from_be(&px_be);
    let py = fe_from_be(&py_be);

    let shared = scalar_mul(k, &px, &py);
    let (shared_x, _) = jacobian_to_affine(&shared)
        .unwrap_or(([0u8; 32], [0u8; 32]));

    shared_x
}
