/*
 * Big-number arithmetic for RSA public-key operations.
 *
 * Only what TLS 1.2 client needs:
 *   - Modular exponentiation  (m^e mod n)  for RSA PKCS#1 v1.5 encryption
 *   - Numbers up to 4096 bits (512 bytes)
 *
 * Representation: little-endian u32 limbs.
 */

use alloc::vec::Vec;

const MAX_LIMBS: usize = 128; // 4096 bits / 32

#[derive(Clone)]
pub struct BigNum {
    pub limbs: Vec<u32>,
}

impl BigNum {
    pub fn zero() -> Self {
        Self { limbs: alloc::vec![0u32; 1] }
    }

    /// Parse big-endian bytes into BigNum.
    pub fn from_be_bytes(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self::zero();
        }
        // Pad to multiple of 4
        let pad = (4 - data.len() % 4) % 4;
        let mut padded = Vec::with_capacity(pad + data.len());
        for _ in 0..pad {
            padded.push(0);
        }
        padded.extend_from_slice(data);

        let word_count = padded.len() / 4;
        let mut limbs = Vec::with_capacity(word_count);
        // Convert from big-endian to little-endian limbs
        for i in (0..word_count).rev() {
            let off = i * 4;
            let w = u32::from_be_bytes([padded[off], padded[off+1], padded[off+2], padded[off+3]]);
            limbs.push(w);
        }
        trim(&mut limbs);
        Self { limbs }
    }

    /// Export as big-endian bytes (no leading zeros except minimum 1 byte).
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.limbs.len() * 4);
        for i in (0..self.limbs.len()).rev() {
            out.extend_from_slice(&self.limbs[i].to_be_bytes());
        }
        // Strip leading zeros (keep at least 1 byte)
        let mut start = 0;
        while start < out.len() - 1 && out[start] == 0 {
            start += 1;
        }
        out[start..].to_vec()
    }

    /// Export as big-endian bytes, zero-padded to exactly `len` bytes.
    pub fn to_be_bytes_padded(&self, len: usize) -> Vec<u8> {
        let raw = self.to_be_bytes();
        if raw.len() >= len {
            return raw[raw.len() - len..].to_vec();
        }
        let mut out = alloc::vec![0u8; len];
        out[len - raw.len()..].copy_from_slice(&raw);
        out
    }

    pub fn bit_len(&self) -> usize {
        let n = self.limbs.len();
        if n == 0 { return 0; }
        let top = self.limbs[n - 1];
        if top == 0 { return 0; }
        (n - 1) * 32 + (32 - top.leading_zeros() as usize)
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }
}

fn trim(limbs: &mut Vec<u32>) {
    while limbs.len() > 1 && *limbs.last().unwrap() == 0 {
        limbs.pop();
    }
}

// ─── Arithmetic ──────────────────────────────────────────────────────────────

/// a + b
fn bn_add(a: &BigNum, b: &BigNum) -> BigNum {
    let n = core::cmp::max(a.limbs.len(), b.limbs.len());
    let mut out = Vec::with_capacity(n + 1);
    let mut carry: u64 = 0;
    for i in 0..n {
        let av = if i < a.limbs.len() { a.limbs[i] as u64 } else { 0 };
        let bv = if i < b.limbs.len() { b.limbs[i] as u64 } else { 0 };
        let s = av + bv + carry;
        out.push(s as u32);
        carry = s >> 32;
    }
    if carry != 0 {
        out.push(carry as u32);
    }
    trim(&mut out);
    BigNum { limbs: out }
}

/// a - b (assumes a >= b)
fn bn_sub(a: &BigNum, b: &BigNum) -> BigNum {
    let mut out = Vec::with_capacity(a.limbs.len());
    let mut borrow: i64 = 0;
    for i in 0..a.limbs.len() {
        let av = a.limbs[i] as i64;
        let bv = if i < b.limbs.len() { b.limbs[i] as i64 } else { 0 };
        let mut diff = av - bv - borrow;
        if diff < 0 {
            diff += 0x1_0000_0000_i64;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out.push(diff as u32);
    }
    trim(&mut out);
    BigNum { limbs: out }
}

/// Compare: -1 if a<b, 0 if a==b, 1 if a>b
fn bn_cmp(a: &BigNum, b: &BigNum) -> i8 {
    let al = a.limbs.len();
    let bl = b.limbs.len();
    // Compare effective lengths after trimming
    let a_eff = {
        let mut i = al;
        while i > 1 && a.limbs[i - 1] == 0 { i -= 1; }
        i
    };
    let b_eff = {
        let mut i = bl;
        while i > 1 && b.limbs[i - 1] == 0 { i -= 1; }
        i
    };
    if a_eff != b_eff {
        return if a_eff > b_eff { 1 } else { -1 };
    }
    for i in (0..a_eff).rev() {
        let av = if i < al { a.limbs[i] } else { 0 };
        let bv = if i < bl { b.limbs[i] } else { 0 };
        if av > bv { return 1; }
        if av < bv { return -1; }
    }
    0
}

/// (a * b) mod m  — schoolbook multiplication then mod
fn bn_mulmod(a: &BigNum, b: &BigNum, m: &BigNum) -> BigNum {
    let al = a.limbs.len();
    let bl = b.limbs.len();
    let mut prod = alloc::vec![0u64; al + bl];

    for i in 0..al {
        let mut carry: u64 = 0;
        for j in 0..bl {
            let p = (a.limbs[i] as u64) * (b.limbs[j] as u64) + prod[i + j] + carry;
            prod[i + j] = p & 0xFFFF_FFFF;
            carry = p >> 32;
        }
        prod[i + bl] += carry;
    }

    // Convert u64 product to BigNum
    let mut limbs: Vec<u32> = prod.iter().map(|&v| v as u32).collect();
    trim(&mut limbs);
    let p = BigNum { limbs };

    bn_mod(&p, m)
}

/// a mod m  (using repeated subtraction with shifting for efficiency)
fn bn_mod(a: &BigNum, m: &BigNum) -> BigNum {
    if bn_cmp(a, m) < 0 {
        return a.clone();
    }

    let mut r = a.clone();
    let m_bits = m.bit_len();
    let r_bits = r.bit_len();

    if m_bits == 0 { return BigNum::zero(); }
    if r_bits < m_bits { return r; }

    // Shift m left to align with r
    let shift = r_bits - m_bits;
    let mut shifted_m = bn_shl(m, shift);

    for _ in 0..=shift {
        if bn_cmp(&r, &shifted_m) >= 0 {
            r = bn_sub(&r, &shifted_m);
        }
        shifted_m = bn_shr1(&shifted_m);
    }

    r
}

/// Left-shift by n bits
fn bn_shl(a: &BigNum, n: usize) -> BigNum {
    if n == 0 { return a.clone(); }
    let word_shift = n / 32;
    let bit_shift = n % 32;

    let mut limbs = alloc::vec![0u32; a.limbs.len() + word_shift + 1];
    if bit_shift == 0 {
        for i in 0..a.limbs.len() {
            limbs[i + word_shift] = a.limbs[i];
        }
    } else {
        let mut carry = 0u32;
        for i in 0..a.limbs.len() {
            let v = a.limbs[i];
            limbs[i + word_shift] = (v << bit_shift) | carry;
            carry = v >> (32 - bit_shift);
        }
        if carry != 0 {
            limbs[a.limbs.len() + word_shift] = carry;
        }
    }
    trim(&mut limbs);
    BigNum { limbs }
}

/// Right-shift by 1 bit
fn bn_shr1(a: &BigNum) -> BigNum {
    let mut limbs = Vec::with_capacity(a.limbs.len());
    let mut carry = 0u32;
    for i in (0..a.limbs.len()).rev() {
        let new_carry = a.limbs[i] & 1;
        limbs.push((a.limbs[i] >> 1) | (carry << 31));
        carry = new_carry;
    }
    limbs.reverse();
    trim(&mut limbs);
    BigNum { limbs }
}

// ─── Modular Exponentiation ─────────────────────────────────────────────────

/// Compute base^exp mod modulus  (square-and-multiply, left-to-right)
pub fn mod_exp(base: &BigNum, exp: &BigNum, modulus: &BigNum) -> BigNum {
    if modulus.is_zero() { return BigNum::zero(); }

    let exp_bits = exp.bit_len();
    if exp_bits == 0 {
        // x^0 = 1
        return BigNum::from_be_bytes(&[1]);
    }

    let mut result = BigNum::from_be_bytes(&[1]);
    let mut b = bn_mod(base, modulus);

    for i in 0..exp_bits {
        let limb_idx = i / 32;
        let bit_idx = i % 32;
        if limb_idx < exp.limbs.len() && (exp.limbs[limb_idx] >> bit_idx) & 1 == 1 {
            result = bn_mulmod(&result, &b, modulus);
        }
        b = bn_mulmod(&b, &b, modulus);
    }

    result
}

// ─── RSA PKCS#1 v1.5 Encryption (Type 2) ────────────────────────────────────

/// RSA PKCS#1 v1.5 encrypt:  0x00 0x02 <random_padding> 0x00 <message>
/// Used to encrypt PremasterSecret with server's RSA public key.
pub fn rsa_encrypt(msg: &[u8], n: &BigNum, e: &BigNum) -> Vec<u8> {
    let k = (n.bit_len() + 7) / 8; // modulus byte length
    // PKCS#1 v1.5 type 2: 00 02 PS 00 M
    // PS must be ≥ 8 bytes of non-zero random
    let ps_len = k - 3 - msg.len();

    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x02);

    // Generate non-zero random padding
    let mut ps = alloc::vec![0u8; ps_len];
    super::rng::random_bytes(&mut ps);
    // Ensure no zero bytes in padding
    for b in ps.iter_mut() {
        while *b == 0 {
            let mut tmp = [0u8; 1];
            super::rng::random_bytes(&mut tmp);
            *b = tmp[0];
        }
    }
    em.extend_from_slice(&ps);

    em.push(0x00);
    em.extend_from_slice(msg);

    // m = OS2IP(em), c = m^e mod n, output = I2OSP(c, k)
    let m = BigNum::from_be_bytes(&em);
    let c = mod_exp(&m, e, n);
    c.to_be_bytes_padded(k)
}
