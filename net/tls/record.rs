/*
 * TLS 1.2 Record Protocol (RFC 5246 §6)
 *
 * Record format:
 *   ContentType (1)  |  ProtocolVersion (2)  |  Length (2)  |  Fragment
 *
 * Content types:
 *   20 = ChangeCipherSpec   21 = Alert   22 = Handshake   23 = ApplicationData
 */

use alloc::vec::Vec;

// Content types
pub const CT_CHANGE_CIPHER: u8 = 20;
pub const CT_ALERT: u8         = 21;
pub const CT_HANDSHAKE: u8     = 22;
pub const CT_APP_DATA: u8      = 23;

// TLS 1.2 version
pub const TLS12_MAJOR: u8 = 3;
pub const TLS12_MINOR: u8 = 3;

/// Maximum TLS record payload (2^14 = 16384).
pub const MAX_FRAGMENT: usize = 16384;

// ─── Plaintext record I/O (before encryption established) ───────────────────

/// Build a TLS record header + payload.
pub fn build_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut rec = Vec::with_capacity(5 + len);
    rec.push(content_type);
    rec.push(TLS12_MAJOR);
    rec.push(TLS12_MINOR);
    rec.push((len >> 8) as u8);
    rec.push(len as u8);
    rec.extend_from_slice(payload);
    rec
}

/// Parse one TLS record from a byte stream.
/// Returns (content_type, payload, bytes_consumed) or None if not enough data.
pub fn parse_record(data: &[u8]) -> Option<(u8, Vec<u8>, usize)> {
    if data.len() < 5 { return None; }
    let ct = data[0];
    // Accept TLS 1.0 (3,1) through 1.2 (3,3) — servers may use 3,1 in records
    if data[1] != 3 { return None; }
    let len = ((data[3] as usize) << 8) | (data[4] as usize);
    if len > MAX_FRAGMENT + 2048 { return None; } // allow some overhead for MAC+padding
    if data.len() < 5 + len { return None; }
    Some((ct, data[5..5 + len].to_vec(), 5 + len))
}

// ─── Encrypted record helpers ────────────────────────────────────────────────

/// Build an encrypted TLS record (AES-128-CBC-SHA256).
///
/// Format: explicit_IV (16) || AES-CBC( fragment || MAC || padding )
///
/// MAC = HMAC-SHA256( mac_key, seq_num(8) || ct(1) || version(2) || len(2) || fragment )
pub fn build_encrypted_record(
    content_type: u8,
    fragment: &[u8],
    seq_num: u64,
    mac_key: &[u8],      // 32 bytes for SHA256
    enc_key: &[u8; 16],  // AES-128 key
) -> Vec<u8> {
    // 1. Compute MAC over: seq_num || content_type || version || frag_length || fragment
    let mut mac_input = Vec::with_capacity(13 + fragment.len());
    mac_input.extend_from_slice(&seq_num.to_be_bytes());
    mac_input.push(content_type);
    mac_input.push(TLS12_MAJOR);
    mac_input.push(TLS12_MINOR);
    mac_input.push((fragment.len() >> 8) as u8);
    mac_input.push(fragment.len() as u8);
    mac_input.extend_from_slice(fragment);

    let mac = super::hmac::hmac_sha256(mac_key, &mac_input);

    // 2. Generate random IV
    let mut iv = [0u8; 16];
    super::rng::random_bytes(&mut iv);

    // 3. Plaintext = fragment || MAC(32)
    let mut plain = Vec::with_capacity(fragment.len() + 32);
    plain.extend_from_slice(fragment);
    plain.extend_from_slice(&mac);

    // 4. AES-CBC encrypt with PKCS#7 (from aes module)
    let ciphertext = super::aes::aes128_cbc_encrypt(enc_key, &iv, &plain);

    // 5. Build record: explicit_IV || ciphertext
    let payload_len = 16 + ciphertext.len();
    let mut rec = Vec::with_capacity(5 + payload_len);
    rec.push(content_type);
    rec.push(TLS12_MAJOR);
    rec.push(TLS12_MINOR);
    rec.push((payload_len >> 8) as u8);
    rec.push(payload_len as u8);
    rec.extend_from_slice(&iv);
    rec.extend_from_slice(&ciphertext);
    rec
}

/// Decrypt an encrypted TLS record.
/// Returns (content_type, decrypted_fragment) or None on error.
pub fn decrypt_record(
    content_type: u8,
    encrypted_payload: &[u8],
    seq_num: u64,
    mac_key: &[u8],
    enc_key: &[u8; 16],
) -> Option<Vec<u8>> {
    // encrypted_payload = explicit_IV(16) || ciphertext
    if encrypted_payload.len() < 32 { return None; } // at least IV + 1 block

    let iv: [u8; 16] = {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&encrypted_payload[..16]);
        arr
    };
    let ciphertext = &encrypted_payload[16..];

    // Decrypt
    let plaintext = super::aes::aes128_cbc_decrypt(enc_key, &iv, ciphertext)?;

    // plaintext = fragment || MAC(32)
    if plaintext.len() < 32 { return None; }
    let frag_len = plaintext.len() - 32;
    let fragment = &plaintext[..frag_len];
    let received_mac = &plaintext[frag_len..];

    // Verify MAC
    let mut mac_input = Vec::with_capacity(13 + frag_len);
    mac_input.extend_from_slice(&seq_num.to_be_bytes());
    mac_input.push(content_type);
    mac_input.push(TLS12_MAJOR);
    mac_input.push(TLS12_MINOR);
    mac_input.push((frag_len >> 8) as u8);
    mac_input.push(frag_len as u8);
    mac_input.extend_from_slice(fragment);

    let expected_mac = super::hmac::hmac_sha256(mac_key, &mac_input);

    // Constant-time MAC comparison
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= received_mac[i] ^ expected_mac[i];
    }
    if diff != 0 { return None; }

    Some(fragment.to_vec())
}
