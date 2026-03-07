/*
 * Minimal X.509 / ASN.1 DER parser for TLS 1.2
 *
 * Only extracts the RSA public key (modulus n, exponent e) from the
 * server's leaf certificate.  We do NOT validate certificate chains
 * or trust anchors — bare-metal OS without a CA store.
 *
 * ASN.1 DER cheat-sheet:
 *   SEQUENCE = 0x30   INTEGER = 0x02   BIT STRING = 0x03
 *   OCTET STRING = 0x04   OID = 0x06   SET = 0x31
 *   Context [0] = 0xA0   Context [3] = 0xA3
 */

use alloc::vec::Vec;
use super::bignum::BigNum;

pub struct RsaPubKey {
    pub n: BigNum,
    pub e: BigNum,
}

// ─── ASN.1 DER primitives ───────────────────────────────────────────────────

/// Read tag + length, return (tag, content_slice, rest_after_content).
fn read_tlv<'a>(data: &'a [u8]) -> Option<(u8, &'a [u8], &'a [u8])> {
    if data.is_empty() { return None; }
    let tag = data[0];
    let (len, hdr_size) = read_der_len(&data[1..])?;
    let start = 1 + hdr_size;
    if start + len > data.len() { return None; }
    Some((tag, &data[start..start + len], &data[start + len..]))
}

/// Read DER length encoding.  Returns (length_value, bytes_consumed).
fn read_der_len(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() { return None; }
    let b0 = data[0];
    if b0 < 0x80 {
        Some((b0 as usize, 1))
    } else {
        let num_bytes = (b0 & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Some((len, 1 + num_bytes))
    }
}

/// Skip one TLV element, returning the rest.
fn skip_tlv<'a>(data: &'a [u8]) -> Option<&'a [u8]> {
    let (_, _, rest) = read_tlv(data)?;
    Some(rest)
}

// ─── Certificate parsing ────────────────────────────────────────────────────

/// Extract RSA public key from a DER-encoded X.509 certificate.
///
/// Certificate ::= SEQUENCE {
///   tbsCertificate      SEQUENCE {
///     version        [0] EXPLICIT ...
///     serialNumber   INTEGER
///     signature      SEQUENCE (AlgorithmIdentifier)
///     issuer         SEQUENCE
///     validity       SEQUENCE
///     subject        SEQUENCE
///     subjectPublicKeyInfo  SEQUENCE {     ← WE WANT THIS
///       algorithm    SEQUENCE (AlgorithmIdentifier — rsaEncryption OID)
///       subjectPublicKey  BIT STRING {
///         RSAPublicKey ::= SEQUENCE {
///           modulus        INTEGER
///           publicExponent INTEGER
///         }
///       }
///     }
///     ... extensions ...
///   }
///   signatureAlgorithm SEQUENCE
///   signatureValue     BIT STRING
/// }
pub fn extract_rsa_pubkey(cert_der: &[u8]) -> Option<RsaPubKey> {
    // Outer SEQUENCE (Certificate)
    let (tag, cert_content, _) = read_tlv(cert_der)?;
    if tag != 0x30 { return None; }

    // tbsCertificate SEQUENCE
    let (tag, tbs, _) = read_tlv(cert_content)?;
    if tag != 0x30 { return None; }

    let mut pos = tbs;

    // version [0] EXPLICIT — optional, skip if present
    if !pos.is_empty() && pos[0] == 0xA0 {
        pos = skip_tlv(pos)?;
    }

    // serialNumber INTEGER — skip
    pos = skip_tlv(pos)?;

    // signature AlgorithmIdentifier SEQUENCE — skip
    pos = skip_tlv(pos)?;

    // issuer SEQUENCE — skip
    pos = skip_tlv(pos)?;

    // validity SEQUENCE — skip
    pos = skip_tlv(pos)?;

    // subject SEQUENCE — skip
    pos = skip_tlv(pos)?;

    // subjectPublicKeyInfo SEQUENCE — THIS IS WHAT WE WANT
    let (tag, spki, _) = read_tlv(pos)?;
    if tag != 0x30 { return None; }

    // algorithm AlgorithmIdentifier SEQUENCE — skip (contains rsaEncryption OID)
    let spki_rest = skip_tlv(spki)?;

    // subjectPublicKey BIT STRING
    let (tag, bitstr, _) = read_tlv(spki_rest)?;
    if tag != 0x03 { return None; }

    // BIT STRING has a leading "unused bits" byte (should be 0x00 for RSA)
    if bitstr.is_empty() || bitstr[0] != 0x00 { return None; }
    let rsa_key_bytes = &bitstr[1..];

    // RSAPublicKey SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    let (tag, rsa_seq, _) = read_tlv(rsa_key_bytes)?;
    if tag != 0x30 { return None; }

    // modulus INTEGER
    let (tag, n_bytes, rest) = read_tlv(rsa_seq)?;
    if tag != 0x02 { return None; }

    // publicExponent INTEGER
    let (tag, e_bytes, _) = read_tlv(rest)?;
    if tag != 0x02 { return None; }

    // Strip leading zero byte (ASN.1 sign padding)
    let n_trimmed = if !n_bytes.is_empty() && n_bytes[0] == 0x00 {
        &n_bytes[1..]
    } else {
        n_bytes
    };
    let e_trimmed = if !e_bytes.is_empty() && e_bytes[0] == 0x00 {
        &e_bytes[1..]
    } else {
        e_bytes
    };

    Some(RsaPubKey {
        n: BigNum::from_be_bytes(n_trimmed),
        e: BigNum::from_be_bytes(e_trimmed),
    })
}

/// Parse the Certificate message from TLS handshake.
/// Format: 3-byte total length, then repeated (3-byte cert_length + DER cert).
/// Returns the FIRST (leaf) certificate's DER bytes.
pub fn parse_certificate_chain(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 3 { return None; }
    let _total_len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);

    let rest = &data[3..];
    if rest.len() < 3 { return None; }
    let cert_len = ((rest[0] as usize) << 16) | ((rest[1] as usize) << 8) | (rest[2] as usize);
    if rest.len() < 3 + cert_len { return None; }

    Some(rest[3..3 + cert_len].to_vec())
}
