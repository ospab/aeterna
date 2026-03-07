/*
 * TLS 1.2 Handshake + Application Data (RFC 5246)
 *
 * Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA256  (0x003C)
 *
 * Handshake flow (RSA key exchange):
 *   C → S: ClientHello
 *   S → C: ServerHello, Certificate, ServerHelloDone
 *   C → S: ClientKeyExchange (RSA-encrypted PremasterSecret)
 *   C → S: ChangeCipherSpec
 *   C → S: Finished (encrypted)
 *   S → C: ChangeCipherSpec
 *   S → C: Finished (encrypted)
 *   ---- Application data (encrypted) ----
 */

use alloc::vec::Vec;
use super::record;
use super::bignum;
use super::x509;
use super::prf;

/// Session keys derived from master_secret.
struct SessionKeys {
    client_mac_key: [u8; 32],
    server_mac_key: [u8; 32],
    client_enc_key: [u8; 16],
    server_enc_key: [u8; 16],
    // CBC IVs are explicit in TLS 1.2, not from key material
}

/// Active TLS connection state.
pub struct TlsConn {
    tcp_conn: usize,                // underlying TCP connection ID
    keys: Option<SessionKeys>,
    client_seq: u64,
    server_seq: u64,
    recv_buf: Vec<u8>,              // buffered encrypted data from TCP
}

// ─── Handshake message types ─────────────────────────────────────────────────

const HS_CLIENT_HELLO:      u8 = 1;
const HS_SERVER_HELLO:      u8 = 2;
const HS_CERTIFICATE:       u8 = 11;
const HS_SERVER_HELLO_DONE: u8 = 14;
const HS_CLIENT_KEY_EXCH:   u8 = 16;
const HS_FINISHED:          u8 = 20;

// Cipher suite ID
const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003C;

// ─── TCP I/O helpers ─────────────────────────────────────────────────────────

fn tcp_send_all(conn: usize, data: &[u8]) -> bool {
    match crate::net::tcp::tcp_send(conn, data) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Read at least `min_bytes` from TCP into `buf`, appending to existing data.
/// Returns false on timeout/error.
fn tcp_read_into(conn: usize, buf: &mut Vec<u8>, min_bytes: usize, timeout: u64) -> bool {
    let start = crate::arch::x86_64::idt::timer_ticks();
    let mut tmp = [0u8; 4096];
    while buf.len() < min_bytes {
        let elapsed = crate::arch::x86_64::idt::timer_ticks().wrapping_sub(start);
        if elapsed > timeout { return false; }
        match crate::net::tcp::tcp_recv(conn, &mut tmp, 50) {
            Ok(0) => return false, // connection closed
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(crate::net::tcp::TcpError::WouldBlock) => continue,
            Err(_) => return false,
        }
    }
    true
}

/// Read one complete TLS record from TCP.
fn read_record(conn: usize, buf: &mut Vec<u8>, timeout: u64) -> Option<(u8, Vec<u8>)> {
    // Need at least 5 bytes for header
    if !tcp_read_into(conn, buf, 5, timeout) { return None; }

    // Parse length from header
    let len = ((buf[3] as usize) << 8) | (buf[4] as usize);
    let total = 5 + len;

    // Read the rest
    if !tcp_read_into(conn, buf, total, timeout) { return None; }

    let (ct, payload, consumed) = record::parse_record(buf)?;
    // Remove consumed bytes from buffer
    *buf = buf[consumed..].to_vec();
    Some((ct, payload))
}

// ─── ClientHello ─────────────────────────────────────────────────────────────

fn build_client_hello(client_random: &[u8; 32], hostname: &str) -> Vec<u8> {
    let mut hs = Vec::with_capacity(128);

    // ProtocolVersion: TLS 1.2
    hs.push(record::TLS12_MAJOR);
    hs.push(record::TLS12_MINOR);

    // Random (32 bytes)
    hs.extend_from_slice(client_random);

    // Session ID length = 0
    hs.push(0);

    // Cipher suites (2-byte length + suites)
    // Cipher suites — RSA key exchange only (we don't implement ECDHE)
    hs.push(0x00); hs.push(0x02); // 2 bytes = 1 suite
    hs.push(0x00); hs.push(0x3C); // TLS_RSA_WITH_AES_128_CBC_SHA256

    // Compression methods: null only
    hs.push(0x01); // 1 method
    hs.push(0x00); // null compression

    // Extensions
    let mut exts = Vec::new();

    // SNI extension (type 0x0000)
    if !hostname.is_empty() {
        let name_bytes = hostname.as_bytes();
        let sni_list_len = 3 + name_bytes.len(); // type(1) + name_len(2) + name
        let sni_ext_len = 2 + sni_list_len;      // list_len(2) + list

        exts.push(0x00); exts.push(0x00); // extension type = server_name
        exts.push((sni_ext_len >> 8) as u8); exts.push(sni_ext_len as u8);
        exts.push((sni_list_len >> 8) as u8); exts.push(sni_list_len as u8);
        exts.push(0x00); // host_name type
        exts.push((name_bytes.len() >> 8) as u8); exts.push(name_bytes.len() as u8);
        exts.extend_from_slice(name_bytes);
    }

    // Signature algorithms extension (type 0x000D) — tell server we support SHA256+RSA
    {
        let sig_algs: &[u8] = &[
            0x04, 0x01, // SHA256 + RSA
            0x05, 0x01, // SHA384 + RSA
            0x06, 0x01, // SHA512 + RSA
            0x02, 0x01, // SHA1   + RSA (fallback)
        ];
        let algs_len = sig_algs.len();
        exts.push(0x00); exts.push(0x0D); // extension type = signature_algorithms
        exts.push(((algs_len + 2) >> 8) as u8); exts.push((algs_len + 2) as u8);
        exts.push((algs_len >> 8) as u8); exts.push(algs_len as u8);
        exts.extend_from_slice(sig_algs);
    }

    // Extensions length
    if !exts.is_empty() {
        hs.push((exts.len() >> 8) as u8);
        hs.push(exts.len() as u8);
        hs.extend_from_slice(&exts);
    }

    // Wrap in handshake header: type(1) + length(3)
    wrap_handshake(HS_CLIENT_HELLO, &hs)
}

/// Wrap handshake message: type(1) || length(3) || body
fn wrap_handshake(hs_type: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len();
    let mut msg = Vec::with_capacity(4 + len);
    msg.push(hs_type);
    msg.push((len >> 16) as u8);
    msg.push((len >> 8) as u8);
    msg.push(len as u8);
    msg.extend_from_slice(body);
    msg
}

// ─── Parse ServerHello ───────────────────────────────────────────────────────

struct ServerHello {
    server_random: [u8; 32],
    session_id: Vec<u8>,
    cipher_suite: u16,
}

fn parse_server_hello(data: &[u8]) -> Option<ServerHello> {
    if data.len() < 38 { return None; }
    // Skip version (2 bytes)
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&data[2..34]);

    let sid_len = data[34] as usize;
    if data.len() < 35 + sid_len + 2 { return None; }
    let session_id = data[35..35 + sid_len].to_vec();

    let cs_offset = 35 + sid_len;
    let cipher_suite = ((data[cs_offset] as u16) << 8) | (data[cs_offset + 1] as u16);

    Some(ServerHello { server_random, session_id, cipher_suite })
}

// ─── Parse handshake messages from a record payload ─────────────────────────

/// Parse multiple handshake messages from a single record payload.
/// Returns vec of (hs_type, hs_body).
fn parse_handshake_messages(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut msgs = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let hs_type = data[pos];
        let hs_len = ((data[pos + 1] as usize) << 16)
            | ((data[pos + 2] as usize) << 8)
            | (data[pos + 3] as usize);
        pos += 4;
        if pos + hs_len > data.len() { break; }
        msgs.push((hs_type, data[pos..pos + hs_len].to_vec()));
        pos += hs_len;
    }
    msgs
}

// ─── Key Derivation ─────────────────────────────────────────────────────────

fn derive_keys(
    pre_master_secret: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> ([u8; 48], SessionKeys) {
    // master_secret = PRF(pre_master_secret, "master secret", client_random + server_random)[0..48]
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);
    let ms_bytes = prf::prf(pre_master_secret, b"master secret", &seed, 48);
    let mut master_secret = [0u8; 48];
    master_secret.copy_from_slice(&ms_bytes);

    // key_block = PRF(master_secret, "key expansion", server_random + client_random)
    // For AES_128_CBC_SHA256:
    //   client_write_MAC_key  (32 bytes — SHA256 HMAC key)
    //   server_write_MAC_key  (32 bytes)
    //   client_write_key      (16 bytes — AES-128)
    //   server_write_key      (16 bytes)
    //   Total: 96 bytes
    let mut ks_seed = [0u8; 64];
    ks_seed[..32].copy_from_slice(server_random);
    ks_seed[32..].copy_from_slice(client_random);
    let kb = prf::prf(&master_secret, b"key expansion", &ks_seed, 96);

    let mut client_mac_key = [0u8; 32];
    let mut server_mac_key = [0u8; 32];
    let mut client_enc_key = [0u8; 16];
    let mut server_enc_key = [0u8; 16];

    client_mac_key.copy_from_slice(&kb[0..32]);
    server_mac_key.copy_from_slice(&kb[32..64]);
    client_enc_key.copy_from_slice(&kb[64..80]);
    server_enc_key.copy_from_slice(&kb[80..96]);

    (master_secret, SessionKeys {
        client_mac_key,
        server_mac_key,
        client_enc_key,
        server_enc_key,
    })
}

// ─── Verify Data (Finished message) ─────────────────────────────────────────

fn compute_verify_data(master_secret: &[u8; 48], label: &[u8], handshake_hash: &[u8; 32]) -> [u8; 12] {
    let vd = prf::prf(master_secret, label, handshake_hash, 12);
    let mut out = [0u8; 12];
    out.copy_from_slice(&vd[..12]);
    out
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Perform a TLS 1.2 handshake over an already-connected TCP connection.
/// Returns a TlsConn on success or an error string.
pub fn tls_connect(tcp_conn: usize, hostname: &str) -> Result<TlsConn, &'static str> {
    tls_connect_inner(tcp_conn, hostname)
}

/// Internal TLS handshake that properly tracks handshake hash.
fn tls_connect_inner(tcp_conn: usize, hostname: &str) -> Result<TlsConn, &'static str> {
    let s = crate::arch::x86_64::serial::write_str;

    // Accumulate ALL handshake message bytes for hash computation
    let mut hs_bytes: Vec<u8> = Vec::with_capacity(4096);

    // 1. client_random
    let mut client_random = [0u8; 32];
    super::rng::random_bytes(&mut client_random);

    s("[TLS] → ClientHello\r\n");

    // 2. ClientHello
    let ch = build_client_hello(&client_random, hostname);
    hs_bytes.extend_from_slice(&ch);
    let ch_record = record::build_record(record::CT_HANDSHAKE, &ch);
    if !tcp_send_all(tcp_conn, &ch_record) {
        return Err("TLS: failed to send ClientHello");
    }

    // 3. Read ServerHello, Certificate, ServerHelloDone
    let mut recv_buf: Vec<u8> = Vec::new();
    let mut server_hello: Option<ServerHello> = None;
    let mut cert_der: Option<Vec<u8>> = None;
    let mut got_server_done = false;
    let timeout = 1000;

    while !got_server_done {
        let (ct, payload) = read_record(tcp_conn, &mut recv_buf, timeout)
            .ok_or("TLS: timeout waiting for server")?;

        if ct == record::CT_ALERT {
            return Err("TLS: server sent alert");
        }
        if ct != record::CT_HANDSHAKE { continue; }

        // Add raw handshake payload to hash accumulator
        hs_bytes.extend_from_slice(&payload);

        let msgs = parse_handshake_messages(&payload);
        for (hs_type, hs_body) in msgs {
            match hs_type {
                HS_SERVER_HELLO => {
                    s("[TLS] ← ServerHello\r\n");
                    server_hello = Some(parse_server_hello(&hs_body)
                        .ok_or("TLS: bad ServerHello")?);
                }
                HS_CERTIFICATE => {
                    s("[TLS] ← Certificate\r\n");
                    cert_der = Some(x509::parse_certificate_chain(&hs_body)
                        .ok_or("TLS: bad Certificate")?);
                }
                HS_SERVER_HELLO_DONE => {
                    s("[TLS] ← ServerHelloDone\r\n");
                    got_server_done = true;
                }
                _ => { /* skip CertificateRequest etc */ }
            }
        }
    }

    let sh = server_hello.ok_or("TLS: no ServerHello")?;
    let cert = cert_der.ok_or("TLS: no Certificate")?;

    if sh.cipher_suite != TLS_RSA_WITH_AES_128_CBC_SHA256 {
        return Err("TLS: server rejected our cipher suite");
    }

    // 4. Extract RSA public key
    let rsa_key = x509::extract_rsa_pubkey(&cert)
        .ok_or("TLS: cannot extract RSA key")?;
    s("[TLS] RSA pubkey extracted\r\n");

    // 5. Pre-master secret
    let mut pre_master_secret = [0u8; 48];
    pre_master_secret[0] = record::TLS12_MAJOR;
    pre_master_secret[1] = record::TLS12_MINOR;
    super::rng::random_bytes(&mut pre_master_secret[2..]);

    // 6. RSA encrypt
    let encrypted_pms = bignum::rsa_encrypt(&pre_master_secret, &rsa_key.n, &rsa_key.e);

    // 7. ClientKeyExchange
    s("[TLS] → ClientKeyExchange\r\n");
    let mut cke_body = Vec::with_capacity(2 + encrypted_pms.len());
    cke_body.push((encrypted_pms.len() >> 8) as u8);
    cke_body.push(encrypted_pms.len() as u8);
    cke_body.extend_from_slice(&encrypted_pms);

    let cke_hs = wrap_handshake(HS_CLIENT_KEY_EXCH, &cke_body);
    hs_bytes.extend_from_slice(&cke_hs);
    let cke_record = record::build_record(record::CT_HANDSHAKE, &cke_hs);
    if !tcp_send_all(tcp_conn, &cke_record) {
        return Err("TLS: send CKE failed");
    }

    // 8. Derive session keys
    let (master_secret, keys) = derive_keys(&pre_master_secret, &client_random, &sh.server_random);
    s("[TLS] Session keys derived\r\n");

    // 9. ChangeCipherSpec
    s("[TLS] → ChangeCipherSpec\r\n");
    let ccs = record::build_record(record::CT_CHANGE_CIPHER, &[1]);
    if !tcp_send_all(tcp_conn, &ccs) {
        return Err("TLS: send CCS failed");
    }

    // 10. Client Finished
    //     verify_data = PRF(master, "client finished", SHA256(hs_bytes))[0..12]
    let hs_hash = super::sha256::sha256(&hs_bytes);
    let client_vd = compute_verify_data(&master_secret, b"client finished", &hs_hash);

    let finished_hs = wrap_handshake(HS_FINISHED, &client_vd);
    // The Finished message is ENCRYPTED
    let finished_record = record::build_encrypted_record(
        record::CT_HANDSHAKE,
        &finished_hs,
        0, // client seq = 0 (first encrypted message)
        &keys.client_mac_key,
        &keys.client_enc_key,
    );
    if !tcp_send_all(tcp_conn, &finished_record) {
        return Err("TLS: send Finished failed");
    }
    s("[TLS] → Finished (encrypted)\r\n");

    // Add client Finished to handshake hash (for server's Finished verification)
    hs_bytes.extend_from_slice(&finished_hs);

    // 11. Read server ChangeCipherSpec + Finished
    let mut got_server_ccs = false;
    let mut got_server_finished = false;

    while !got_server_finished {
        let (ct, payload) = read_record(tcp_conn, &mut recv_buf, timeout)
            .ok_or("TLS: timeout waiting for server Finished")?;

        match ct {
            record::CT_CHANGE_CIPHER => {
                s("[TLS] ← ChangeCipherSpec\r\n");
                got_server_ccs = true;
            }
            record::CT_HANDSHAKE if got_server_ccs => {
                // This is the encrypted Finished
                let decrypted = record::decrypt_record(
                    record::CT_HANDSHAKE,
                    &payload,
                    0, // server seq = 0
                    &keys.server_mac_key,
                    &keys.server_enc_key,
                ).ok_or("TLS: decrypt server Finished failed")?;

                // Verify the Finished content
                let hs_hash2 = super::sha256::sha256(&hs_bytes);
                let expected_vd = compute_verify_data(&master_secret, b"server finished", &hs_hash2);

                if decrypted.len() >= 4 && decrypted[0] == HS_FINISHED {
                    let vd_len = ((decrypted[1] as usize) << 16)
                        | ((decrypted[2] as usize) << 8)
                        | (decrypted[3] as usize);
                    let server_vd = &decrypted[4..4 + core::cmp::min(vd_len, decrypted.len() - 4)];

                    let mut diff: u8 = 0;
                    for i in 0..core::cmp::min(12, server_vd.len()) {
                        diff |= server_vd[i] ^ expected_vd[i];
                    }
                    if diff != 0 || server_vd.len() != 12 {
                        return Err("TLS: server Finished verify_data mismatch");
                    }
                }

                s("[TLS] ← Finished (verified)\r\n");
                got_server_finished = true;
            }
            record::CT_ALERT => {
                return Err("TLS: server alert during handshake");
            }
            _ => { /* skip unexpected records */ }
        }
    }

    s("[TLS] Handshake complete — connection encrypted\r\n");

    Ok(TlsConn {
        tcp_conn,
        keys: Some(keys),
        client_seq: 1, // first encrypted record was Finished (seq 0)
        server_seq: 1, // server's Finished was seq 0
        recv_buf,
    })
}

// ─── Data Transfer (encrypted application data) ─────────────────────────────

impl TlsConn {
    /// Send application data (encrypted).
    pub fn send(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        let keys = self.keys.as_ref().ok_or("TLS: no session keys")?;

        // Fragment if necessary
        let mut offset = 0;
        while offset < data.len() {
            let chunk_end = core::cmp::min(offset + record::MAX_FRAGMENT, data.len());
            let chunk = &data[offset..chunk_end];

            let enc_record = record::build_encrypted_record(
                record::CT_APP_DATA,
                chunk,
                self.client_seq,
                &keys.client_mac_key,
                &keys.client_enc_key,
            );

            if !tcp_send_all(self.tcp_conn, &enc_record) {
                return Err("TLS: send failed");
            }
            self.client_seq += 1;
            offset = chunk_end;
        }

        Ok(data.len())
    }

    /// Receive application data (decrypted).
    /// Returns number of bytes read, or 0 on connection close.
    pub fn recv(&mut self, buf: &mut [u8], timeout_ticks: u64) -> Result<usize, &'static str> {
        let start = crate::arch::x86_64::idt::timer_ticks();

        loop {
            let elapsed = crate::arch::x86_64::idt::timer_ticks().wrapping_sub(start);
            if elapsed > timeout_ticks { return Ok(0); }

            // Try to read a record
            let rec = read_record(self.tcp_conn, &mut self.recv_buf, 50);
            let (ct, payload) = match rec {
                Some(r) => r,
                None => {
                    // Check if we've exceeded total timeout
                    let elapsed2 = crate::arch::x86_64::idt::timer_ticks().wrapping_sub(start);
                    if elapsed2 > timeout_ticks { return Ok(0); }
                    continue;
                }
            };

            match ct {
                record::CT_APP_DATA => {
                    let keys = self.keys.as_ref().ok_or("TLS: no keys")?;
                    let decrypted = record::decrypt_record(
                        record::CT_APP_DATA,
                        &payload,
                        self.server_seq,
                        &keys.server_mac_key,
                        &keys.server_enc_key,
                    ).ok_or("TLS: decrypt failed")?;

                    self.server_seq += 1;

                    let take = core::cmp::min(decrypted.len(), buf.len());
                    buf[..take].copy_from_slice(&decrypted[..take]);
                    return Ok(take);
                }
                record::CT_ALERT => {
                    // Close notify or error — treat as EOF
                    return Ok(0);
                }
                _ => {
                    // Skip non-app-data records
                    continue;
                }
            }
        }
    }

    /// Send TLS close_notify alert and close TCP.
    pub fn close(mut self) {
        if let Some(ref keys) = self.keys {
            // close_notify alert: level=warning(1), description=close_notify(0)
            let alert = [1u8, 0];
            let enc = record::build_encrypted_record(
                record::CT_ALERT,
                &alert,
                self.client_seq,
                &keys.client_mac_key,
                &keys.client_enc_key,
            );
            let _ = tcp_send_all(self.tcp_conn, &enc);
        }
        crate::net::tcp::tcp_close(self.tcp_conn);
    }

    /// Get the underlying TCP connection ID.
    pub fn tcp_id(&self) -> usize {
        self.tcp_conn
    }
}
