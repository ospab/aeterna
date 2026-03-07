/*
 * TLS 1.2 Stack for AETERNA
 *
 * Pure no_std Rust implementation — no external crypto crates.
 *
 * Supported cipher suite:
 *   TLS_RSA_WITH_AES_128_CBC_SHA256  (0x003C)
 *
 * Crypto primitives (all in-tree):
 *   SHA-256, HMAC-SHA256, AES-128-CBC, RSA PKCS#1 v1.5, RDRAND RNG
 *
 * Usage:
 *   let conn_id = tcp::tcp_connect(ip, 443)?;
 *   let mut tls = tls::connect(conn_id, "example.com")?;
 *   tls.send(b"GET / HTTP/1.0\r\n...")?;
 *   let n = tls.recv(&mut buf, 500)?;
 *   tls.close();
 */

extern crate alloc;

pub mod sha256;
pub mod hmac;
pub mod aes;
pub mod rng;
pub mod prf;
pub mod bignum;
pub mod x509;
pub mod record;
pub mod handshake;

/// Convenience: perform TCP connect + TLS handshake in one call.
pub fn connect(ip: [u8; 4], port: u16, hostname: &str) -> Result<handshake::TlsConn, &'static str> {
    let tcp_conn = crate::net::tcp::tcp_connect(ip, port)
        .map_err(|_| "TLS: TCP connect failed")?;

    match handshake::tls_connect(tcp_conn, hostname) {
        Ok(tls) => Ok(tls),
        Err(e) => {
            crate::net::tcp::tcp_close(tcp_conn);
            Err(e)
        }
    }
}
