/* Minimal DNS A-record query/response codec for `ostp dns` (tunnelled UDP). */

extern crate alloc;
use alloc::vec::Vec;

pub fn build_query(id: u16, name: &str) -> Option<Vec<u8>> {
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, 1 question
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    Some(q)
}

fn skip_name(p: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *p.get(i)? as usize;
        if l == 0 {
            return Some(i + 1);
        }
        if l & 0xC0 == 0xC0 {
            return Some(i + 2);
        }
        i += 1 + l;
    }
}

/// A records of a response to query `id`; `Err(rcode)` for a non-zero RCODE.
pub fn parse_a(p: &[u8], id: u16) -> Option<Result<Vec<[u8; 4]>, u8>> {
    if p.len() < 12 || u16::from_be_bytes([p[0], p[1]]) != id || p[2] & 0x80 == 0 {
        return None;
    }
    let rcode = p[3] & 0x0F;
    if rcode != 0 {
        return Some(Err(rcode));
    }
    let qd = u16::from_be_bytes([p[4], p[5]]) as usize;
    let an = u16::from_be_bytes([p[6], p[7]]) as usize;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(p, i)? + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        i = skip_name(p, i)?;
        let t = u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]);
        let rdlen = u16::from_be_bytes([*p.get(i + 8)?, *p.get(i + 9)?]) as usize;
        i += 10;
        if t == 1 && rdlen == 4 {
            out.push([*p.get(i)?, *p.get(i + 1)?, *p.get(i + 2)?, *p.get(i + 3)?]);
        }
        i += rdlen;
    }
    Some(Ok(out))
}
