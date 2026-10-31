// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// On-disk structures: keys, tree nodes, superblock, free-space pages.

use crate::crc::crc32c;
use crate::{Error, Result, BLOCK_SIZE};
use alloc::vec;
use alloc::vec::Vec;

pub const KIND_SNAP: u8 = 1;
pub const KIND_INODE: u8 = 2;
pub const KIND_DIR: u8 = 3;
pub const KIND_EXT: u8 = 4;
pub const KIND_LINK: u8 = 5;

pub const KEY_SIZE: usize = 17;
pub const NODE_HDR: usize = 32;
pub const MAX_VAL: usize = 1000;
pub const NODE_MAGIC: u16 = 0x4E41; // "AN"
pub const FREE_MAGIC: u16 = 0x4641; // "AF"
pub const SB_MAGIC: &[u8; 8] = b"AETERNA2";
pub const FREE_PER_PAGE: usize = (BLOCK_SIZE - 40) / 16;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Key {
    pub obj: u64,
    pub kind: u8,
    pub off: u64,
}

impl Key {
    pub const MIN: Key = Key { obj: 0, kind: 0, off: 0 };
    pub fn new(obj: u64, kind: u8, off: u64) -> Key {
        Key { obj, kind, off }
    }
}

fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn put_key(b: &mut [u8], o: usize, k: &Key) {
    b[o..o + 8].copy_from_slice(&k.obj.to_le_bytes());
    b[o + 8] = k.kind;
    b[o + 9..o + 17].copy_from_slice(&k.off.to_le_bytes());
}
fn get_key(b: &[u8], o: usize) -> Key {
    Key { obj: rd64(b, o), kind: b[o + 8], off: rd64(b, o + 9) }
}

fn seal(b: &mut [u8]) {
    let c = crc32c(&b[4..]);
    b[0..4].copy_from_slice(&c.to_le_bytes());
}
fn check(b: &[u8], blk: u64) -> Result<()> {
    if b.len() != BLOCK_SIZE { return Err(Error::Corrupt("block size")); }
    if rd32(b, 0) != crc32c(&b[4..]) { return Err(Error::Checksum(blk)); }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Node {
    pub gen: u64,
    pub leaf: bool,
    pub items: Vec<(Key, Vec<u8>)>,
    pub kids: Vec<(Key, u64)>,
}

impl Node {
    pub fn new_leaf() -> Node {
        Node { gen: 0, leaf: true, items: Vec::new(), kids: Vec::new() }
    }
    pub fn size(&self) -> usize {
        if self.leaf {
            NODE_HDR + self.items.iter().map(|(_, v)| KEY_SIZE + 2 + v.len()).sum::<usize>()
        } else {
            NODE_HDR + self.kids.len() * (KEY_SIZE + 8)
        }
    }
    pub fn first_key(&self) -> Key {
        if self.leaf { self.items[0].0 } else { self.kids[0].0 }
    }
    pub fn encode(&self, blk: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLOCK_SIZE];
        b[4..6].copy_from_slice(&NODE_MAGIC.to_le_bytes());
        b[6] = if self.leaf { 1 } else { 2 };
        let n = if self.leaf { self.items.len() } else { self.kids.len() };
        b[8..12].copy_from_slice(&(n as u32).to_le_bytes());
        b[12..20].copy_from_slice(&self.gen.to_le_bytes());
        b[20..28].copy_from_slice(&blk.to_le_bytes());
        let mut p = NODE_HDR;
        if self.leaf {
            for (k, v) in &self.items {
                put_key(&mut b, p, k);
                b[p + KEY_SIZE..p + KEY_SIZE + 2].copy_from_slice(&(v.len() as u16).to_le_bytes());
                b[p + KEY_SIZE + 2..p + KEY_SIZE + 2 + v.len()].copy_from_slice(v);
                p += KEY_SIZE + 2 + v.len();
            }
        } else {
            for (k, c) in &self.kids {
                put_key(&mut b, p, k);
                b[p + KEY_SIZE..p + KEY_SIZE + 8].copy_from_slice(&c.to_le_bytes());
                p += KEY_SIZE + 8;
            }
        }
        debug_assert!(p <= BLOCK_SIZE);
        seal(&mut b);
        b
    }
    pub fn decode(b: &[u8], blk: u64) -> Result<Node> {
        check(b, blk)?;
        if rd16(b, 4) != NODE_MAGIC { return Err(Error::Corrupt("node magic")); }
        if rd64(b, 20) != blk { return Err(Error::Corrupt("node misplaced")); }
        let n = rd32(b, 8) as usize;
        let gen = rd64(b, 12);
        let mut p = NODE_HDR;
        match b[6] {
            1 => {
                let mut items: Vec<(Key, Vec<u8>)> = Vec::with_capacity(n.min(256));
                for _ in 0..n {
                    if p + KEY_SIZE + 2 > BLOCK_SIZE { return Err(Error::Corrupt("leaf overrun")); }
                    let k = get_key(b, p);
                    let l = rd16(b, p + KEY_SIZE) as usize;
                    p += KEY_SIZE + 2;
                    if l > MAX_VAL || p + l > BLOCK_SIZE { return Err(Error::Corrupt("leaf item")); }
                    if let Some((pk, _)) = items.last() {
                        if *pk >= k { return Err(Error::Corrupt("leaf order")); }
                    }
                    items.push((k, b[p..p + l].to_vec()));
                    p += l;
                }
                Ok(Node { gen, leaf: true, items, kids: Vec::new() })
            }
            2 => {
                if n == 0 || NODE_HDR + n * (KEY_SIZE + 8) > BLOCK_SIZE {
                    return Err(Error::Corrupt("internal count"));
                }
                let mut kids: Vec<(Key, u64)> = Vec::with_capacity(n);
                for _ in 0..n {
                    let k = get_key(b, p);
                    if let Some((pk, _)) = kids.last() {
                        if *pk >= k { return Err(Error::Corrupt("internal order")); }
                    }
                    kids.push((k, rd64(b, p + KEY_SIZE)));
                    p += KEY_SIZE + 8;
                }
                Ok(Node { gen, leaf: false, items: Vec::new(), kids })
            }
            _ => Err(Error::Corrupt("node kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Super {
    pub generation: u64,
    pub block_count: u64,
    pub root: u64,
    pub free_head: u64,
    pub free_pages: u32,
    pub last_snap_gen: u64,
    pub next_ino: u64,
    pub next_snap: u64,
    pub hash_seed: u64,
    pub created: i64,
    pub label: Vec<u8>,
}

impl Super {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; BLOCK_SIZE];
        b[4..12].copy_from_slice(SB_MAGIC);
        b[12..16].copy_from_slice(&1u32.to_le_bytes());
        b[16..20].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
        b[20..28].copy_from_slice(&self.generation.to_le_bytes());
        b[28..36].copy_from_slice(&self.block_count.to_le_bytes());
        b[36..44].copy_from_slice(&self.root.to_le_bytes());
        b[44..52].copy_from_slice(&self.free_head.to_le_bytes());
        b[52..56].copy_from_slice(&self.free_pages.to_le_bytes());
        b[56..64].copy_from_slice(&self.last_snap_gen.to_le_bytes());
        b[64..72].copy_from_slice(&self.next_ino.to_le_bytes());
        b[72..80].copy_from_slice(&self.next_snap.to_le_bytes());
        b[80..88].copy_from_slice(&self.hash_seed.to_le_bytes());
        b[88..96].copy_from_slice(&self.created.to_le_bytes());
        let l = self.label.len().min(63);
        b[96] = l as u8;
        b[97..97 + l].copy_from_slice(&self.label[..l]);
        seal(&mut b);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Super> {
        if b.len() != BLOCK_SIZE { return Err(Error::Corrupt("sb size")); }
        if &b[4..12] != SB_MAGIC { return Err(Error::NotFormatted); }
        check(b, 0)?;
        if rd32(b, 12) != 1 || rd32(b, 16) as usize != BLOCK_SIZE { return Err(Error::Corrupt("sb version")); }
        let l = b[96] as usize;
        if l > 63 { return Err(Error::Corrupt("sb label")); }
        Ok(Super {
            generation: rd64(b, 20),
            block_count: rd64(b, 28),
            root: rd64(b, 36),
            free_head: rd64(b, 44),
            free_pages: rd32(b, 52),
            last_snap_gen: rd64(b, 56),
            next_ino: rd64(b, 64),
            next_snap: rd64(b, 72),
            hash_seed: rd64(b, 80),
            created: rd64(b, 88) as i64,
            label: b[97..97 + l].to_vec(),
        })
    }
}

pub struct FreePage {
    pub gen: u64,
    pub next: u64,
    pub entries: Vec<(u64, u64)>,
}

impl FreePage {
    pub fn encode(&self, blk: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLOCK_SIZE];
        b[4..6].copy_from_slice(&FREE_MAGIC.to_le_bytes());
        b[8..12].copy_from_slice(&(self.entries.len() as u32).to_le_bytes());
        b[12..20].copy_from_slice(&self.gen.to_le_bytes());
        b[20..28].copy_from_slice(&blk.to_le_bytes());
        b[28..36].copy_from_slice(&self.next.to_le_bytes());
        for (i, (s, l)) in self.entries.iter().enumerate() {
            b[40 + i * 16..48 + i * 16].copy_from_slice(&s.to_le_bytes());
            b[48 + i * 16..56 + i * 16].copy_from_slice(&l.to_le_bytes());
        }
        seal(&mut b);
        b
    }
    pub fn decode(b: &[u8], blk: u64) -> Result<FreePage> {
        check(b, blk)?;
        if rd16(b, 4) != FREE_MAGIC || rd64(b, 20) != blk { return Err(Error::Corrupt("free page")); }
        let n = rd32(b, 8) as usize;
        if n > FREE_PER_PAGE { return Err(Error::Corrupt("free page count")); }
        let mut entries = Vec::with_capacity(n);
        for i in 0..n {
            entries.push((rd64(b, 40 + i * 16), rd64(b, 48 + i * 16)));
        }
        Ok(FreePage { gen: rd64(b, 12), next: rd64(b, 28), entries })
    }
}
