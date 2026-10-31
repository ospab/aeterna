// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// In-memory free extent map and a simple bitmap.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

pub struct FreeMap {
    pub map: BTreeMap<u64, u64>,
    pub total: u64,
    cursor: u64,
}

impl FreeMap {
    pub fn new() -> FreeMap {
        FreeMap { map: BTreeMap::new(), total: 0, cursor: 0 }
    }

    /// Adds a free range. Returns false when it overlaps a free range.
    pub fn insert(&mut self, start: u64, len: u64) -> bool {
        if len == 0 { return true; }
        let end = start + len;
        let mut s = start;
        let mut e = end;
        if let Some((&ps, &pl)) = self.map.range(..=start).next_back() {
            if ps + pl > start { return false; }
            if ps + pl == start { s = ps; }
        }
        if let Some((&ns, &nl)) = self.map.range(start..).next() {
            if ns < end { return false; }
            if ns == end { e = ns + nl; self.map.remove(&ns); }
        }
        self.map.insert(s, e - s);
        self.total += len;
        true
    }

    #[allow(dead_code)]
    pub fn contains(&self, blk: u64) -> bool {
        match self.map.range(..=blk).next_back() {
            Some((&s, &l)) => blk < s + l,
            None => false,
        }
    }

    fn take(&mut self, s: u64, l: u64, n: u64) -> (u64, u64) {
        self.map.remove(&s);
        if l > n {
            self.map.insert(s + n, l - n);
        }
        self.total -= n;
        self.cursor = s + n;
        (s, n)
    }

    /// Allocates up to `want` contiguous blocks, preferring the range that
    /// starts at `hint`. Returns the run actually allocated (at least one block).
    pub fn alloc(&mut self, want: u64, hint: u64) -> Option<(u64, u64)> {
        if self.total == 0 || want == 0 { return None; }
        if let Some(&l) = self.map.get(&hint) {
            let n = l.min(want);
            return Some(self.take(hint, l, n));
        }
        let mut best: Option<(u64, u64)> = None;
        let mut found: Option<(u64, u64)> = None;
        for (&s, &l) in self.map.range(self.cursor..).chain(self.map.range(..self.cursor)) {
            if l >= want { found = Some((s, l)); break; }
            if best.map_or(true, |(_, bl)| l > bl) { best = Some((s, l)); }
        }
        let (s, l) = found.or(best)?;
        let n = l.min(want);
        Some(self.take(s, l, n))
    }

    pub fn to_bitmap(&self, blocks: u64) -> Bitmap {
        let mut b = Bitmap::new(blocks);
        for (&s, &l) in &self.map {
            b.set_range(s, l);
        }
        b
    }
}

pub struct Bitmap {
    w: Vec<u64>,
    pub n: u64,
}

impl Bitmap {
    pub fn new(n: u64) -> Bitmap {
        Bitmap { w: vec![0u64; ((n + 63) / 64) as usize], n }
    }
    pub fn get(&self, i: u64) -> bool {
        i < self.n && self.w[(i / 64) as usize] & (1 << (i % 64)) != 0
    }
    pub fn set(&mut self, i: u64) {
        if i < self.n { self.w[(i / 64) as usize] |= 1 << (i % 64); }
    }
    pub fn or_with(&mut self, o: &Bitmap) {
        for (a, b) in self.w.iter_mut().zip(o.w.iter()) { *a |= *b; }
    }
    pub fn set_range(&mut self, s: u64, l: u64) {
        for i in s..(s + l).min(self.n) { self.set(i); }
    }
}
