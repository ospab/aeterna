// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//
// Copy-on-write B+tree operations.

use crate::dev::BlockDevice;
use crate::freemap::Bitmap;
use crate::fs::Fs;
use crate::layout::*;
use crate::{Error, Result};
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;

const MAX_DEPTH: usize = 24;

fn child_idx(kids: &[(Key, u64)], k: &Key) -> usize {
    kids.partition_point(|(s, _)| s <= k).saturating_sub(1)
}

fn clone_node(n: &Rc<Node>) -> Node {
    Node { gen: n.gen, leaf: n.leaf, items: n.items.clone(), kids: n.kids.clone() }
}

impl<D: BlockDevice> Fs<D> {
    pub(crate) fn tget(&mut self, root: u64, key: &Key) -> Result<Option<Vec<u8>>> {
        let mut blk = root;
        let mut maxg = self.cur_gen;
        for _ in 0..MAX_DEPTH {
            let n = self.load(blk, maxg)?;
            if n.leaf {
                return Ok(n.items.binary_search_by(|(k, _)| k.cmp(key)).ok().map(|i| n.items[i].1.clone()));
            }
            blk = n.kids[child_idx(&n.kids, key)].1;
            maxg = n.gen;
        }
        Err(Error::Corrupt("tree depth"))
    }

    pub(crate) fn tput(&mut self, key: Key, val: &[u8]) -> Result<()> {
        if val.len() > MAX_VAL { return Err(Error::TooLarge); }
        let g = self.cur_gen;
        let (nb, split) = self.tins(self.root, g, 0, key, val)?;
        match split {
            None => self.root = nb,
            Some((sk, sb)) => {
                let node = Node { gen: 0, leaf: false, items: Vec::new(), kids: vec![(Key::MIN, nb), (sk, sb)] };
                self.root = self.write_node(None, node)?;
            }
        }
        Ok(())
    }

    fn tins(&mut self, blk: u64, maxg: u64, depth: usize, key: Key, val: &[u8]) -> Result<(u64, Option<(Key, u64)>)> {
        if depth > MAX_DEPTH { return Err(Error::Corrupt("tree depth")); }
        let n = self.load(blk, maxg)?;
        let mut node = clone_node(&n);
        if node.leaf {
            match node.items.binary_search_by(|(k, _)| k.cmp(&key)) {
                Ok(i) => node.items[i].1 = val.to_vec(),
                Err(i) => node.items.insert(i, (key, val.to_vec())),
            }
        } else {
            let i = child_idx(&node.kids, &key);
            let (nb, sp) = self.tins(node.kids[i].1, n.gen, depth + 1, key, val)?;
            node.kids[i].1 = nb;
            if let Some((sk, sb)) = sp { node.kids.insert(i + 1, (sk, sb)); }
        }
        if node.size() > crate::BLOCK_SIZE {
            let mut right = Node { gen: 0, leaf: node.leaf, items: Vec::new(), kids: Vec::new() };
            if node.leaf {
                let total = node.size() - NODE_HDR;
                let mut acc = 0;
                let mut at = 0;
                for (i, (_, v)) in node.items.iter().enumerate() {
                    if acc >= total / 2 { at = i; break; }
                    acc += KEY_SIZE + 2 + v.len();
                    at = i + 1;
                }
                let at = at.clamp(1, node.items.len() - 1);
                right.items = node.items.split_off(at);
            } else {
                let at = node.kids.len() / 2;
                right.kids = node.kids.split_off(at);
            }
            let rkey = right.first_key();
            let rb = self.write_node(None, right)?;
            let lb = self.write_node(Some((blk, n.gen)), node)?;
            return Ok((lb, Some((rkey, rb))));
        }
        let b = self.write_node(Some((blk, n.gen)), node)?;
        Ok((b, None))
    }

    /// Deletes a key. Returns whether it existed.
    pub(crate) fn tdel(&mut self, key: Key) -> Result<bool> {
        let g = self.cur_gen;
        let (nb, found) = self.tdel_rec(self.root, g, 0, &key, true)?;
        if !found { return Ok(false); }
        self.root = nb.ok_or(Error::Corrupt("root vanished"))?;
        // collapse single-child roots
        loop {
            let g = self.cur_gen;
            let n = self.load(self.root, g)?;
            if n.leaf || n.kids.len() != 1 { break; }
            let old = self.root;
            self.root = n.kids[0].1;
            self.release(old, 1, n.gen);
        }
        Ok(true)
    }

    fn tdel_rec(&mut self, blk: u64, maxg: u64, depth: usize, key: &Key, is_root: bool) -> Result<(Option<u64>, bool)> {
        if depth > MAX_DEPTH { return Err(Error::Corrupt("tree depth")); }
        let n = self.load(blk, maxg)?;
        let mut node = clone_node(&n);
        if node.leaf {
            match node.items.binary_search_by(|(k, _)| k.cmp(key)) {
                Err(_) => return Ok((Some(blk), false)),
                Ok(i) => { node.items.remove(i); }
            }
            if node.items.is_empty() && !is_root {
                self.release(blk, 1, n.gen);
                return Ok((None, true));
            }
        } else {
            let i = child_idx(&node.kids, key);
            let (nb, found) = self.tdel_rec(node.kids[i].1, n.gen, depth + 1, key, false)?;
            if !found { return Ok((Some(blk), false)); }
            match nb {
                Some(b) => node.kids[i].1 = b,
                None => { node.kids.remove(i); }
            }
            if node.kids.is_empty() {
                if is_root {
                    node = Node::new_leaf();
                } else {
                    self.release(blk, 1, n.gen);
                    return Ok((None, true));
                }
            }
        }
        let b = self.write_node(Some((blk, n.gen)), node)?;
        Ok((Some(b), true))
    }

    /// Calls `f` for each item with key >= `from`, in order, until it returns false.
    pub(crate) fn tscan(&mut self, blk: u64, maxg: u64, depth: usize, from: &Key, f: &mut dyn FnMut(&Key, &[u8]) -> Result<bool>) -> Result<bool> {
        if depth > MAX_DEPTH { return Err(Error::Corrupt("tree depth")); }
        let n = self.load(blk, maxg)?;
        if n.leaf {
            let start = n.items.partition_point(|(k, _)| k < from);
            for (k, v) in &n.items[start..] {
                if !f(k, v)? { return Ok(false); }
            }
            return Ok(true);
        }
        let i = child_idx(&n.kids, from);
        for j in i..n.kids.len() {
            if !self.tscan(n.kids[j].1, n.gen, depth + 1, from, f)? { return Ok(false); }
        }
        Ok(true)
    }

    /// Items with `from <= key <= to`, at most `limit`.
    pub(crate) fn tcollect(&mut self, root: u64, from: Key, to: Key, limit: usize) -> Result<Vec<(Key, Vec<u8>)>> {
        let mut out: Vec<(Key, Vec<u8>)> = Vec::new();
        let g = self.cur_gen;
        self.tscan(root, g, 0, &from, &mut |k, v| {
            if *k > to || out.len() >= limit { return Ok(false); }
            out.push((*k, v.to_vec()));
            Ok(true)
        })?;
        Ok(out)
    }

    /// Greatest item with key <= `key`.
    pub(crate) fn tfind_le(&mut self, root: u64, key: &Key) -> Result<Option<(Key, Vec<u8>)>> {
        let g = self.cur_gen;
        self.tfind_rec(root, g, 0, key)
    }

    fn tfind_rec(&mut self, blk: u64, maxg: u64, depth: usize, key: &Key) -> Result<Option<(Key, Vec<u8>)>> {
        if depth > MAX_DEPTH { return Err(Error::Corrupt("tree depth")); }
        let n = self.load(blk, maxg)?;
        if n.leaf {
            let pp = n.items.partition_point(|(k, _)| k <= key);
            return Ok(if pp > 0 { Some(n.items[pp - 1].clone()) } else { None });
        }
        let i = child_idx(&n.kids, key);
        for j in (0..=i).rev() {
            if let Some(r) = self.tfind_rec(n.kids[j].1, n.gen, depth + 1, key)? { return Ok(Some(r)); }
        }
        Ok(None)
    }

    /// Walks every node and item of a tree. With `skip_shared`, subtrees whose
    /// root is already marked in `used` are skipped; otherwise a repeated block
    /// is counted in `dups`.
    pub(crate) fn walk(&mut self, root: u64, maxg: u64, used: &mut Bitmap, skip_shared: bool, dups: &mut u64, f: &mut dyn FnMut(&Key, &[u8]) -> Result<()>) -> Result<()> {
        self.walk_rec(root, maxg, 0, used, skip_shared, dups, f)
    }

    fn walk_rec(&mut self, blk: u64, maxg: u64, depth: usize, used: &mut Bitmap, skip_shared: bool, dups: &mut u64, f: &mut dyn FnMut(&Key, &[u8]) -> Result<()>) -> Result<()> {
        if depth > MAX_DEPTH { return Err(Error::Corrupt("tree depth")); }
        if used.get(blk) {
            if skip_shared { return Ok(()); }
            *dups += 1;
        }
        let n = self.load(blk, maxg)?;
        used.set(blk);
        if n.leaf {
            for (k, v) in &n.items { f(k, v)?; }
        } else {
            for (_, c) in &n.kids {
                self.walk_rec(*c, n.gen, depth + 1, used, skip_shared, dups, f)?;
            }
        }
        Ok(())
    }
}
