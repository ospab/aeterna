// SPDX-License-Identifier: AGPL-3.0-only
//! Damage tracking: the set of rectangles that must be repainted.
//!
//! Rectangles are merged when they overlap or when merging wastes little
//! area; past `max_rects` everything collapses into the bounding box.  This
//! keeps per-frame work proportional to what changed (a blinking caret, a
//! hovered button, a moving cursor), and the same rect list is what a client
//! will send to the compositor with each frame.

use alloc::vec::Vec;

use crate::geom::Rect;

#[derive(Clone, Debug)]
pub struct Damage {
    rects: Vec<Rect>,
    pub max_rects: usize,
}

impl Default for Damage {
    fn default() -> Self { Damage::new() }
}

impl Damage {
    pub fn new() -> Self { Damage { rects: Vec::new(), max_rects: 16 } }

    pub fn is_empty(&self) -> bool { self.rects.is_empty() }
    pub fn rects(&self) -> &[Rect] { &self.rects }

    pub fn bounds(&self) -> Rect {
        self.rects.iter().fold(Rect::default(), |a, r| a.union(r))
    }

    pub fn add(&mut self, r: Rect) {
        if r.is_empty() { return; }
        let mut r = r;
        // Merge with anything it overlaps or nearly touches, repeatedly.
        loop {
            let mut merged = false;
            let mut i = 0;
            while i < self.rects.len() {
                let o = self.rects[i];
                if o.contains_rect(&r) { return; }
                let u = o.union(&r);
                let waste = u.area() - o.area() - r.area() + o.intersect(&r).area();
                if o.outset(1).intersects(&r) && (waste <= (o.area() + r.area()) / 4 || r.contains_rect(&o) || o.intersects(&r)) {
                    r = u;
                    self.rects.swap_remove(i);
                    merged = true;
                } else {
                    i += 1;
                }
            }
            if !merged { break; }
        }
        self.rects.push(r);
        if self.rects.len() > self.max_rects {
            let b = self.bounds();
            self.rects.clear();
            self.rects.push(b);
        }
    }

    pub fn add_all(&mut self, rs: &[Rect]) {
        for r in rs { self.add(*r); }
    }

    /// Clip every rect to `bounds`.
    pub fn clip(&mut self, bounds: Rect) {
        for r in self.rects.iter_mut() { *r = r.intersect(&bounds); }
        self.rects.retain(|r| !r.is_empty());
    }

    pub fn take(&mut self) -> Vec<Rect> { core::mem::take(&mut self.rects) }
    pub fn clear(&mut self) { self.rects.clear(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_overlaps() {
        let mut d = Damage::new();
        d.add(Rect::new(0, 0, 10, 10));
        d.add(Rect::new(5, 5, 10, 10));
        assert_eq!(d.rects().len(), 1);
        assert_eq!(d.rects()[0], Rect::new(0, 0, 15, 15));
        d.add(Rect::new(100, 100, 4, 4));
        assert_eq!(d.rects().len(), 2);
        d.add(Rect::new(1, 1, 2, 2));
        assert_eq!(d.rects().len(), 2);
    }
}
