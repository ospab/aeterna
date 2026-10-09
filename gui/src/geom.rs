// SPDX-License-Identifier: AGPL-3.0-only
//! Integer geometry: points, sizes, rectangles, insets.

/// A point in pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    pub const fn new(x: i32, y: i32) -> Self { Point { x, y } }
}

/// A size in pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Size {
    pub w: i32,
    pub h: i32,
}

impl Size {
    pub const fn new(w: i32, h: i32) -> Self { Size { w, h } }
}

/// An axis-aligned rectangle: origin (x, y), extent (w, h). Empty if w or h <= 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self { Rect { x, y, w, h } }
    pub const fn from_size(w: i32, h: i32) -> Self { Rect { x: 0, y: 0, w, h } }
    pub fn from_ltrb(l: i32, t: i32, r: i32, b: i32) -> Self { Rect { x: l, y: t, w: r - l, h: b - t } }

    #[inline] pub const fn right(&self) -> i32 { self.x + self.w }
    #[inline] pub const fn bottom(&self) -> i32 { self.y + self.h }
    #[inline] pub const fn is_empty(&self) -> bool { self.w <= 0 || self.h <= 0 }
    #[inline] pub const fn area(&self) -> i64 { if self.is_empty() { 0 } else { self.w as i64 * self.h as i64 } }
    pub fn center(&self) -> Point { Point::new(self.x + self.w / 2, self.y + self.h / 2) }

    #[inline]
    pub fn contains(&self, x: i32, y: i32) -> bool {
        x >= self.x && y >= self.y && x < self.right() && y < self.bottom()
    }

    pub fn contains_rect(&self, o: &Rect) -> bool {
        o.is_empty() || (o.x >= self.x && o.y >= self.y && o.right() <= self.right() && o.bottom() <= self.bottom())
    }

    /// Intersection; the result may be empty.
    pub fn intersect(&self, o: &Rect) -> Rect {
        let l = self.x.max(o.x);
        let t = self.y.max(o.y);
        let r = self.right().min(o.right());
        let b = self.bottom().min(o.bottom());
        if r <= l || b <= t { Rect::new(l, t, 0, 0) } else { Rect::from_ltrb(l, t, r, b) }
    }

    pub fn intersects(&self, o: &Rect) -> bool { !self.intersect(o).is_empty() }

    /// Smallest rectangle containing both (empty rects are ignored).
    pub fn union(&self, o: &Rect) -> Rect {
        if self.is_empty() { return *o; }
        if o.is_empty() { return *self; }
        Rect::from_ltrb(self.x.min(o.x), self.y.min(o.y), self.right().max(o.right()), self.bottom().max(o.bottom()))
    }

    pub fn offset(&self, dx: i32, dy: i32) -> Rect { Rect::new(self.x + dx, self.y + dy, self.w, self.h) }

    /// Shrink by `d` on every side (negative grows).
    pub fn inset(&self, d: i32) -> Rect { Rect::new(self.x + d, self.y + d, self.w - 2 * d, self.h - 2 * d) }

    pub fn inset_by(&self, i: Insets) -> Rect {
        Rect::new(self.x + i.l, self.y + i.t, self.w - i.l - i.r, self.h - i.t - i.b)
    }

    pub fn outset(&self, d: i32) -> Rect { self.inset(-d) }
}

/// Padding on four sides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Insets {
    pub l: i32,
    pub t: i32,
    pub r: i32,
    pub b: i32,
}

impl Insets {
    pub const ZERO: Insets = Insets { l: 0, t: 0, r: 0, b: 0 };
    pub const fn all(v: i32) -> Self { Insets { l: v, t: v, r: v, b: v } }
    pub const fn xy(h: i32, v: i32) -> Self { Insets { l: h, t: v, r: h, b: v } }
    pub const fn new(l: i32, t: i32, r: i32, b: i32) -> Self { Insets { l, t, r, b } }
    pub const fn horizontal(&self) -> i32 { self.l + self.r }
    pub const fn vertical(&self) -> i32 { self.t + self.b }
}
