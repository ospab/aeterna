// SPDX-License-Identifier: AGPL-3.0-only
//! Pixel surfaces: premultiplied ARGB8888 with an explicit stride.
//!
//! [`Surface`] owns its pixels (a window buffer, the compositor back buffer, an
//! image).  [`PixelsMut`] / [`Pixels`] are borrowed views, so the same drawing
//! code can target a heap buffer, a sub-rectangle, or (later) a shared-memory
//! mapping handed over by the compositor.

use alloc::vec;
use alloc::vec::Vec;

use crate::geom::Rect;

/// Owned premultiplied ARGB8888 surface.
#[derive(Clone)]
pub struct Surface {
    pub width: i32,
    pub height: i32,
    /// Row pitch in pixels (>= width).
    pub stride: usize,
    pub data: Vec<u32>,
}

impl Surface {
    pub fn new(width: i32, height: i32) -> Surface { Self::new_filled(width, height, 0) }

    pub fn new_filled(width: i32, height: i32, premul: u32) -> Surface {
        let (w, h) = (width.max(0), height.max(0));
        Surface { width: w, height: h, stride: w as usize, data: vec![premul; w as usize * h as usize] }
    }

    /// Wrap existing premultiplied pixels (e.g. a decoded image).
    pub fn from_vec(width: i32, height: i32, data: Vec<u32>) -> Surface {
        assert!(data.len() >= width as usize * height as usize);
        Surface { width, height, stride: width as usize, data }
    }

    pub fn rect(&self) -> Rect { Rect::from_size(self.width, self.height) }

    pub fn view(&self) -> Pixels<'_> {
        Pixels { data: &self.data, width: self.width, height: self.height, stride: self.stride }
    }

    pub fn view_mut(&mut self) -> PixelsMut<'_> {
        PixelsMut { data: &mut self.data, width: self.width, height: self.height, stride: self.stride }
    }

    #[inline]
    pub fn pixel(&self, x: i32, y: i32) -> u32 { self.data[y as usize * self.stride + x as usize] }

    /// Resize, discarding content.
    pub fn resize(&mut self, width: i32, height: i32) {
        if width == self.width && height == self.height { return; }
        *self = Surface::new(width, height);
    }

    pub fn clear(&mut self, premul: u32) {
        for p in self.data.iter_mut() { *p = premul; }
    }
}

/// Read-only pixel view.
#[derive(Clone, Copy)]
pub struct Pixels<'a> {
    pub data: &'a [u32],
    pub width: i32,
    pub height: i32,
    pub stride: usize,
}

impl<'a> Pixels<'a> {
    #[inline]
    pub fn row(&self, y: i32) -> &'a [u32] {
        let s = y as usize * self.stride;
        &self.data[s..s + self.width as usize]
    }
    pub fn rect(&self) -> Rect { Rect::from_size(self.width, self.height) }
}

/// Mutable pixel view.
pub struct PixelsMut<'a> {
    pub data: &'a mut [u32],
    pub width: i32,
    pub height: i32,
    pub stride: usize,
}

impl<'a> PixelsMut<'a> {
    /// View over raw memory (e.g. a linear framebuffer whose pixel format is
    /// already 0x00RRGGBB).
    ///
    /// # Safety
    /// `ptr` must be valid for `stride * height` u32 writes for `'a`.
    pub unsafe fn from_raw(ptr: *mut u32, width: i32, height: i32, stride: usize) -> PixelsMut<'a> {
        PixelsMut { data: core::slice::from_raw_parts_mut(ptr, stride * height as usize), width, height, stride }
    }

    #[inline]
    pub fn row_mut(&mut self, y: i32) -> &mut [u32] {
        let s = y as usize * self.stride;
        &mut self.data[s..s + self.width as usize]
    }

    pub fn rect(&self) -> Rect { Rect::from_size(self.width, self.height) }

    pub fn reborrow(&mut self) -> PixelsMut<'_> {
        PixelsMut { data: self.data, width: self.width, height: self.height, stride: self.stride }
    }
}
