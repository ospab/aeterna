// SPDX-License-Identifier: AGPL-3.0-only
//! oos-ui — the ospab.os user-interface toolkit.
//!
//! `no_std + alloc`; everything is rendered in software on the CPU into
//! premultiplied ARGB8888 surfaces.  Layers, bottom-up:
//!
//! * [`surface`], [`canvas`], [`shadow`] — pixels, clipping, blending,
//!   anti-aliased shapes, scaled blits, cached soft shadows;
//! * [`text`], [`fonts`] — fontdue rasterisation, glyph cache, GPOS kerning,
//!   measuring, ellipsis, wrapping; bundled Inter + JetBrains Mono subsets;
//! * [`theme`] — design tokens (dark minimalism);
//! * [`ui`], [`menu`], [`window`] — retained widget tree with layout, input,
//!   focus and damage tracking; client-side window chrome;
//! * [`proto`], [`session`], [`desktop`] — the window-system protocol, the
//!   session loop and the compositor / window manager;
//! * [`demo`] — the reference desktop used by the PNG mockups and `guidemo`.
//!
//! The `std` feature is for host tools and tests only.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![allow(clippy::too_many_arguments)]

extern crate alloc;

mod blend;
pub mod app;
pub mod canvas;
pub mod color;
pub mod cursor;
pub mod damage;
pub mod demo;
pub mod desktop;
pub mod event;
pub mod fonts;
pub mod geom;
pub mod icons;
pub mod math;
pub mod menu;
pub mod proto;
pub mod session;
pub mod shadow;
pub mod surface;
pub mod text;
pub mod theme;
pub mod ui;
pub mod window;

pub use canvas::{Canvas, Filter};
pub use color::Color;
pub use event::{CursorShape, Event, Key, Modifiers, MouseButton};
pub use geom::{Insets, Point, Rect, Size};
pub use surface::{Pixels, PixelsMut, Surface};
pub use text::TextEngine;
pub use theme::{Theme, DARK};

/// Convert a premultiplied opaque pixel to 0x00RRGGBB for a framebuffer.
#[inline(always)]
pub fn to_xrgb(p: u32) -> u32 { p & 0x00FF_FFFF }
