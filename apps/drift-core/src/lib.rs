// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! drift-core: platform-independent core of the drift space game.
#![no_std]
extern crate alloc;
#[cfg(test)]
extern crate std;
pub mod audio;
pub mod commander;
pub mod econ;
pub mod font_cyr;
pub mod galaxy;
pub mod game;
pub mod gfx;
pub mod i18n;
pub mod i18n_ru;
pub mod i18n_text;
pub mod math;
pub mod menus;
pub mod models;
pub mod raster;
pub mod screens;
pub mod sim;
pub mod space;
pub mod story;
pub mod tutorial;
pub mod view;
