// SPDX-License-Identifier: AGPL-3.0-only
//! Bundled fonts (SIL Open Font License 1.1, see gui/fonts/OFL-*.txt).
//!
//! Subsets (Latin, Latin-1, Latin Extended-A, Cyrillic, punctuation, a few
//! symbols) rebuilt by gui/fonts/subset.py:
//!   Inter 4 (rsms/inter): Regular 400 + SemiBold 600, opsz 14 — UI text;
//!   JetBrains Mono 400 — terminal and code.

use crate::text::TextEngine;

#[cfg(feature = "embedded-fonts")]
pub static INTER_REGULAR: &[u8] = include_bytes!("../fonts/Inter-Regular.ttf");
#[cfg(feature = "embedded-fonts")]
pub static INTER_SEMIBOLD: &[u8] = include_bytes!("../fonts/Inter-SemiBold.ttf");
#[cfg(feature = "embedded-fonts")]
pub static JETBRAINS_MONO: &[u8] = include_bytes!("../fonts/JetBrainsMono-Regular.ttf");

/// A text engine with the standard fonts registered as
/// [`crate::theme::UI`], [`crate::theme::UI_SEMIBOLD`], [`crate::theme::MONO`].
#[cfg(feature = "embedded-fonts")]
pub fn default_text_engine() -> TextEngine {
    let mut t = TextEngine::new();
    t.add_font(INTER_REGULAR).expect("Inter Regular");
    t.add_font(INTER_SEMIBOLD).expect("Inter SemiBold");
    t.add_font(JETBRAINS_MONO).expect("JetBrains Mono");
    t
}
