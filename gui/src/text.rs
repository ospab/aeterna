// SPDX-License-Identifier: AGPL-3.0-only
//! Text: font loading, glyph cache, kerning, measuring, drawing, wrapping.
//!
//! Outlines are parsed and rasterised by `fontdue` (pure Rust, `no_std` +
//! `alloc`).  fontdue only reads the legacy `kern` table, while modern fonts
//! such as Inter keep their kerning in GPOS, so pair kerning is looked up here
//! directly in the GPOS PairAdjustment subtables via `ttf-parser` and cached.
//!
//! Rendering is grayscale (no subpixel/LCD AA): it composites correctly on any
//! background and survives scaling and screenshots.  Glyph coverage goes
//! through a small gamma LUT so light-on-dark text does not look thin.
//! Glyph positions are rounded to whole pixels; the pen advances in floating
//! point so spacing does not drift.

use alloc::vec::Vec;
use core::ops::Range;

use hashbrown::HashMap;

use crate::canvas::Canvas;
use crate::color::Color;
use crate::math;

/// Index of a font registered with [`TextEngine::add_font`].
pub type FontId = usize;

/// Vertical metrics of a font at a pixel size (all in whole pixels).
#[derive(Clone, Copy, Debug, Default)]
pub struct LineMetrics {
    /// Baseline offset from the top of the line box.
    pub ascent: i32,
    pub descent: i32,
    /// Natural line height (ascent + descent + line gap).
    pub height: i32,
}

struct Face {
    font: fontdue::Font,
    face: ttf_parser::Face<'static>,
    upem: f32,
    ascender: f32,
    descender: f32,
    line_gap: f32,
    /// GPOS pair kerning cache: (left << 16 | right) -> design units.
    kern: HashMap<u32, i16>,
    has_gpos: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct GlyphKey {
    font: u16,
    glyph: u16,
    size: u16,
}

struct Glyph {
    xmin: i32,
    /// Offset from the baseline to the top row of the bitmap (positive = up).
    top: i32,
    w: i32,
    h: i32,
    advance: f32,
    data: Vec<u8>,
}

/// Font registry + glyph cache. One per process (or per compositor client).
pub struct TextEngine {
    faces: Vec<Face>,
    cache: HashMap<GlyphKey, Glyph>,
    cache_bytes: usize,
    /// Upper bound for cached bitmap bytes before the cache is flushed.
    pub cache_limit: usize,
    lut: [u8; 256],
    /// Fallback order when a font lacks a character.
    fallback: Vec<FontId>,
}

/// A shaped glyph: which font, which glyph, pen position.
#[derive(Clone, Copy)]
struct Placed {
    font: FontId,
    glyph: u16,
    x: f32,
}

impl TextEngine {
    pub fn new() -> Self {
        let mut t = TextEngine {
            faces: Vec::new(),
            cache: HashMap::new(),
            cache_bytes: 0,
            cache_limit: 2 * 1024 * 1024,
            lut: [0; 256],
            fallback: Vec::new(),
        };
        t.set_gamma(0.80);
        t
    }

    /// Coverage curve: out = in^gamma. Below 1.0 thickens strokes slightly,
    /// which compensates for light text on dark backgrounds.
    pub fn set_gamma(&mut self, gamma: f32) {
        for i in 0..256 {
            let v = math::powf(i as f32 / 255.0, gamma);
            self.lut[i] = (v * 255.0 + 0.5) as u8;
        }
        self.cache.clear();
        self.cache_bytes = 0;
    }

    /// Register a font from static data (embedded or leaked). Fonts added
    /// later are used as fallbacks for missing characters.
    pub fn add_font(&mut self, data: &'static [u8]) -> Result<FontId, &'static str> {
        let settings = fontdue::FontSettings { scale: 40.0, ..fontdue::FontSettings::default() };
        let font = fontdue::Font::from_bytes(data, settings)?;
        let face = ttf_parser::Face::parse(data, 0).map_err(|_| "ttf-parser: bad font")?;
        let upem = face.units_per_em() as f32;
        let (asc, desc, gap) = (face.ascender() as f32, face.descender() as f32, face.line_gap() as f32);
        let has_gpos = face.tables().gpos.is_some();
        self.faces.push(Face { font, face, upem, ascender: asc, descender: desc, line_gap: gap, kern: HashMap::new(), has_gpos });
        let id = self.faces.len() - 1;
        self.fallback.push(id);
        Ok(id)
    }

    pub fn font_count(&self) -> usize { self.faces.len() }

    pub fn metrics(&self, font: FontId, size: u16) -> LineMetrics {
        let f = &self.faces[font];
        let s = size as f32 / f.upem;
        let ascent = math::ceil(f.ascender * s);
        let descent = math::ceil(-f.descender * s);
        let height = math::round((f.ascender - f.descender + f.line_gap) * s).max(ascent + descent);
        LineMetrics { ascent, descent, height }
    }

    /// Cell width of a monospace font (advance of 'M', rounded).
    pub fn mono_advance(&mut self, font: FontId, size: u16) -> i32 {
        let gid = self.faces[font].font.lookup_glyph_index('M');
        math::round(self.glyph(font, gid, size).advance).max(1)
    }

    fn resolve(&self, font: FontId, ch: char) -> (FontId, u16) {
        let gid = self.faces[font].font.lookup_glyph_index(ch);
        if gid != 0 || ch == ' ' { return (font, gid); }
        for &f in &self.fallback {
            if f == font { continue; }
            let g = self.faces[f].font.lookup_glyph_index(ch);
            if g != 0 { return (f, g); }
        }
        (font, 0)
    }

    fn kern_units(&mut self, font: FontId, a: u16, b: u16) -> i16 {
        let f = &mut self.faces[font];
        let key = (a as u32) << 16 | b as u32;
        if let Some(&v) = f.kern.get(&key) { return v; }
        let v = if f.has_gpos { gpos_pair(&f.face, a, b) } else { 0 };
        let v = if v == 0 && !f.has_gpos {
            f.font.horizontal_kern_indexed(a, b, f.upem).map(|k| k as i16).unwrap_or(0)
        } else { v };
        if f.kern.len() > 16384 { f.kern.clear(); }
        f.kern.insert(key, v);
        v
    }

    fn glyph(&mut self, font: FontId, gid: u16, size: u16) -> &Glyph {
        let key = GlyphKey { font: font as u16, glyph: gid, size };
        if !self.cache.contains_key(&key) {
            if self.cache_bytes > self.cache_limit {
                self.cache.clear();
                self.cache_bytes = 0;
            }
            let (m, mut data) = self.faces[font].font.rasterize_indexed(gid, size as f32);
            for v in data.iter_mut() { *v = self.lut[*v as usize]; }
            self.cache_bytes += data.len() + 32;
            let g = Glyph {
                xmin: m.xmin,
                top: m.ymin + m.height as i32,
                w: m.width as i32,
                h: m.height as i32,
                advance: m.advance_width,
                data,
            };
            self.cache.insert(key, g);
        }
        &self.cache[&key]
    }

    /// Lay out one line of text (no wrapping). Returns placed glyphs and the
    /// total advance.
    fn shape(&mut self, font: FontId, size: u16, text: &str, out: &mut Vec<Placed>) -> f32 {
        out.clear();
        let mut pen = 0.0f32;
        let mut prev: Option<(FontId, u16)> = None;
        for ch in text.chars() {
            let ch = if ch == '\t' { ' ' } else { ch };
            if ch.is_control() { continue; }
            let (f, gid) = self.resolve(font, ch);
            if let Some((pf, pg)) = prev {
                if pf == f {
                    let k = self.kern_units(f, pg, gid);
                    if k != 0 { pen += k as f32 * size as f32 / self.faces[f].upem; }
                }
            }
            out.push(Placed { font: f, glyph: gid, x: pen });
            pen += self.glyph(f, gid, size).advance;
            prev = Some((f, gid));
        }
        pen
    }

    /// Width of `text` in pixels.
    pub fn measure(&mut self, font: FontId, size: u16, text: &str) -> i32 {
        let mut v = Vec::new();
        math::ceil(self.shape(font, size, text, &mut v))
    }

    /// Draw a single line with the top of its line box at `y`. Returns the advance.
    pub fn draw(&mut self, c: &mut Canvas, x: i32, y: i32, font: FontId, size: u16, color: Color, text: &str) -> i32 {
        let mut placed = Vec::new();
        let adv = self.shape(font, size, text, &mut placed);
        let base = y + self.metrics(font, size).ascent;
        // Quick reject against the clip.
        let clip = c.clip();
        let lm = self.metrics(font, size);
        if base + lm.descent + 2 < clip.y || y - 2 > clip.bottom() || x > clip.right() || x + math::ceil(adv) + 2 < clip.x {
            return math::ceil(adv);
        }
        for p in placed.iter() {
            let gx = x + math::round(p.x);
            let g = self.glyph(p.font, p.glyph, size);
            if g.w == 0 || g.h == 0 { continue; }
            c.draw_mask(gx + g.xmin, base - g.top, &g.data, g.w, g.h, color);
        }
        math::ceil(adv)
    }

    /// Draw on a fixed character grid (terminal). Returns columns drawn.
    pub fn draw_mono(&mut self, c: &mut Canvas, x: i32, y: i32, font: FontId, size: u16, color: Color, text: &str) -> i32 {
        let cell = self.mono_advance(font, size);
        let base = y + self.metrics(font, size).ascent;
        let mut col = 0;
        for ch in text.chars() {
            if ch != ' ' && !ch.is_control() {
                let (f, gid) = self.resolve(font, ch);
                let g = self.glyph(f, gid, size);
                if g.w > 0 && g.h > 0 {
                    // Centre glyphs from fallback fonts in the cell.
                    let off = if f == font { 0 } else { (cell - math::round(g.advance)) / 2 };
                    c.draw_mask(x + col * cell + off + g.xmin, base - g.top, &g.data, g.w, g.h, color);
                }
            }
            col += 1;
        }
        col
    }

    /// Longest prefix (byte length) of `text` that fits in `max_w` together
    /// with a trailing ellipsis. Returns (prefix_len, truncated).
    pub fn ellipsize(&mut self, font: FontId, size: u16, text: &str, max_w: i32) -> (usize, bool) {
        if self.measure(font, size, text) <= max_w { return (text.len(), false); }
        let ell = self.measure(font, size, "\u{2026}");
        let stops = self.caret_stops(font, size, text);
        let mut end = 0;
        for (i, (bi, ch)) in text.char_indices().enumerate() {
            if stops[i + 1] + ell <= max_w { end = bi + ch.len_utf8(); } else { break; }
        }
        (end, true)
    }

    /// Draw `text`, truncated with "…" if wider than `max_w`.
    pub fn draw_ellipsis(&mut self, c: &mut Canvas, x: i32, y: i32, max_w: i32, font: FontId, size: u16, color: Color, text: &str) -> i32 {
        let (n, cut) = self.ellipsize(font, size, text, max_w);
        if !cut { return self.draw(c, x, y, font, size, color, text); }
        let w = self.draw(c, x, y, font, size, color, text[..n].trim_end());
        w + self.draw(c, x + w, y, font, size, color, "\u{2026}")
    }

    /// X offset of every caret position (one per char boundary, `chars + 1` entries).
    pub fn caret_stops(&mut self, font: FontId, size: u16, text: &str) -> Vec<i32> {
        let mut placed = Vec::new();
        let total = self.shape(font, size, text, &mut placed);
        let mut stops = Vec::with_capacity(placed.len() + 1);
        // shape() skips control chars; keep one stop per char anyway.
        let mut it = placed.iter();
        for ch in text.chars() {
            if ch.is_control() && ch != '\t' {
                stops.push(stops.last().copied().unwrap_or(0));
                continue;
            }
            stops.push(it.next().map_or(math::round(total), |p| math::round(p.x)));
        }
        stops.push(math::round(total));
        stops
    }

    /// Char index nearest to `x` (for mouse caret placement).
    pub fn hit_index(&mut self, font: FontId, size: u16, text: &str, x: i32) -> usize {
        let stops = self.caret_stops(font, size, text);
        let mut best = 0;
        let mut bd = i32::MAX;
        for (i, &s) in stops.iter().enumerate() {
            let d = (s - x).abs();
            if d < bd { bd = d; best = i; }
        }
        best
    }

    /// Greedy word wrap. Returns byte ranges of lines (without the newline);
    /// words longer than a line are broken between characters.
    pub fn wrap(&mut self, font: FontId, size: u16, text: &str, max_w: i32) -> Vec<Range<usize>> {
        let mut lines = Vec::new();
        for para in split_inclusive_ranges(text) {
            let p = &text[para.clone()];
            if p.is_empty() { lines.push(para.start..para.start); continue; }
            let mut start = 0usize; // within p
            while start < p.len() {
                let rest = &p[start..];
                if self.measure(font, size, rest) <= max_w {
                    lines.push(para.start + start..para.start + p.len());
                    break;
                }
                // Find the last space that keeps the line within max_w.
                let stops = self.caret_stops(font, size, rest);
                let mut fit_end = 0usize; // byte end of fitting chars
                let mut last_space: Option<usize> = None;
                for (i, (bi, ch)) in rest.char_indices().enumerate() {
                    if stops[i + 1] > max_w { break; }
                    fit_end = bi + ch.len_utf8();
                    if ch == ' ' { last_space = Some(bi); }
                }
                let (end, next) = match last_space {
                    Some(sp) if sp > 0 => (sp, sp + 1),
                    _ => {
                        let e = if fit_end == 0 { rest.chars().next().map_or(1, |c| c.len_utf8()) } else { fit_end };
                        (e, e)
                    }
                };
                lines.push(para.start + start..para.start + start + end);
                start += next;
                while p[start..].starts_with(' ') { start += 1; }
            }
        }
        lines
    }
}

impl Default for TextEngine {
    fn default() -> Self { Self::new() }
}

/// Byte ranges of the lines of `text` split at '\n' (newline excluded).
fn split_inclusive_ranges(text: &str) -> Vec<Range<usize>> {
    let mut v = Vec::new();
    let mut s = 0;
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' { v.push(s..i); s = i + 1; }
    }
    v.push(s..text.len());
    v
}

/// Horizontal pair adjustment (x_advance of the first glyph) from GPOS
/// PairAdjustment subtables, in design units.
fn gpos_pair(face: &ttf_parser::Face<'static>, a: u16, b: u16) -> i16 {
    use ttf_parser::gpos::{PairAdjustment, PositioningSubtable};
    use ttf_parser::GlyphId;
    let gpos = match face.tables().gpos { Some(g) => g, None => return 0 };
    let (ga, gb) = (GlyphId(a), GlyphId(b));
    for lookup in gpos.lookups {
        for sub in lookup.subtables.into_iter::<PositioningSubtable>() {
            if let PositioningSubtable::Pair(pair) = sub {
                match pair {
                    PairAdjustment::Format1 { coverage, sets } => {
                        if let Some(idx) = coverage.get(ga) {
                            if let Some(set) = sets.get(idx) {
                                if let Some((v1, _)) = set.get(gb) {
                                    return v1.x_advance;
                                }
                            }
                        }
                    }
                    PairAdjustment::Format2 { coverage, classes, matrix } => {
                        if coverage.get(ga).is_some() {
                            let c1 = classes.0.get(ga);
                            let c2 = classes.1.get(gb);
                            if let Some((v1, _)) = matrix.get((c1, c2)) {
                                if v1.x_advance != 0 { return v1.x_advance; }
                            }
                        }
                    }
                }
            }
        }
    }
    0
}
