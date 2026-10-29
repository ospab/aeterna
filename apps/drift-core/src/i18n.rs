// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! Languages and the string tables. Fixed UI strings are looked up by their English text; strings
//! built from a template ("Arrived at {}") are matched against the table entries that contain `{}`.
use crate::game::Game;
use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    En,
    Ru,
}

impl Lang {
    pub fn code(self) -> u8 {
        match self {
            Lang::En => 0,
            Lang::Ru => 1,
        }
    }
    pub fn from_code(c: u8) -> Lang {
        if c == 1 {
            Lang::Ru
        } else {
            Lang::En
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Ru => "Русский",
        }
    }
}

struct Pat {
    ru: &'static str,
    lits: Vec<&'static str>,
    weight: usize,
}

/// Translation table for one language.
pub struct Tr {
    exact: BTreeMap<&'static str, &'static str>,
    pats: Vec<Pat>,
}

impl Tr {
    pub fn russian() -> Tr {
        Tr::build(crate::i18n_ru::RU)
    }

    fn build(table: &'static [(&'static str, &'static str)]) -> Tr {
        let mut exact = BTreeMap::new();
        let mut pats = Vec::new();
        for (en, ru) in table {
            exact.insert(*en, *ru);
            if en.contains("{}") {
                let lits: Vec<&'static str> = en.split("{}").collect();
                let weight = lits.iter().map(|l| l.len()).sum();
                pats.push(Pat { ru, lits, weight });
            }
        }
        pats.sort_by(|a, b| b.weight.cmp(&a.weight));
        Tr { exact, pats }
    }

    pub fn get(&self, s: &str) -> Option<&'static str> {
        self.exact.get(s).copied()
    }

    /// Translate `s`: exact entry, else a template entry, else unchanged.
    pub fn translate<'a>(&self, s: &'a str) -> Cow<'a, str> {
        if s.is_empty() {
            return Cow::Borrowed(s);
        }
        if let Some(t) = self.exact.get(s) {
            return Cow::Borrowed(t);
        }
        if !s.bytes().any(|b| b.is_ascii_alphabetic()) {
            return Cow::Borrowed(s);
        }
        for p in &self.pats {
            if let Some(args) = Self::matches(p, s) {
                let mut out = String::new();
                let mut it = args.into_iter();
                for (i, piece) in p.ru.split("{}").enumerate() {
                    if i > 0 {
                        if let Some(a) = it.next() {
                            if a.len() < s.len() {
                                out.push_str(&self.translate(a));
                            } else {
                                out.push_str(a);
                            }
                        }
                    }
                    out.push_str(piece);
                }
                return Cow::Owned(out);
            }
        }
        Cow::Borrowed(s)
    }

    fn matches<'a>(p: &Pat, s: &'a str) -> Option<Vec<&'a str>> {
        let n = p.lits.len();
        let first = p.lits[0];
        let last = p.lits[n - 1];
        if s.len() < first.len() + last.len() || !s.starts_with(first) || !s.ends_with(last) {
            return None;
        }
        let end = s.len() - last.len();
        let mut pos = first.len();
        let mut args = Vec::new();
        for i in 1..n - 1 {
            let lit = p.lits[i];
            let rest = &s[pos..end];
            let at = if lit.is_empty() { 0 } else { rest.find(lit)? };
            args.push(&rest[..at]);
            pos += at + lit.len();
        }
        args.push(&s[pos..end]);
        if args.iter().any(|a| a.is_empty()) {
            return None;
        }
        Some(args)
    }
}

impl Game {
    pub fn lang(&self) -> Lang {
        self.settings.lang
    }
    pub fn is_ru(&self) -> bool {
        self.settings.lang == Lang::Ru
    }
    /// The table to hand to the canvas, if the language needs one.
    pub fn tr_for_canvas(&self) -> Option<Rc<Tr>> {
        if self.is_ru() {
            Some(self.tr.clone())
        } else {
            None
        }
    }
    /// Translate a fixed English string; unknown strings come back unchanged.
    pub fn t(&self, s: &'static str) -> &'static str {
        if self.is_ru() {
            if let Some(t) = self.tr.get(s) {
                return t;
            }
        }
        s
    }
    /// Translate a built string (templates are matched).
    pub fn td(&self, s: &str) -> String {
        if self.is_ru() {
            String::from(self.tr.translate(s))
        } else {
            String::from(s)
        }
    }

    pub fn chapter_def(&self, n: u8) -> crate::story::ChapterDef {
        if self.is_ru() {
            crate::i18n_text::chapter_ru(n)
        } else {
            crate::story::chapter(n)
        }
    }
    pub fn intro_page(&self, i: usize) -> &'static str {
        if self.is_ru() {
            crate::i18n_text::INTRO_RU[i]
        } else {
            crate::story::INTRO[i]
        }
    }
    pub fn ending_page(&self, i: usize) -> &'static str {
        if self.is_ru() {
            crate::i18n_text::ENDING_RU[i]
        } else {
            crate::story::ENDING[i]
        }
    }
    pub fn credits_lines(&self) -> &'static [(&'static str, &'static str)] {
        if self.is_ru() {
            &crate::i18n_text::CREDITS_RU
        } else {
            &crate::story::CREDITS
        }
    }
    pub fn step_text(&self, i: usize) -> (&'static str, &'static str, &'static str) {
        if self.is_ru() {
            crate::i18n_text::STEPS_RU[i]
        } else {
            crate::tutorial::STEPS[i]
        }
    }
}
