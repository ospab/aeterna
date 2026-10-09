/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

axon/regex — small regular-expression engine for grep, awk and [[ =~ ]].

Syntax (POSIX ERE subset; with `basic` = true, GNU BRE spelling is used:
\( \) \| \+ \? \{ \} are operators and the bare characters are literals):
  .  [abc] [^a-z] [[:digit:]] etc.   ^ $   * + ? {n} {n,} {n,m}
  ( ) grouping,  |  alternation,  \d \w \s \D \W \S \b \B,  \t \n, \x escapes

Matching uses a Pike VM (Thompson NFA simulation): no recursion on the
input, so long lines cannot overflow the small kernel stack, and no
exponential blow-up.  find() returns the leftmost-longest match.
*/

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Named { Alpha, Digit, Alnum, Space, Upper, Lower, Punct, Xdigit, Word }

#[derive(Clone)]
struct Class {
    ranges: Vec<(char, char)>,
    named: Vec<(Named, bool)>, // (class, negated)
    neg: bool,
}

fn named_match(n: Named, c: char) -> bool {
    match n {
        Named::Alpha => c.is_alphabetic(),
        Named::Digit => c.is_ascii_digit(),
        Named::Alnum => c.is_alphanumeric(),
        Named::Space => c.is_whitespace(),
        Named::Upper => c.is_uppercase(),
        Named::Lower => c.is_lowercase(),
        Named::Punct => c.is_ascii_punctuation(),
        Named::Xdigit => c.is_ascii_hexdigit(),
        Named::Word => c.is_alphanumeric() || c == '_',
    }
}

impl Class {
    fn matches(&self, c: char, icase: bool) -> bool {
        let test = |ch: char| {
            self.ranges.iter().any(|(lo, hi)| *lo <= ch && ch <= *hi)
                || self.named.iter().any(|(n, neg)| named_match(*n, ch) != *neg)
        };
        let mut m = test(c);
        if !m && icase {
            m = test(c.to_ascii_lowercase()) || test(c.to_ascii_uppercase());
        }
        m != self.neg
    }
}

enum Ast {
    Empty,
    Char(char),
    Any,
    Class(usize),
    Bol,
    Eol,
    WordB(bool),
    Concat(Vec<Ast>),
    Alt(Vec<Ast>),
    Repeat(Box<Ast>, u32, Option<u32>),
}

#[derive(Clone, Copy)]
enum Inst {
    Char(char),
    Any,
    Class(usize),
    Split(usize, usize),
    Jmp(usize),
    Bol,
    Eol,
    WordB(bool),
    Match,
}

pub struct Regex {
    prog: Vec<Inst>,
    classes: Vec<Class>,
    icase: bool,
    anchored: bool,
}

struct Parser<'a> {
    c: &'a [char],
    i: usize,
    basic: bool,
    icase: bool,
    classes: Vec<Class>,
}

const MAX_REPEAT: u32 = 255;

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<char> { self.c.get(self.i).copied() }

    /// Is the next thing an operator token `op`? (handles BRE escaping)
    fn at_op(&self, op: char) -> bool {
        if self.basic {
            self.peek() == Some('\\') && self.c.get(self.i + 1).copied() == Some(op)
        } else {
            self.peek() == Some(op)
        }
    }

    fn eat_op(&mut self, op: char) -> bool {
        if self.at_op(op) {
            self.i += if self.basic { 2 } else { 1 };
            true
        } else {
            false
        }
    }

    fn alt(&mut self) -> Result<Ast, String> {
        let mut branches = alloc::vec![self.concat()?];
        while self.eat_op('|') {
            branches.push(self.concat()?);
        }
        Ok(if branches.len() == 1 { branches.pop().unwrap() } else { Ast::Alt(branches) })
    }

    fn concat(&mut self) -> Result<Ast, String> {
        let mut items = Vec::new();
        let start = self.i;
        while self.i < self.c.len() {
            if self.at_op('|') || self.at_op(')') { break; }
            let at_start = self.i == start;
            let atom = self.atom(at_start)?;
            let atom = self.quantifiers(atom)?;
            items.push(atom);
        }
        Ok(match items.len() {
            0 => Ast::Empty,
            1 => items.pop().unwrap(),
            _ => Ast::Concat(items),
        })
    }

    fn quantifiers(&mut self, mut atom: Ast) -> Result<Ast, String> {
        loop {
            if self.peek() == Some('*') {
                self.i += 1;
                atom = Ast::Repeat(Box::new(atom), 0, None);
            } else if self.eat_op('+') {
                atom = Ast::Repeat(Box::new(atom), 1, None);
            } else if self.eat_op('?') {
                atom = Ast::Repeat(Box::new(atom), 0, Some(1));
            } else if self.at_op('{') {
                let save = self.i;
                self.eat_op('{');
                let mut num = String::new();
                while let Some(d) = self.peek() { if d.is_ascii_digit() || d == ',' { num.push(d); self.i += 1; } else { break; } }
                if !self.eat_op('}') {
                    self.i = save;
                    return Ok(atom);
                }
                let (lo, hi) = match num.find(',') {
                    None => { let n = num.parse::<u32>().map_err(|_| String::from("bad {n}"))?; (n, Some(n)) }
                    Some(p) => {
                        let lo = if p == 0 { 0 } else { num[..p].parse::<u32>().map_err(|_| String::from("bad {n,m}"))? };
                        let hi = if p + 1 == num.len() { None } else { Some(num[p + 1..].parse::<u32>().map_err(|_| String::from("bad {n,m}"))?) };
                        (lo, hi)
                    }
                };
                if lo > MAX_REPEAT || hi.map(|h| h > MAX_REPEAT || h < lo).unwrap_or(false) {
                    return Err(String::from("invalid repetition count"));
                }
                atom = Ast::Repeat(Box::new(atom), lo, hi);
            } else {
                return Ok(atom);
            }
        }
    }

    fn lit(&self, c: char) -> Ast {
        Ast::Char(if self.icase { c.to_ascii_lowercase() } else { c })
    }

    fn atom(&mut self, at_start: bool) -> Result<Ast, String> {
        if self.eat_op('(') {
            let inner = self.alt()?;
            if !self.eat_op(')') { return Err(String::from("unmatched (")); }
            return Ok(inner);
        }
        let c = self.peek().unwrap();
        self.i += 1;
        match c {
            '.' => Ok(Ast::Any),
            '^' => {
                if at_start { Ok(Ast::Bol) } else { Ok(self.lit('^')) }
            }
            '$' => {
                let at_end = self.i >= self.c.len() || self.at_op('|') || self.at_op(')');
                if at_end { Ok(Ast::Eol) } else { Ok(self.lit('$')) }
            }
            '*' if at_start => Ok(self.lit('*')),
            '[' => self.class(),
            '\\' => {
                let e = match self.peek() { Some(e) => e, None => return Ok(self.lit('\\')) };
                self.i += 1;
                let mk = |p: &mut Self, n: Named, neg: bool| {
                    p.classes.push(Class { ranges: Vec::new(), named: alloc::vec![(n, neg)], neg: false });
                    Ast::Class(p.classes.len() - 1)
                };
                Ok(match e {
                    'd' => mk(self, Named::Digit, false),
                    'D' => mk(self, Named::Digit, true),
                    'w' => mk(self, Named::Word, false),
                    'W' => mk(self, Named::Word, true),
                    's' => mk(self, Named::Space, false),
                    'S' => mk(self, Named::Space, true),
                    'b' => Ast::WordB(true),
                    'B' => Ast::WordB(false),
                    't' => Ast::Char('\t'),
                    'n' => Ast::Char('\n'),
                    other => self.lit(other),
                })
            }
            other => Ok(self.lit(other)),
        }
    }

    fn class(&mut self) -> Result<Ast, String> {
        let mut cls = Class { ranges: Vec::new(), named: Vec::new(), neg: false };
        if self.peek() == Some('^') { cls.neg = true; self.i += 1; }
        let mut first = true;
        loop {
            let c = match self.peek() { Some(c) => c, None => return Err(String::from("unmatched [")) };
            if c == ']' && !first { self.i += 1; break; }
            first = false;
            if c == '[' && self.c.get(self.i + 1).copied() == Some(':') {
                let rest: String = self.c[self.i + 2..].iter().collect();
                if let Some(end) = rest.find(":]") {
                    let name = &rest[..end];
                    let n = match name {
                        "alpha" => Named::Alpha, "digit" => Named::Digit, "alnum" => Named::Alnum,
                        "space" | "blank" => Named::Space, "upper" => Named::Upper, "lower" => Named::Lower,
                        "punct" => Named::Punct, "xdigit" => Named::Xdigit,
                        _ => return Err(alloc::format!("unknown class [:{}:]", name)),
                    };
                    cls.named.push((n, false));
                    self.i += 2 + name.chars().count() + 2;
                    continue;
                }
            }
            let lo = if c == '\\' && self.i + 1 < self.c.len() { self.i += 1; self.c[self.i] } else { c };
            self.i += 1;
            if self.peek() == Some('-') && self.c.get(self.i + 1).map(|&x| x != ']').unwrap_or(false) {
                let hi = self.c[self.i + 1];
                self.i += 2;
                cls.ranges.push((lo, hi));
            } else {
                cls.ranges.push((lo, lo));
            }
        }
        self.classes.push(cls);
        Ok(Ast::Class(self.classes.len() - 1))
    }
}

struct Compiler {
    prog: Vec<Inst>,
}

impl Compiler {
    fn emit(&mut self, i: Inst) -> usize {
        self.prog.push(i);
        self.prog.len() - 1
    }

    fn comp(&mut self, a: &Ast) -> Result<(), String> {
        if self.prog.len() > 20000 {
            return Err(String::from("regular expression too large"));
        }
        match a {
            Ast::Empty => {}
            Ast::Char(c) => { self.emit(Inst::Char(*c)); }
            Ast::Any => { self.emit(Inst::Any); }
            Ast::Class(i) => { self.emit(Inst::Class(*i)); }
            Ast::Bol => { self.emit(Inst::Bol); }
            Ast::Eol => { self.emit(Inst::Eol); }
            Ast::WordB(b) => { self.emit(Inst::WordB(*b)); }
            Ast::Concat(v) => { for x in v { self.comp(x)?; } }
            Ast::Alt(v) => {
                let mut jumps = Vec::new();
                for (k, x) in v.iter().enumerate() {
                    if k + 1 < v.len() {
                        let split = self.emit(Inst::Split(0, 0));
                        self.comp(x)?;
                        jumps.push(self.emit(Inst::Jmp(0)));
                        let next = self.prog.len();
                        self.prog[split] = Inst::Split(split + 1, next);
                    } else {
                        self.comp(x)?;
                    }
                }
                let end = self.prog.len();
                for j in jumps { self.prog[j] = Inst::Jmp(end); }
            }
            Ast::Repeat(x, min, max) => {
                for _ in 0..*min { self.comp(x)?; }
                match max {
                    None => {
                        let l = self.emit(Inst::Split(0, 0));
                        self.comp(x)?;
                        self.emit(Inst::Jmp(l));
                        let end = self.prog.len();
                        self.prog[l] = Inst::Split(l + 1, end);
                    }
                    Some(m) => {
                        let mut splits = Vec::new();
                        for _ in *min..*m {
                            splits.push(self.emit(Inst::Split(0, 0)));
                            self.comp(x)?;
                        }
                        let end = self.prog.len();
                        for s in splits { self.prog[s] = Inst::Split(s + 1, end); }
                    }
                }
            }
        }
        Ok(())
    }
}

fn is_word(c: Option<char>) -> bool {
    c.map(|c| c.is_alphanumeric() || c == '_').unwrap_or(false)
}

impl Regex {
    pub fn new(pat: &str) -> Result<Regex, String> { Self::build(pat, false, false) }

    pub fn build(pat: &str, basic: bool, icase: bool) -> Result<Regex, String> {
        let chars: Vec<char> = pat.chars().collect();
        let mut p = Parser { c: &chars, i: 0, basic, icase, classes: Vec::new() };
        let ast = p.alt()?;
        if p.i < chars.len() {
            return Err(String::from("unmatched )"));
        }
        let anchored = matches!(&ast, Ast::Bol) || matches!(&ast, Ast::Concat(v) if matches!(v.first(), Some(Ast::Bol)));
        let mut c = Compiler { prog: Vec::new() };
        c.comp(&ast)?;
        c.emit(Inst::Match);
        Ok(Regex { prog: c.prog, classes: p.classes, icase, anchored })
    }

    fn add(&self, list: &mut Vec<usize>, mark: &mut [usize], gen: usize, pc: usize, t: &[char], pos: usize) {
        let mut stack = alloc::vec![pc];
        while let Some(pc) = stack.pop() {
            if mark[pc] == gen { continue; }
            mark[pc] = gen;
            match self.prog[pc] {
                Inst::Jmp(x) => stack.push(x),
                Inst::Split(a, b) => { stack.push(b); stack.push(a); }
                Inst::Bol => if pos == 0 { stack.push(pc + 1); },
                Inst::Eol => if pos == t.len() { stack.push(pc + 1); },
                Inst::WordB(want) => {
                    let before = if pos > 0 { Some(t[pos - 1]) } else { None };
                    let at_b = is_word(before) != is_word(t.get(pos).copied());
                    if at_b == want { stack.push(pc + 1); }
                }
                _ => list.push(pc),
            }
        }
    }

    /// Longest match starting exactly at `start`; returns its end.
    fn match_at(&self, t: &[char], start: usize, mark: &mut [usize], gen: &mut usize) -> Option<usize> {
        let mut clist = Vec::new();
        let mut nlist = Vec::new();
        *gen += 1;
        self.add(&mut clist, mark, *gen, 0, t, start);
        let mut last = None;
        let mut pos = start;
        loop {
            if clist.iter().any(|&pc| matches!(self.prog[pc], Inst::Match)) {
                last = Some(pos);
            }
            if pos >= t.len() || clist.is_empty() { break; }
            let ch = if self.icase { t[pos].to_ascii_lowercase() } else { t[pos] };
            *gen += 1;
            nlist.clear();
            for &pc in &clist {
                let ok = match self.prog[pc] {
                    Inst::Char(c) => c == ch,
                    Inst::Any => true,
                    Inst::Class(i) => self.classes[i].matches(t[pos], self.icase),
                    _ => false,
                };
                if ok {
                    self.add(&mut nlist, mark, *gen, pc + 1, t, pos + 1);
                }
            }
            core::mem::swap(&mut clist, &mut nlist);
            pos += 1;
        }
        last
    }

    /// Leftmost-longest match as char indices (start, end).
    pub fn find_chars(&self, t: &[char]) -> Option<(usize, usize)> {
        let mut mark = alloc::vec![0usize; self.prog.len()];
        let mut gen = 0usize;
        let last_start = if self.anchored { 0 } else { t.len() };
        for s in 0..=last_start {
            if let Some(e) = self.match_at(t, s, &mut mark, &mut gen) {
                return Some((s, e));
            }
        }
        None
    }

    /// Leftmost-longest match as byte offsets into `s`.
    pub fn find(&self, s: &str) -> Option<(usize, usize)> {
        let chars: Vec<char> = s.chars().collect();
        let (a, b) = self.find_chars(&chars)?;
        let off = |n: usize| s.char_indices().nth(n).map(|(i, _)| i).unwrap_or(s.len());
        Some((off(a), off(b)))
    }

    pub fn is_match(&self, s: &str) -> bool {
        let chars: Vec<char> = s.chars().collect();
        self.find_chars(&chars).is_some()
    }
}
