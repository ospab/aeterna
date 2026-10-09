/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

plum/parse — lexer and parser for the plum shell language (a POSIX sh
subset).

Supported grammar:
  list      := and_or ((';' | '&' | NEWLINE) and_or)*
  and_or    := pipeline (('&&' | '||') pipeline)*
  pipeline  := ['!'] command ('|' command)*
  command   := simple | compound redir* | funcdef
  compound  := if | for | while | until | case | '{' list '}' | '(' list ')'
               | '((' arith '))'
  funcdef   := NAME '(' ')' command | 'function' NAME command
  redir     := '>' w | '>>' w | '<' w | '2>' w | '2>>' w | '2>&1' | '>&2'
               | '&>' w

Words keep their quotes; quote removal and expansion happen at run time
(see exec.rs), so `"$x"` and `'$x'` behave as in sh.
*/

extern crate alloc;

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

// ─── AST ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RedirKind {
    Out,       // >
    Append,    // >>
    In,        // <
    ErrOut,    // 2>
    ErrAppend, // 2>>
    ErrToOut,  // 2>&1
    OutToErr,  // >&2  1>&2
    BothOut,   // &>
}

#[derive(Clone)]
pub struct Redir {
    pub kind: RedirKind,
    pub target: String,
}

pub struct CaseArm {
    pub patterns: Vec<String>,
    pub body: Node,
}

pub enum Node {
    Simple { words: Vec<String>, redirs: Vec<Redir> },
    Pipeline { cmds: Vec<Node>, negate: bool },
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Seq(Vec<Node>),
    Background(Box<Node>),
    If { branches: Vec<(Node, Node)>, else_body: Option<Box<Node>> },
    For { var: String, items: Option<Vec<String>>, body: Box<Node> },
    While { cond: Box<Node>, body: Box<Node>, until: bool },
    Case { word: String, arms: Vec<CaseArm> },
    Group { body: Box<Node>, subshell: bool },
    FuncDef { name: String, body: Rc<Node> },
    Arith(String),
    Redirected { node: Box<Node>, redirs: Vec<Redir> },
}

// ─── Lexer ──────────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq, Debug)]
enum Tok {
    Word(String),
    Op(&'static str),
    Newline,
    Eof,
}

fn is_op_char(c: u8) -> bool {
    matches!(c, b'|' | b'&' | b';' | b'(' | b')' | b'<' | b'>')
}

/// Scan from `i` (just after an opening `(`) to the matching `)`, honouring
/// quotes and nesting.  Returns the index just after the closing paren.
fn scan_parens(b: &[u8], mut i: usize, mut depth: usize) -> Result<usize, String> {
    while i < b.len() {
        match b[i] {
            b'\\' => { i += 2; continue; }
            b'\'' => {
                i += 1;
                while i < b.len() && b[i] != b'\'' { i += 1; }
                if i >= b.len() { return Err(String::from("unterminated quote")); }
            }
            b'"' => {
                i = scan_dquote(b, i + 1)?;
                continue;
            }
            b'`' => {
                i += 1;
                while i < b.len() && b[i] != b'`' {
                    if b[i] == b'\\' { i += 1; }
                    i += 1;
                }
                if i >= b.len() { return Err(String::from("unterminated `")); }
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 { return Ok(i + 1); }
            }
            _ => {}
        }
        i += 1;
    }
    Err(String::from("unterminated $( or ("))
}

/// Scan a double-quoted string starting just after the opening quote.
/// Returns index just after the closing quote.
fn scan_dquote(b: &[u8], mut i: usize) -> Result<usize, String> {
    while i < b.len() {
        match b[i] {
            b'\\' => { i += 2; continue; }
            b'"' => return Ok(i + 1),
            b'$' if i + 1 < b.len() && b[i + 1] == b'(' => {
                i = scan_parens(b, i + 2, 1)?;
                continue;
            }
            b'`' => {
                i += 1;
                while i < b.len() && b[i] != b'`' {
                    if b[i] == b'\\' { i += 1; }
                    i += 1;
                }
                if i >= b.len() { return Err(String::from("unterminated `")); }
            }
            _ => {}
        }
        i += 1;
    }
    Err(String::from("unterminated double quote"))
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        // whitespace
        if c == b' ' || c == b'\t' || c == b'\r' {
            i += 1;
            continue;
        }
        // line continuation
        if c == b'\\' && i + 1 < b.len() && b[i + 1] == b'\n' {
            i += 2;
            continue;
        }
        if c == b'\n' {
            toks.push(Tok::Newline);
            i += 1;
            continue;
        }
        // comment
        if c == b'#' {
            while i < b.len() && b[i] != b'\n' { i += 1; }
            continue;
        }
        // arithmetic command (( ... )) at token start
        if c == b'(' && i + 1 < b.len() && b[i + 1] == b'(' {
            let start = i;
            let end = scan_parens(b, i + 1, 1)?; // index after inner ')'
            // expect a second ')' right after
            if end < b.len() && b[end] == b')' {
                toks.push(Tok::Word(String::from(&src[start..end + 1])));
                i = end + 1;
                continue;
            }
            // not arithmetic: treat as two '(' operators
        }
        // 2> / 2>> / 2>&1 (only when '2' is a whole token)
        if c == b'2' && i + 1 < b.len() && b[i + 1] == b'>' {
            if i + 3 < b.len() && &b[i + 1..i + 4] == b">&1" {
                toks.push(Tok::Op("2>&1"));
                i += 4;
                continue;
            }
            if i + 2 < b.len() && b[i + 2] == b'>' {
                toks.push(Tok::Op("2>>"));
                i += 3;
                continue;
            }
            toks.push(Tok::Op("2>"));
            i += 2;
            continue;
        }
        if c == b'1' && i + 3 < b.len() && &b[i + 1..i + 4] == b">&2" {
            toks.push(Tok::Op(">&2"));
            i += 4;
            continue;
        }
        if is_op_char(c) {
            let two = if i + 1 < b.len() { &src[i..i + 2] } else { "" };
            let three = if i + 2 < b.len() { &src[i..i + 3] } else { "" };
            let op: &'static str = if three == ">&2" {
                ">&2"
            } else {
                match two {
                    "||" => "||",
                    "&&" => "&&",
                    ";;" => ";;",
                    ">>" => ">>",
                    "&>" => "&>",
                    "<<" => return Err(String::from("here-documents (<<) are not supported")),
                    _ => match c {
                        b'|' => "|",
                        b'&' => "&",
                        b';' => ";",
                        b'(' => "(",
                        b')' => ")",
                        b'<' => "<",
                        _ => ">",
                    },
                }
            };
            toks.push(Tok::Op(op));
            i += op.len();
            continue;
        }
        // word
        let start = i;
        while i < b.len() {
            let ch = b[i];
            if ch == b' ' || ch == b'\t' || ch == b'\n' || ch == b'\r' || is_op_char(ch) {
                break;
            }
            match ch {
                b'\\' => {
                    i += 2;
                    continue;
                }
                b'\'' => {
                    i += 1;
                    while i < b.len() && b[i] != b'\'' { i += 1; }
                    if i >= b.len() { return Err(String::from("unterminated single quote")); }
                    i += 1;
                    continue;
                }
                b'"' => {
                    i = scan_dquote(b, i + 1)?;
                    continue;
                }
                b'`' => {
                    i += 1;
                    while i < b.len() && b[i] != b'`' {
                        if b[i] == b'\\' { i += 1; }
                        i += 1;
                    }
                    if i >= b.len() { return Err(String::from("unterminated `")); }
                    i += 1;
                    continue;
                }
                b'$' => {
                    if i + 1 < b.len() && b[i + 1] == b'(' {
                        i = scan_parens(b, i + 2, 1)?;
                        continue;
                    }
                    if i + 1 < b.len() && b[i + 1] == b'{' {
                        i += 2;
                        while i < b.len() && b[i] != b'}' { i += 1; }
                        if i >= b.len() { return Err(String::from("unterminated ${")); }
                        i += 1;
                        continue;
                    }
                    i += 1;
                    continue;
                }
                _ => { i += 1; }
            }
        }
        let end = if i > b.len() { b.len() } else { i };
        toks.push(Tok::Word(String::from(&src[start..end])));
        i = end;
    }
    toks.push(Tok::Eof);
    Ok(toks)
}

// ─── Parser ─────────────────────────────────────────────────────────────────

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

fn is_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.pos]
    }

    fn peek_at(&self, n: usize) -> &Tok {
        let i = (self.pos + n).min(self.toks.len() - 1);
        &self.toks[i]
    }

    fn next(&mut self) -> Tok {
        let t = self.toks[self.pos].clone();
        if self.pos < self.toks.len() - 1 { self.pos += 1; }
        t
    }

    fn is_word(&self, w: &str) -> bool {
        matches!(self.peek(), Tok::Word(s) if s == w)
    }

    fn is_op(&self, o: &str) -> bool {
        matches!(self.peek(), Tok::Op(s) if *s == o)
    }

    fn skip_newlines(&mut self) {
        while *self.peek() == Tok::Newline { self.next(); }
    }

    fn skip_separators(&mut self) {
        loop {
            match self.peek() {
                Tok::Newline => { self.next(); }
                Tok::Op(";") => { self.next(); }
                _ => break,
            }
        }
    }

    fn expect_word(&mut self, w: &str) -> Result<(), String> {
        self.skip_separators();
        if self.is_word(w) {
            self.next();
            Ok(())
        } else {
            Err(alloc::format!("expected '{}' {}", w, self.describe()))
        }
    }

    fn describe(&self) -> String {
        match self.peek() {
            Tok::Word(s) => alloc::format!("near '{}'", s),
            Tok::Op(o) => alloc::format!("near '{}'", o),
            Tok::Newline => String::from("at end of line"),
            Tok::Eof => String::from("at end of input"),
        }
    }

    fn at_terminator(&self, terms: &[&str]) -> bool {
        match self.peek() {
            Tok::Eof => true,
            Tok::Op(")") | Tok::Op(";;") => true,
            Tok::Word(w) => terms.iter().any(|t| *t == w.as_str()),
            _ => false,
        }
    }

    /// list := and_or ((';' | '&' | NEWLINE) and_or)*
    fn parse_list(&mut self, terms: &[&str]) -> Result<Node, String> {
        let mut items = Vec::new();
        loop {
            self.skip_separators();
            if self.at_terminator(terms) { break; }
            let node = self.parse_and_or()?;
            match self.peek() {
                Tok::Op("&") => {
                    self.next();
                    items.push(Node::Background(Box::new(node)));
                }
                Tok::Op(";") | Tok::Newline => {
                    self.next();
                    items.push(node);
                }
                _ => {
                    items.push(node);
                    if !self.at_terminator(terms) {
                        return Err(alloc::format!("syntax error {}", self.describe()));
                    }
                    break;
                }
            }
        }
        Ok(Node::Seq(items))
    }

    fn parse_and_or(&mut self) -> Result<Node, String> {
        let mut left = self.parse_pipeline()?;
        loop {
            if self.is_op("&&") {
                self.next();
                self.skip_newlines();
                let right = self.parse_pipeline()?;
                left = Node::And(Box::new(left), Box::new(right));
            } else if self.is_op("||") {
                self.next();
                self.skip_newlines();
                let right = self.parse_pipeline()?;
                left = Node::Or(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_pipeline(&mut self) -> Result<Node, String> {
        let mut negate = false;
        if self.is_word("!") {
            self.next();
            negate = true;
        }
        let mut cmds = Vec::new();
        cmds.push(self.parse_command()?);
        while self.is_op("|") {
            self.next();
            self.skip_newlines();
            cmds.push(self.parse_command()?);
        }
        if cmds.len() == 1 && !negate {
            return Ok(cmds.pop().unwrap());
        }
        Ok(Node::Pipeline { cmds, negate })
    }

    fn parse_redir(&mut self) -> Result<Option<Redir>, String> {
        let kind = match self.peek() {
            Tok::Op(">") => RedirKind::Out,
            Tok::Op(">>") => RedirKind::Append,
            Tok::Op("<") => RedirKind::In,
            Tok::Op("2>") => RedirKind::ErrOut,
            Tok::Op("2>>") => RedirKind::ErrAppend,
            Tok::Op("2>&1") => RedirKind::ErrToOut,
            Tok::Op(">&2") => RedirKind::OutToErr,
            Tok::Op("&>") => RedirKind::BothOut,
            _ => return Ok(None),
        };
        self.next();
        if kind == RedirKind::ErrToOut || kind == RedirKind::OutToErr {
            return Ok(Some(Redir { kind, target: String::new() }));
        }
        match self.next() {
            Tok::Word(w) => Ok(Some(Redir { kind, target: w })),
            _ => Err(String::from("syntax error: redirection without a file name")),
        }
    }

    fn parse_trailing_redirs(&mut self, node: Node) -> Result<Node, String> {
        let mut redirs = Vec::new();
        while let Some(r) = self.parse_redir()? {
            redirs.push(r);
        }
        if redirs.is_empty() {
            Ok(node)
        } else {
            Ok(Node::Redirected { node: Box::new(node), redirs })
        }
    }

    fn parse_command(&mut self) -> Result<Node, String> {
        let first = match self.peek() {
            Tok::Word(w) => Some(w.clone()),
            _ => None,
        };
        if self.is_op("(") {
            self.next();
            let body = self.parse_list(&[])?;
            if !self.is_op(")") {
                return Err(alloc::format!("expected ')' {}", self.describe()));
            }
            self.next();
            let node = Node::Group { body: Box::new(body), subshell: true };
            return self.parse_trailing_redirs(node);
        }
        if let Some(w) = first {
            match w.as_str() {
                "if" => { let n = self.parse_if()?; return self.parse_trailing_redirs(n); }
                "for" => { let n = self.parse_for()?; return self.parse_trailing_redirs(n); }
                "while" | "until" => { let n = self.parse_while()?; return self.parse_trailing_redirs(n); }
                "case" => { let n = self.parse_case()?; return self.parse_trailing_redirs(n); }
                "{" => {
                    self.next();
                    let body = self.parse_list(&["}"])?;
                    self.expect_word("}")?;
                    let node = Node::Group { body: Box::new(body), subshell: false };
                    return self.parse_trailing_redirs(node);
                }
                "function" => {
                    self.next();
                    let name = match self.next() {
                        Tok::Word(n) if is_name(&n) => n,
                        _ => return Err(String::from("syntax error: bad function name")),
                    };
                    if self.is_op("(") && *self.peek_at(1) == Tok::Op(")") {
                        self.next();
                        self.next();
                    }
                    self.skip_newlines();
                    let body = self.parse_command()?;
                    return Ok(Node::FuncDef { name, body: Rc::new(body) });
                }
                "then" | "else" | "elif" | "fi" | "do" | "done" | "esac" | "}" | "in" => {
                    return Err(alloc::format!("syntax error near unexpected '{}'", w));
                }
                _ => {}
            }
            if w.starts_with("((") && w.ends_with("))") && w.len() >= 4 {
                self.next();
                let expr = String::from(&w[2..w.len() - 2]);
                return self.parse_trailing_redirs(Node::Arith(expr));
            }
            // funcdef: NAME ( )
            if is_name(&w) && *self.peek_at(1) == Tok::Op("(") && *self.peek_at(2) == Tok::Op(")") {
                self.next();
                self.next();
                self.next();
                self.skip_newlines();
                let body = self.parse_command()?;
                return Ok(Node::FuncDef { name: w, body: Rc::new(body) });
            }
        }
        // simple command
        let mut words = Vec::new();
        let mut redirs = Vec::new();
        loop {
            if let Some(r) = self.parse_redir()? {
                redirs.push(r);
                continue;
            }
            match self.peek() {
                Tok::Word(w) => {
                    let w = w.clone();
                    self.next();
                    words.push(w);
                }
                _ => break,
            }
        }
        if words.is_empty() && redirs.is_empty() {
            return Err(alloc::format!("syntax error {}", self.describe()));
        }
        Ok(Node::Simple { words, redirs })
    }

    fn parse_if(&mut self) -> Result<Node, String> {
        self.next(); // if
        let mut branches = Vec::new();
        let cond = self.parse_list(&["then"])?;
        self.expect_word("then")?;
        let body = self.parse_list(&["elif", "else", "fi"])?;
        branches.push((cond, body));
        let mut else_body = None;
        loop {
            self.skip_separators();
            if self.is_word("elif") {
                self.next();
                let c = self.parse_list(&["then"])?;
                self.expect_word("then")?;
                let b = self.parse_list(&["elif", "else", "fi"])?;
                branches.push((c, b));
            } else if self.is_word("else") {
                self.next();
                let b = self.parse_list(&["fi"])?;
                else_body = Some(Box::new(b));
            } else {
                break;
            }
        }
        self.expect_word("fi")?;
        Ok(Node::If { branches, else_body })
    }

    fn parse_for(&mut self) -> Result<Node, String> {
        self.next(); // for
        let var = match self.next() {
            Tok::Word(v) if is_name(&v) => v,
            _ => return Err(String::from("syntax error: bad for-loop variable")),
        };
        self.skip_newlines();
        let mut items = None;
        if self.is_word("in") {
            self.next();
            let mut list = Vec::new();
            loop {
                match self.peek() {
                    Tok::Word(w) => {
                        let w = w.clone();
                        self.next();
                        list.push(w);
                    }
                    _ => break,
                }
            }
            items = Some(list);
        }
        self.expect_word("do")?;
        let body = self.parse_list(&["done"])?;
        self.expect_word("done")?;
        Ok(Node::For { var, items, body: Box::new(body) })
    }

    fn parse_while(&mut self) -> Result<Node, String> {
        let until = self.is_word("until");
        self.next();
        let cond = self.parse_list(&["do"])?;
        self.expect_word("do")?;
        let body = self.parse_list(&["done"])?;
        self.expect_word("done")?;
        Ok(Node::While { cond: Box::new(cond), body: Box::new(body), until })
    }

    fn parse_case(&mut self) -> Result<Node, String> {
        self.next(); // case
        let word = match self.next() {
            Tok::Word(w) => w,
            _ => return Err(String::from("syntax error: case needs a word")),
        };
        self.skip_newlines();
        if !self.is_word("in") {
            return Err(alloc::format!("expected 'in' {}", self.describe()));
        }
        self.next();
        let mut arms = Vec::new();
        loop {
            self.skip_separators();
            if self.is_word("esac") {
                self.next();
                break;
            }
            if *self.peek() == Tok::Eof {
                return Err(String::from("expected 'esac' at end of input"));
            }
            if self.is_op("(") { self.next(); }
            let mut patterns = Vec::new();
            loop {
                match self.next() {
                    Tok::Word(p) => patterns.push(p),
                    _ => return Err(String::from("syntax error in case pattern")),
                }
                if self.is_op("|") {
                    self.next();
                    continue;
                }
                if self.is_op(")") {
                    self.next();
                    break;
                }
                return Err(alloc::format!("expected ')' in case pattern {}", self.describe()));
            }
            let body = self.parse_list(&["esac"])?;
            arms.push(CaseArm { patterns, body });
            if self.is_op(";;") {
                self.next();
            }
        }
        Ok(Node::Case { word, arms })
    }
}

/// Parse a complete program (one line or a whole script).
pub fn parse(src: &str) -> Result<Node, String> {
    let toks = lex(src)?;
    let mut p = Parser { toks, pos: 0 };
    let node = p.parse_list(&[])?;
    match p.peek() {
        Tok::Eof => Ok(node),
        _ => Err(alloc::format!("syntax error {}", p.describe())),
    }
}

/// Does this text contain anything that needs the full shell (not just a
/// plain `cmd arg arg` line)?
pub fn needs_shell(s: &str) -> bool {
    s.bytes().any(|c| matches!(c, b'|' | b'&' | b';' | b'<' | b'>' | b'$' | b'`' | b'\'' | b'"' | b'(' | b')' | b'*' | b'?' | b'[' | b'~' | b'\\' | b'=' | b'#' | b'{' | b'}'))
}
