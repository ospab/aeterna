/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

plum/arith — integer arithmetic for $(( )), (( )) and `let`.

Operators (C precedence): ( ) ! ~ unary + -, * / %, + -, << >>,
< <= > >=, == !=, &, ^, |, &&, ||, ?:, = += -= *= /= %=, ++ -- (pre/post).
Variables are read from and written to the shell environment; an unset or
non-numeric variable reads as 0.  Values are 64-bit signed.
*/

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, PartialEq, Debug)]
enum T {
    Num(i64),
    Var(String),
    Op(&'static str),
}

const OPS: &[&str] = &[
    "<<=", ">>=", "++", "--", "**", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+=", "-=", "*=", "/=", "%=",
    "+", "-", "*", "/", "%", "<", ">", "!", "~", "&", "^", "|", "(", ")", "?", ":", "=",
];

fn lex(s: &str) -> Result<Vec<T>, String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    'outer: while i < b.len() {
        let c = b[i];
        if c == b' ' || c == b'\t' || c == b'\n' {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            let mut radix = 10;
            if c == b'0' && i + 1 < b.len() && (b[i + 1] == b'x' || b[i + 1] == b'X') {
                radix = 16;
                i += 2;
            }
            let digits_start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric()) { i += 1; }
            let text = if radix == 16 { &s[digits_start..i] } else { &s[start..i] };
            let v = i64::from_str_radix(text, radix)
                .map_err(|_| alloc::format!("invalid number '{}'", &s[start..i]))?;
            out.push(T::Num(v));
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') { i += 1; }
            out.push(T::Var(String::from(&s[start..i])));
            continue;
        }
        if c == b'$' {
            // $var inside arithmetic: same as var
            i += 1;
            continue;
        }
        for op in OPS {
            if s[i..].starts_with(op) {
                out.push(T::Op(op));
                i += op.len();
                continue 'outer;
            }
        }
        return Err(alloc::format!("unexpected character '{}'", c as char));
    }
    Ok(out)
}

struct P {
    t: Vec<T>,
    i: usize,
    /// When false, assignments and ++/-- are evaluated without side effects
    /// (used for the branch of ?: / && / || that is not taken).
    live: bool,
}

fn var_value(name: &str) -> Result<i64, String> {
    match super::getenv(name) {
        None => Ok(0),
        Some(v) => {
            let v = v.trim();
            if v.is_empty() { return Ok(0); }
            // a variable may itself contain an expression
            if v.bytes().all(|c| c.is_ascii_digit() || c == b'-') {
                v.parse::<i64>().map_err(|_| alloc::format!("'{}': not a number", v))
            } else {
                eval_depth(v, 1)
            }
        }
    }
}

impl P {
    fn peek(&self) -> Option<&T> { self.t.get(self.i) }
    fn is(&self, op: &str) -> bool { matches!(self.peek(), Some(T::Op(o)) if *o == op) }

    fn expr(&mut self) -> Result<i64, String> { self.assign() }

    fn assign(&mut self) -> Result<i64, String> {
        if let (Some(T::Var(name)), Some(T::Op(op))) = (self.t.get(self.i).cloned(), self.t.get(self.i + 1).cloned()) {
            if matches!(op, "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "<<=" | ">>=") {
                self.i += 2;
                let rhs = self.assign()?;
                let cur = if op == "=" { 0 } else { var_value(&name)? };
                let v = match op {
                    "=" => rhs,
                    "+=" => cur.wrapping_add(rhs),
                    "-=" => cur.wrapping_sub(rhs),
                    "*=" => cur.wrapping_mul(rhs),
                    "/=" => { if rhs == 0 { return Err(String::from("division by 0")); } cur / rhs }
                    "%=" => { if rhs == 0 { return Err(String::from("division by 0")); } cur % rhs }
                    "<<=" => cur.wrapping_shl(rhs as u32),
                    _ => cur.wrapping_shr(rhs as u32),
                };
                if self.live { super::setenv(&name, &super::io::fmt_i64(v)); }
                return Ok(v);
            }
        }
        self.ternary()
    }

    fn ternary(&mut self) -> Result<i64, String> {
        let c = self.binary(1)?;
        if self.is("?") {
            self.i += 1;
            let live = self.live;
            self.live = live && c != 0;
            let a = self.assign()?;
            if !self.is(":") { return Err(String::from("expected ':' in ?: expression")); }
            self.i += 1;
            self.live = live && c == 0;
            let b = self.assign()?;
            self.live = live;
            return Ok(if c != 0 { a } else { b });
        }
        Ok(c)
    }

    fn binary(&mut self, min_prec: u8) -> Result<i64, String> {
        let mut lhs = self.unary()?;
        loop {
            let (op, prec) = match self.peek() {
                Some(T::Op(o)) => match *o {
                    "||" => ("||", 1),
                    "&&" => ("&&", 2),
                    "|" => ("|", 3),
                    "^" => ("^", 4),
                    "&" => ("&", 5),
                    "==" => ("==", 6),
                    "!=" => ("!=", 6),
                    "<" => ("<", 7),
                    "<=" => ("<=", 7),
                    ">" => (">", 7),
                    ">=" => (">=", 7),
                    "<<" => ("<<", 8),
                    ">>" => (">>", 8),
                    "+" => ("+", 9),
                    "-" => ("-", 9),
                    "*" => ("*", 10),
                    "/" => ("/", 10),
                    "%" => ("%", 10),
                    "**" => ("**", 11),
                    _ => break,
                },
                _ => break,
            };
            if prec < min_prec { break; }
            self.i += 1;
            // short-circuit
            if op == "&&" || op == "||" {
                let live = self.live;
                let skip = (op == "&&" && lhs == 0) || (op == "||" && lhs != 0);
                self.live = live && !skip;
                let rhs = self.binary(prec + 1)?;
                self.live = live;
                lhs = if op == "&&" { (lhs != 0 && rhs != 0) as i64 } else { (lhs != 0 || rhs != 0) as i64 };
                continue;
            }
            let next_min = if op == "**" { prec } else { prec + 1 };
            let rhs = self.binary(next_min)?;
            lhs = match op {
                "|" => lhs | rhs,
                "^" => lhs ^ rhs,
                "&" => lhs & rhs,
                "==" => (lhs == rhs) as i64,
                "!=" => (lhs != rhs) as i64,
                "<" => (lhs < rhs) as i64,
                "<=" => (lhs <= rhs) as i64,
                ">" => (lhs > rhs) as i64,
                ">=" => (lhs >= rhs) as i64,
                "<<" => lhs.wrapping_shl(rhs as u32),
                ">>" => lhs.wrapping_shr(rhs as u32),
                "+" => lhs.wrapping_add(rhs),
                "-" => lhs.wrapping_sub(rhs),
                "*" => lhs.wrapping_mul(rhs),
                "/" => {
                    if rhs == 0 { if self.live { return Err(String::from("division by 0")); } 0 } else { lhs.wrapping_div(rhs) }
                }
                "%" => {
                    if rhs == 0 { if self.live { return Err(String::from("division by 0")); } 0 } else { lhs.wrapping_rem(rhs) }
                }
                _ => {
                    // **
                    if rhs < 0 { return Err(String::from("exponent less than 0")); }
                    let mut r: i64 = 1;
                    for _ in 0..rhs.min(64) { r = r.wrapping_mul(lhs); }
                    r
                }
            };
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> Result<i64, String> {
        match self.peek().cloned() {
            Some(T::Op("!")) => { self.i += 1; Ok((self.unary()? == 0) as i64) }
            Some(T::Op("~")) => { self.i += 1; Ok(!self.unary()?) }
            Some(T::Op("-")) => { self.i += 1; Ok(self.unary()?.wrapping_neg()) }
            Some(T::Op("+")) => { self.i += 1; self.unary() }
            Some(T::Op(op)) if op == "++" || op == "--" => {
                self.i += 1;
                match self.peek().cloned() {
                    Some(T::Var(name)) => {
                        self.i += 1;
                        let v = var_value(&name)? + if op == "++" { 1 } else { -1 };
                        if self.live { super::setenv(&name, &super::io::fmt_i64(v)); }
                        Ok(v)
                    }
                    _ => Err(alloc::format!("'{}' needs a variable", op)),
                }
            }
            _ => self.postfix(),
        }
    }

    fn postfix(&mut self) -> Result<i64, String> {
        match self.peek().cloned() {
            Some(T::Num(n)) => { self.i += 1; Ok(n) }
            Some(T::Var(name)) => {
                self.i += 1;
                let v = var_value(&name)?;
                if self.is("++") || self.is("--") {
                    let inc = if self.is("++") { 1 } else { -1 };
                    self.i += 1;
                    if self.live { super::setenv(&name, &super::io::fmt_i64(v + inc)); }
                }
                Ok(v)
            }
            Some(T::Op("(")) => {
                self.i += 1;
                let v = self.expr()?;
                if !self.is(")") { return Err(String::from("missing ')'")); }
                self.i += 1;
                Ok(v)
            }
            Some(T::Op(o)) => Err(alloc::format!("syntax error near '{}'", o)),
            None => Err(String::from("syntax error: operand expected")),
        }
    }
}

fn eval_depth(s: &str, depth: usize) -> Result<i64, String> {
    if depth > 8 { return Err(String::from("expression recursion too deep")); }
    let t = lex(s)?;
    if t.is_empty() { return Ok(0); }
    let mut p = P { t, i: 0, live: true };
    let v = p.expr()?;
    if p.i < p.t.len() {
        return Err(alloc::format!("syntax error in expression '{}'", s.trim()));
    }
    Ok(v)
}

/// Evaluate an arithmetic expression (variables already may contain $ — the
/// caller is expected to have run parameter expansion first).
pub fn eval(s: &str) -> Result<i64, String> {
    eval_depth(s, 0)
}
