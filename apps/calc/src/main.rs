// SPDX-License-Identifier: AGPL-3.0-only
//! calc — command-line calculator. `calc 2+3*4`, `calc "(1+2)^3 / 4"`.
//!
//! Operators: + - * / % ^ (power, right-associative), unary minus, parentheses.
//! Exit status: 0 on success, 1 on a syntax or arithmetic error, 2 on usage.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use liboos::println;

liboos::entry!(main);

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.s.len() && self.s[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.s.get(self.pos).copied()
    }

    // expr := term (('+' | '-') term)*
    fn expr(&mut self) -> Result<f64, &'static str> {
        let mut v = self.term()?;
        while let Some(c) = self.peek() {
            match c {
                b'+' => { self.pos += 1; v += self.term()?; }
                b'-' => { self.pos += 1; v -= self.term()?; }
                _ => break,
            }
        }
        Ok(v)
    }

    // term := power (('*' | '/' | '%') power)*
    fn term(&mut self) -> Result<f64, &'static str> {
        let mut v = self.power()?;
        while let Some(c) = self.peek() {
            match c {
                b'*' => { self.pos += 1; v *= self.power()?; }
                b'/' => {
                    self.pos += 1;
                    let d = self.power()?;
                    if d == 0.0 { return Err("division by zero"); }
                    v /= d;
                }
                b'%' => {
                    self.pos += 1;
                    let d = self.power()?;
                    if d == 0.0 { return Err("division by zero"); }
                    v = v - d * trunc(v / d);
                }
                _ => break,
            }
        }
        Ok(v)
    }

    // power := unary ('^' power)?
    fn power(&mut self) -> Result<f64, &'static str> {
        let base = self.unary()?;
        if self.peek() == Some(b'^') {
            self.pos += 1;
            let exp = self.power()?;
            return powi(base, exp);
        }
        Ok(base)
    }

    // unary := '-' unary | '+' unary | atom
    fn unary(&mut self) -> Result<f64, &'static str> {
        match self.peek() {
            Some(b'-') => { self.pos += 1; Ok(-self.unary()?) }
            Some(b'+') => { self.pos += 1; self.unary() }
            _ => self.atom(),
        }
    }

    fn atom(&mut self) -> Result<f64, &'static str> {
        match self.peek() {
            Some(b'(') => {
                self.pos += 1;
                let v = self.expr()?;
                if self.peek() != Some(b')') { return Err("missing ')'"); }
                self.pos += 1;
                Ok(v)
            }
            Some(c) if c.is_ascii_digit() || c == b'.' => self.number(),
            Some(_) => Err("unexpected character"),
            None => Err("unexpected end of expression"),
        }
    }

    fn number(&mut self) -> Result<f64, &'static str> {
        let mut int: f64 = 0.0;
        let mut seen = false;
        while self.pos < self.s.len() && self.s[self.pos].is_ascii_digit() {
            int = int * 10.0 + (self.s[self.pos] - b'0') as f64;
            self.pos += 1;
            seen = true;
        }
        if self.pos < self.s.len() && self.s[self.pos] == b'.' {
            self.pos += 1;
            let mut scale = 0.1;
            while self.pos < self.s.len() && self.s[self.pos].is_ascii_digit() {
                int += (self.s[self.pos] - b'0') as f64 * scale;
                scale /= 10.0;
                self.pos += 1;
                seen = true;
            }
        }
        if seen { Ok(int) } else { Err("bad number") }
    }
}

/// Truncate toward zero without libm (values beyond 2^63 are already integers).
fn trunc(x: f64) -> f64 {
    if x >= 9.0e18 || x <= -9.0e18 { x } else { (x as i64) as f64 }
}

/// base^exp for integer exponents (no libm available).
fn powi(base: f64, exp: f64) -> Result<f64, &'static str> {
    if trunc(exp) != exp { return Err("only integer exponents are supported"); }
    if exp.abs() > 10_000.0 { return Err("exponent too large"); }
    let mut n = exp.abs() as u32;
    let (mut b, mut r) = (base, 1.0f64);
    while n > 0 {
        if n & 1 == 1 { r *= b; }
        b *= b;
        n >>= 1;
    }
    if exp < 0.0 {
        if r == 0.0 { return Err("division by zero"); }
        r = 1.0 / r;
    }
    Ok(r)
}

fn main(args: liboos::Args) -> i32 {
    let mut text = String::new();
    for a in args.iter().skip(1) {
        text.push_str(a);
        text.push(' ');
    }
    if text.trim().is_empty() {
        println!("usage: calc <expression>   e.g. calc 2+3*4   calc \"(1+2)^3 / 4\"");
        return 2;
    }
    let mut p = Parser { s: text.as_bytes(), pos: 0 };
    let result = p.expr().and_then(|v| {
        if p.peek().is_some() { Err("unexpected character") } else { Ok(v) }
    });
    match result {
        Ok(v) if v.is_finite() => {
            if v == trunc(v) && v.abs() < 1.0e15 {
                println!("{}", v as i64);
            } else {
                println!("{}", v);
            }
            0
        }
        Ok(_) => { println!("calc: result is not a finite number"); 1 }
        Err(e) => { println!("calc: {} (at column {})", e, p.pos + 1); 1 }
    }
}
