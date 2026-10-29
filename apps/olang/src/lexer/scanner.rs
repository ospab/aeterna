// Ported from the olang project: src/lexer/scanner.rs (no_std + alloc, synchronous).
use alloc::{boxed::Box, format, string::{String, ToString}, vec, vec::Vec};
use crate::lexer::token::{lookup_ident, Token, TokenType};
use core::iter::Peekable;
use core::str::Chars;

pub struct Scanner<'a> {
    input: Peekable<Chars<'a>>,
    line: usize,
    column: usize,
}

impl<'a> Scanner<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            input: input.chars().peekable(),
            line: 1,
            column: 1,
        }
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.input.next()?;
        if ch == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(ch)
    }

    fn peek(&mut self) -> Option<&char> {
        self.input.peek()
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            match self.peek() {
                Some(&ch) if ch.is_whitespace() => {
                    self.advance();
                }
                Some('#') => {
                    while let Some(&ch) = self.peek() {
                        if ch == '\n' { break; }
                        self.advance();
                    }
                }
                _ => break,
            }
        }
    }

    pub fn next_token(&mut self) -> Token {
        self.skip_whitespace_and_comments();

        let start_line = self.line;
        let start_col = self.column;

        let ch = match self.advance() {
            Some(c) => c,
            None => return Token::new(TokenType::Eof, start_line, start_col),
        };

        match ch {
            '=' => {
                if let Some(&'=') = self.peek() {
                    self.advance();
                    return Token::new(TokenType::Eq, start_line, start_col);
                } else if let Some(&'>') = self.peek() {
                    self.advance();
                    return Token::new(TokenType::Arrow, start_line, start_col);
                }
                return Token::new(TokenType::Assign, start_line, start_col);
            }
            '&' => {
                if let Some(&'&') = self.peek() {
                    self.advance();
                    return Token::new(TokenType::And, start_line, start_col);
                }
                return Token::new(TokenType::Illegal('&'), start_line, start_col);
            }
            '|' => {
                if let Some(&'|') = self.peek() {
                    self.advance();
                    return Token::new(TokenType::Or, start_line, start_col);
                }
                return Token::new(TokenType::Illegal('|'), start_line, start_col);
            }
            _ => {}
        }

        let token_type = match ch {
            '+' => TokenType::Plus,
            '-' => {
                if let Some(&'>') = self.peek() {
                    self.advance();
                    TokenType::SingleArrow
                } else {
                    TokenType::Minus
                }
            },
            '*' => TokenType::Asterisk,
            '/' => TokenType::Slash,
            '<' => TokenType::Less,
            '>' => TokenType::Greater,
            ',' => TokenType::Comma,
            ':' => {
                if let Some(&':') = self.peek() {
                    self.advance();
                    TokenType::DoubleColon
                } else {
                    TokenType::Colon
                }
            },
            '.' => TokenType::Dot,
            '(' => TokenType::LParen,
            ')' => TokenType::RParen,
            '{' => TokenType::LBrace,
            '}' => TokenType::RBrace,
            '[' => TokenType::LBracket,
            ']' => TokenType::RBracket,
            '"' => self.read_string(),
            _ if ch.is_alphabetic() || ch == '_' => {
                let ident = self.read_ident_or_keyword(ch);
                if ident == TokenType::Ident("f".to_string()) {
                    if let Some(&'"') = self.peek() {
                        self.advance(); // consume '"'
                        let mut string = String::new();
                        while let Some(&next_ch) = self.peek() {
                            if next_ch == '"' {
                                self.advance(); // consume closing quote
                                break;
                            }
                            
                            if next_ch == '\\' {
                                self.advance(); // consume '\'
                                if let Some(&esc_ch) = self.peek() {
                                    match esc_ch {
                                        'n' => { string.push('\n'); self.advance(); },
                                        'r' => { string.push('\r'); self.advance(); },
                                        't' => { string.push('\t'); self.advance(); },
                                        '\\' => { string.push('\\'); self.advance(); },
                                        '"' => { string.push('"'); self.advance(); },
                                        _ => { string.push('\\'); string.push(esc_ch); self.advance(); },
                                    }
                                }
                            } else {
                                string.push(self.advance().unwrap());
                            }
                        }
                        return Token { token_type: TokenType::FString(string), line: start_line, column: start_col };
                    }
                }
                ident
            },
            _ if ch.is_ascii_digit() => self.read_number_or_ip(ch),
            _ => TokenType::Illegal(ch),
        };

        Token::new(token_type, start_line, start_col)
    }

    fn read_ident_or_keyword(&mut self, first: char) -> TokenType {
        let mut ident = String::new();
        ident.push(first);
        while let Some(&ch) = self.peek() {
            if ch.is_alphanumeric() || ch == '_' {
                ident.push(self.advance().unwrap());
            } else {
                break;
            }
        }
        lookup_ident(&ident)
    }

    fn read_number_or_ip(&mut self, first: char) -> TokenType {
        let mut num_str = String::new();
        num_str.push(first);
        let mut dots = 0;

        while let Some(&ch) = self.peek() {
            if ch.is_ascii_digit() {
                num_str.push(self.advance().unwrap());
            } else if ch == '.' {
                dots += 1;
                num_str.push(self.advance().unwrap());
            } else {
                break;
            }
        }

        // Если это IP адрес (содержит 3 точки)
        if dots == 3 {
            TokenType::Ipv4(num_str)
        } else if dots == 0 {
            // Обычное число
            if let Ok(val) = num_str.parse::<i64>() {
                TokenType::Int(val)
            } else {
                TokenType::Illegal(first) // Упрощенная обработка ошибки
            }
        } else {
            // Ошибка формата
            TokenType::Illegal(first) 
        }
    }

    fn read_string(&mut self) -> TokenType {
        let mut string = String::new();
        while let Some(&ch) = self.peek() {
            if ch == '"' {
                self.advance(); // consume closing quote
                break;
            }
            if ch == '\\' {
                self.advance(); // consume '\'
                if let Some(&esc_ch) = self.peek() {
                    match esc_ch {
                        'n' => { string.push('\n'); self.advance(); },
                        'r' => { string.push('\r'); self.advance(); },
                        't' => { string.push('\t'); self.advance(); },
                        '\\' => { string.push('\\'); self.advance(); },
                        '"' => { string.push('"'); self.advance(); },
                        _ => { string.push('\\'); string.push(esc_ch); self.advance(); },
                    }
                }
            } else {
                string.push(self.advance().unwrap());
            }
        }
        TokenType::String(string)
    }
}
