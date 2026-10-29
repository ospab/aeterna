// Ported from the olang project: src/lexer/token.rs (no_std + alloc, synchronous).
use alloc::{boxed::Box, format, string::{String, ToString}, vec, vec::Vec};
#[derive(Debug, PartialEq, Clone)]
pub enum TokenType {
    // Базовые
    Illegal(char),
    Eof,

    // Идентификаторы и литералы
    Ident(String),     // названия переменных, функций и т.д.
    Int(i64),          // числа
    String(String),    // строки "hello"
    FString(String),   // F-строки f"..."
    Ipv4(String),      // Сетевая фишка: встроенный IP (например, 127.0.0.1)

    // Операторы
    Assign,      // =
    Plus,        // +
    Minus,       // -
    Asterisk,    // *
    Slash,       // /
    Less,        // <
    Greater,     // >
    Eq,          // ==
    And,         // &&
    Or,          // ||
    Arrow,       // =>
    SingleArrow, // ->

    // Разделители
    Comma,       // ,
    Colon,       // :
    DoubleColon, // ::
    Dot,         // .
    LParen,      // (
    RParen,      // )
    LBrace,      // {
    RBrace,      // }
    LBracket,    // [
    RBracket,    // ]

    // Ключевые слова
    Let,         // let
    Fn,          // fn
    Import,      // import
    If,          // if
    Else,        // else
    Loop,        // loop
    Match,       // match
    Defer,       // defer
    Return,      // return
    Struct,      // struct
    New,         // new
}

#[derive(Debug, PartialEq, Clone)]
pub struct Token {
    pub token_type: TokenType,
    pub line: usize,
    pub column: usize,
}

impl Token {
    pub fn new(token_type: TokenType, line: usize, column: usize) -> Self {
        Self { token_type, line, column }
    }
}

pub fn lookup_ident(ident: &str) -> TokenType {
    match ident {
        "fn" => TokenType::Fn,
        "let" => TokenType::Let,
        "import" => TokenType::Import,
        "if" => TokenType::If,
        "else" => TokenType::Else,
        "loop" => TokenType::Loop,
        "match" => TokenType::Match,
        "defer" => TokenType::Defer,
        "return" => TokenType::Return,
        "struct" => TokenType::Struct,
        "new" => TokenType::New,
        _ => TokenType::Ident(ident.to_string()),
    }
}
