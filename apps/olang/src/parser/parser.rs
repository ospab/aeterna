// Ported from the olang project: src/parser/parser.rs (no_std + alloc, synchronous).
use alloc::{boxed::Box, format, string::{String, ToString}, vec, vec::Vec};
use crate::ast::{Expression, Program, Statement};
use crate::lexer::scanner::Scanner;
use crate::lexer::token::{Token, TokenType};

#[derive(PartialEq, PartialOrd, Debug)]
enum Precedence {
    Lowest = 1,
    Logical = 2,
    Equals = 3,
    LessGreater = 4,
    Sum = 5,
    Product = 6,
    Prefix = 7,
    Call = 8,
}

fn token_precedence(token_type: &TokenType) -> Precedence {
    match token_type {
        TokenType::LParen => Precedence::Call,
        TokenType::Dot => Precedence::Call,
        TokenType::DoubleColon => Precedence::Call,
        TokenType::LBracket => Precedence::Call,
        TokenType::Or | TokenType::And => Precedence::Logical,
        TokenType::Eq => Precedence::Equals,
        TokenType::Less | TokenType::Greater => Precedence::LessGreater,
        TokenType::Plus | TokenType::Minus => Precedence::Sum,
        TokenType::Asterisk | TokenType::Slash => Precedence::Product,
        _ => Precedence::Lowest,
    }
}

pub struct Parser<'a> {
    scanner: Scanner<'a>,
    current_token: Token,
    peek_token: Token,
    pub errors: Vec<String>,
}

impl<'a> Parser<'a> {
    pub fn new(mut scanner: Scanner<'a>) -> Self {
        let current_token = scanner.next_token();
        let peek_token = scanner.next_token();
        Self {
            scanner,
            current_token,
            peek_token,
            errors: Vec::new(),
        }
    }

    fn add_error(&mut self, msg: String) {
        let line = self.current_token.line;
        let col = self.current_token.column;
        self.errors.push(format!("[Line {}, Col {}] {}", line, col, msg));
    }

    fn advance(&mut self) {
        self.current_token = self.peek_token.clone();
        self.peek_token = self.scanner.next_token();
    }

    fn current_precedence(&self) -> Precedence {
        token_precedence(&self.current_token.token_type)
    }

    fn peek_precedence(&self) -> Precedence {
        token_precedence(&self.peek_token.token_type)
    }

    pub fn parse_program(&mut self) -> Program {
        let mut program = Program::new();

        while self.current_token.token_type != TokenType::Eof {
            let line = self.current_token.line;
            if let Some(stmt) = self.parse_statement() {
                program.statements.push(stmt);
                program.lines.push(line);
            }
            self.advance();
        }

        program
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        match self.current_token.token_type {
            TokenType::Let => self.parse_let_statement(),
            TokenType::Return => self.parse_return_statement(),
            TokenType::Fn => self.parse_function_declaration(),
            TokenType::Import => self.parse_import_statement(),
            TokenType::Struct => self.parse_struct_declaration(),
            _ => self.parse_expression_statement(),
        }
    }

    fn parse_let_statement(&mut self) -> Option<Statement> {
        self.advance(); // consume 'let'
        
        let name = match &self.current_token.token_type {
            TokenType::Ident(name) => name.clone(),
            _ => {
                self.add_error(format!("Expected variable name, got {:?}", self.current_token.token_type));
                return None;
            }
        };

        let mut type_name = None;
        if self.peek_token.token_type == TokenType::Colon {
            self.advance(); // consume name -> colon
            self.advance(); // consume colon -> type
            match &self.current_token.token_type {
                TokenType::Ident(t) => type_name = Some(t.clone()),
                _ => {
                    self.add_error(format!("Expected type, got {:?}", self.current_token.token_type));
                    return None;
                }
            }
        }

        // Если не присваиваем значение сразу (например let buf: byte[1024])
        if self.peek_token.token_type != TokenType::Assign {
            // Но в нашем случае массив это выражение справа, так что мы требуем = или поддерживаем без =?
            // Сделаем пока что byte[1024] парсится как тип, либо мы пишем `let buf = byte[1024]`
            // Допустим, мы пишем `let buf: byte[1024]` (в Rust так нельзя, обычно let buf = [0; 1024]). 
            // Пусть у нас переменная всегда требует '=', или мы парсим выделение массива справа!
            // Т.е. `let buf = byte[1024]`.
        }
        
        if self.peek_token.token_type != TokenType::Assign {
            // Для упрощения, если нет '=', то это объявление без инициализации (вернем Null в eval)
            // Но мы требуем '=' пока.
            self.add_error(format!("Expected '=', got {:?}", self.peek_token.token_type));
            return None;
        }

        self.advance(); // consume to '='
        self.advance(); // consume '=' to expression

        let value = self.parse_expression(Precedence::Lowest)?;

        Some(Statement::Let {
            name,
            type_name,
            value,
        })
    }

    fn parse_return_statement(&mut self) -> Option<Statement> {
        self.advance();
        let value = self.parse_expression(Precedence::Lowest)?;
        Some(Statement::Return(value))
    }

    fn parse_import_statement(&mut self) -> Option<Statement> {
        self.advance(); // consume 'import'
        let mut path = Vec::new();
        loop {
            match &self.current_token.token_type {
                TokenType::Ident(name) => {
                    path.push(name.clone());
                }
                _ => {
                    self.add_error("Expected identifier in import path".to_string());
                    return None;
                }
            }
            if self.peek_token.token_type == TokenType::DoubleColon {
                self.advance(); // to ::
                self.advance(); // to next ident
            } else {
                break;
            }
        }
        Some(Statement::Import(path))
    }

    fn parse_struct_declaration(&mut self) -> Option<Statement> {
        self.advance(); // consume 'struct'
        let name = match &self.current_token.token_type {
            TokenType::Ident(n) => n.clone(),
            _ => { self.add_error("Expected struct name".to_string()); return None; }
        };
        if self.peek_token.token_type != TokenType::LBrace { return None; }
        self.advance(); // to {
        let mut fields = Vec::new();
        while self.peek_token.token_type != TokenType::RBrace && self.peek_token.token_type != TokenType::Eof {
            self.advance();
            let field_name = match &self.current_token.token_type {
                TokenType::Ident(n) => n.clone(),
                _ => break,
            };
            if self.peek_token.token_type != TokenType::Colon { return None; }
            self.advance(); // to :
            self.advance(); // to type
            let field_type = match &self.current_token.token_type {
                TokenType::Ident(n) => n.clone(),
                _ => break,
            };
            fields.push((field_name, field_type));
            if self.peek_token.token_type == TokenType::Comma { self.advance(); }
        }
        self.advance(); // to }
        Some(Statement::Struct { name, fields })
    }

    fn parse_function_declaration(&mut self) -> Option<Statement> {
        self.advance(); // consume 'fn'

        let name = match &self.current_token.token_type {
            TokenType::Ident(name) => name.clone(),
            _ => {
                self.add_error(format!("Expected function name, got {:?}", self.current_token.token_type));
                return None;
            }
        };

        if self.peek_token.token_type != TokenType::LParen {
            self.add_error(format!("Expected '(' after function name, got {:?}", self.peek_token.token_type));
            return None;
        }
        self.advance(); // consume name -> '('

        let mut parameters = Vec::new();
        if self.peek_token.token_type != TokenType::RParen {
            self.advance(); // go to first param
            loop {
                let param_name = match &self.current_token.token_type {
                    TokenType::Ident(name) => name.clone(),
                    _ => {
                        self.add_error("Expected parameter name".to_string());
                        return None;
                    }
                };

                if self.peek_token.token_type != TokenType::Colon {
                    self.add_error("Expected ':' after parameter name".to_string());
                    return None;
                }
                self.advance(); // param_name -> ':'
                self.advance(); // ':' -> param_type

                let param_type = match &self.current_token.token_type {
                    TokenType::Ident(name) => name.clone(),
                    _ => {
                        self.add_error("Expected parameter type".to_string());
                        return None;
                    }
                };

                parameters.push((param_name, param_type));

                if self.peek_token.token_type == TokenType::Comma {
                    self.advance(); // type -> ','
                    self.advance(); // ',' -> next param_name
                } else {
                    break;
                }
            }
        }

        if self.peek_token.token_type != TokenType::RParen {
            self.add_error("Expected ')' after parameters".to_string());
            return None;
        }
        self.advance(); // type (or '(') -> ')'

        let mut return_type = None;
        if self.peek_token.token_type == TokenType::SingleArrow {
            self.advance(); // ')' -> '->'
            self.advance(); // '->' -> return_type
            match &self.current_token.token_type {
                TokenType::Ident(name) => return_type = Some(name.clone()),
                _ => {
                    self.add_error("Expected return type after '->'".to_string());
                    return None;
                }
            }
        }

        if self.peek_token.token_type != TokenType::LBrace {
            self.add_error("Expected '{' before function body".to_string());
            return None;
        }
        
        // Use parse_block_statement but we need to advance to '{' first
        self.advance(); // last_token -> '{'
        let block_stmt = self.parse_block_statement()?;
        
        let body = match block_stmt {
            Statement::Block(stmts) => stmts,
            _ => vec![],
        };

        Some(Statement::Function {
            name,
            parameters,
            return_type,
            body,
        })
    }

    fn parse_expression_statement(&mut self) -> Option<Statement> {
        let expr = self.parse_expression(Precedence::Lowest)?;
        
        if self.peek_token.token_type == TokenType::Assign {
            self.advance(); // to '='
            self.advance(); // to value
            let value = self.parse_expression(Precedence::Lowest)?;
            return Some(Statement::Assign { target: expr, value });
        }
        
        Some(Statement::Expression(expr))
    }

    // --- Pratt Parsing ---
    fn parse_expression(&mut self, precedence: Precedence) -> Option<Expression> {
        let mut left_exp = self.parse_prefix()?;

        while self.peek_token.token_type != TokenType::Eof && precedence < self.peek_precedence() {
            if let Some(infix) = self.parse_infix(left_exp.clone()) {
                left_exp = infix;
            } else {
                return Some(left_exp);
            }
        }

        Some(left_exp)
    }

    fn parse_prefix(&mut self) -> Option<Expression> {
        match &self.current_token.token_type {
            TokenType::Ident(name) => Some(Expression::Identifier(name.clone())),
            TokenType::Int(val) => Some(Expression::Integer(*val)),
            TokenType::String(val) => Some(Expression::String(val.clone())),
            TokenType::Ipv4(val) => Some(Expression::Ipv4(val.clone())),
            TokenType::FString(val) => self.parse_fstring(val.clone()),
            TokenType::LBracket => self.parse_array_literal(),
            TokenType::Minus => {
                let op = "-".to_string();
                self.advance();
                let right = self.parse_expression(Precedence::Prefix)?;
                Some(Expression::Prefix { operator: op, right: Box::new(right) })
            }
            TokenType::New => self.parse_struct_literal(),
            TokenType::Loop => self.parse_loop_expression(),
            TokenType::If => self.parse_if_expression(),
            _ => {
                self.add_error(format!("Unknown prefix expression: {:?}", self.current_token.token_type));
                None
            }
        }
    }

    fn parse_infix(&mut self, left: Expression) -> Option<Expression> {
        match self.peek_token.token_type {
            TokenType::LParen => {
                self.advance(); // переходим на LParen
                self.parse_call_expression(left)
            }
            TokenType::LBracket => {
                self.advance(); // переходим на LBracket
                self.parse_array_allocation(left)
            }
            TokenType::Dot => {
                self.advance(); // переходим на Dot
                self.parse_property_or_method_call(left)
            }
            TokenType::DoubleColon => {
                self.advance(); // переходим на ::
                self.parse_static_method_call(left)
            }
            TokenType::Plus | TokenType::Minus | TokenType::Asterisk | TokenType::Slash | TokenType::Eq | TokenType::Less | TokenType::Greater | TokenType::And | TokenType::Or => {
                self.advance(); // переходим на оператор
                let op = match self.current_token.token_type {
                    TokenType::Plus => "+",
                    TokenType::Minus => "-",
                    TokenType::Asterisk => "*",
                    TokenType::Slash => "/",
                    TokenType::Eq => "==",
                    TokenType::Less => "<",
                    TokenType::Greater => ">",
                    TokenType::And => "&&",
                    TokenType::Or => "||",
                    _ => "",
                }.to_string();
                
                let precedence = self.current_precedence();
                self.advance(); // переходим на правое выражение
                let right = self.parse_expression(precedence)?;
                Some(Expression::Infix {
                    left: Box::new(left),
                    operator: op,
                    right: Box::new(right),
                })
            }
            _ => None,
        }
    }

    // Функция: print(a, b)
    fn parse_call_expression(&mut self, function: Expression) -> Option<Expression> {
        let func_name = match function {
            Expression::Identifier(n) => n,
            _ => {
                self.add_error("Expected identifier for function call".to_string());
                return None;
            }
        };
        let args = self.parse_expression_list(TokenType::RParen);
        Some(Expression::Call { function: func_name, arguments: args })
    }

    // Статический метод: TcpListener::bind(addr, port)
    fn parse_static_method_call(&mut self, class: Expression) -> Option<Expression> {
        let class_name = match class {
            Expression::Identifier(n) => n,
            _ => {
                self.add_error("Expected identifier before ::".to_string());
                return None;
            }
        };

        self.advance(); // переходим на имя метода
        let method_name = match &self.current_token.token_type {
            TokenType::Ident(name) => name.clone(),
            _ => {
                self.add_error("Expected method name after ::".to_string());
                return None;
            }
        };

        if self.peek_token.token_type != TokenType::LParen {
            self.add_error("Expected '(' after static method name".to_string());
            return None;
        }
        self.advance(); // переходим на '('

        let args = self.parse_expression_list(TokenType::RParen);
        Some(Expression::StaticMethodCall { class_name, method_name, arguments: args })
    }

    // Property or Method: client.read(buf) or obj.field
    fn parse_property_or_method_call(&mut self, object: Expression) -> Option<Expression> {
        self.advance(); // to name
        let name = match &self.current_token.token_type {
            TokenType::Ident(name) => name.clone(),
            _ => {
                self.add_error("Expected property or method name after .".to_string());
                return None;
            }
        };

        if self.peek_token.token_type == TokenType::LParen {
            self.advance(); // to '('
            let args = self.parse_expression_list(TokenType::RParen);
            Some(Expression::MethodCall { object: Box::new(object), method_name: name, arguments: args })
        } else {
            Some(Expression::PropertyAccess { object: Box::new(object), property: name })
        }
    }

    // Выделение массива: byte[1024]
    fn parse_array_allocation(&mut self, element: Expression) -> Option<Expression> {
        let element_type = match element {
            Expression::Identifier(n) => n,
            _ => {
                self.add_error("Expected type identifier before [".to_string());
                return None;
            }
        };

        self.advance(); // перешли внутрь [
        let size = self.parse_expression(Precedence::Lowest)?;

        if self.peek_token.token_type != TokenType::RBracket {
            self.add_error("Expected ']' after array size".to_string());
            return None;
        }
        self.advance(); // переходим на ']'

        Some(Expression::ArrayAllocation { element_type, size: Box::new(size) })
    }

    fn parse_expression_list(&mut self, end: TokenType) -> Vec<Expression> {
        let mut list = Vec::new();

        if self.peek_token.token_type == end {
            self.advance();
            return list;
        }

        self.advance(); // первый аргумент
        if let Some(expr) = self.parse_expression(Precedence::Lowest) {
            list.push(expr);
        }

        while self.peek_token.token_type == TokenType::Comma {
            self.advance(); // на запятую
            self.advance(); // на следующий аргумент
            if let Some(expr) = self.parse_expression(Precedence::Lowest) {
                list.push(expr);
            }
        }

        if self.peek_token.token_type != end {
            self.add_error(format!("Expected {:?}, got {:?}", end, self.peek_token.token_type));
        } else {
            self.advance(); // на закрывающую скобку
        }

        list
    }

    fn parse_array_literal(&mut self) -> Option<Expression> {
        let elements = self.parse_expression_list(TokenType::RBracket);
        Some(Expression::Array(elements))
    }

    fn parse_struct_literal(&mut self) -> Option<Expression> {
        self.advance(); // consume 'new'
        let name = match &self.current_token.token_type {
            TokenType::Ident(n) => n.clone(),
            _ => { self.add_error("Expected struct name after new".to_string()); return None; }
        };
        if self.peek_token.token_type != TokenType::LBrace { return None; }
        self.advance(); // to {
        let mut fields = Vec::new();
        while self.peek_token.token_type != TokenType::RBrace && self.peek_token.token_type != TokenType::Eof {
            self.advance();
            let field_name = match &self.current_token.token_type {
                TokenType::Ident(n) => n.clone(),
                _ => break,
            };
            if self.peek_token.token_type != TokenType::Colon { return None; }
            self.advance(); // to :
            self.advance(); // to value
            let value = self.parse_expression(Precedence::Lowest)?;
            fields.push((field_name, value));
            if self.peek_token.token_type == TokenType::Comma { self.advance(); }
        }
        self.advance(); // to }
        Some(Expression::StructLiteral { name, fields })
    }

    fn parse_fstring(&mut self, text: String) -> Option<Expression> {
        let mut parts = Vec::new();
        let mut current_str = String::new();
        let mut chars = text.chars().peekable();
        
        while let Some(ch) = chars.next() {
            if ch == '{' {
                if !current_str.is_empty() {
                    parts.push(Expression::String(current_str.clone()));
                    current_str.clear();
                }
                
                let mut expr_str = String::new();
                while let Some(&next_ch) = chars.peek() {
                    if next_ch == '}' {
                        chars.next(); // consume }
                        break;
                    }
                    expr_str.push(chars.next().unwrap());
                }
                
                let scanner = Scanner::new(&expr_str);
                let mut mini_parser = Parser::new(scanner);
                if let Some(expr) = mini_parser.parse_expression(Precedence::Lowest) {
                    parts.push(expr);
                } else {
                    self.add_error(format!("Failed to parse f-string expr: {}", expr_str));
                }
            } else {
                current_str.push(ch);
            }
        }
        
        if !current_str.is_empty() {
            parts.push(Expression::String(current_str));
        }
        
        Some(Expression::FString(parts))
    }

    // Блок: { ... }
    fn parse_block_statement(&mut self) -> Option<Statement> {
        let mut statements = Vec::new();
        self.advance(); // перешли на первую инструкцию внутри {

        while self.current_token.token_type != TokenType::RBrace && self.current_token.token_type != TokenType::Eof {
            if let Some(stmt) = self.parse_statement() {
                statements.push(stmt);
            }
            self.advance();
        }

        Some(Statement::Block(statements))
    }

    // Цикл: loop { ... }
    fn parse_loop_expression(&mut self) -> Option<Expression> {
        if self.peek_token.token_type != TokenType::LBrace {
            self.add_error("Expected '{' after loop".to_string());
            return None;
        }
        self.advance(); // на '{'
        
        let body = self.parse_block_statement()?;
        Some(Expression::Loop { body: Box::new(body) })
    }

    // Условие: if condition { ... }
    fn parse_if_expression(&mut self) -> Option<Expression> {
        self.advance(); // на условие
        let condition = self.parse_expression(Precedence::Lowest)?;

        if self.peek_token.token_type != TokenType::LBrace {
            self.add_error("Expected '{' after if condition".to_string());
            return None;
        }
        self.advance(); // на '{'
        
        let consequence = self.parse_block_statement()?;
        let mut alternative = None;

        if self.peek_token.token_type == TokenType::Else {
            self.advance(); // на 'else'
            if self.peek_token.token_type != TokenType::LBrace {
                self.add_error("Expected '{' after else".to_string());
                return None;
            }
            self.advance(); // на '{'
            alternative = Some(Box::new(self.parse_block_statement()?));
        }

        Some(Expression::If {
            condition: Box::new(condition),
            consequence: Box::new(consequence),
            alternative,
        })
    }
}
