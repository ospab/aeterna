// Ported from the olang project: src/ast/mod.rs (no_std + alloc, synchronous).
use alloc::{boxed::Box, format, string::{String, ToString}, vec, vec::Vec};
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    // let name: type = expression
    Let {
        name: String,
        type_name: Option<String>,
        value: Expression,
    },
    // return expression
    Return(Expression),
    // Блок кода { stmt; stmt; }
    Block(Vec<Statement>),
    // Определение функции: fn name(a: int) -> int { ... }
    Function {
        name: String,
        parameters: Vec<(String, String)>, // (name, type_name)
        return_type: Option<String>,
        body: Vec<Statement>, // Тело блока
    },
    Import(Vec<String>),
    Struct {
        name: String,
        fields: Vec<(String, String)>,
    },
    Assign {
        target: Expression,
        value: Expression,
    },
    // Просто выражение
    Expression(Expression),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    Identifier(String),
    Integer(i64),
    String(String),
    FString(Vec<Expression>),
    Ipv4(String),
    Array(Vec<Expression>),
    
    // Префиксные операции (-5)
    Prefix {
        operator: String,
        right: Box<Expression>,
    },
    
    // Инфиксные операции (5 + 5, a > b)
    Infix {
        left: Box<Expression>,
        operator: String,
        right: Box<Expression>,
    },

    // Вызов обычной функции: func(arg)
    Call {
        function: String, 
        arguments: Vec<Expression>,
    },

    // Вызов статического метода: TcpListener::bind(args)
    StaticMethodCall {
        class_name: String,
        method_name: String,
        arguments: Vec<Expression>,
    },

    // Вызов метода у объекта: client.write(args)
    MethodCall {
        object: Box<Expression>,
        method_name: String,
        arguments: Vec<Expression>,
    },

    // Выделение памяти (массив): byte[1024]
    ArrayAllocation {
        element_type: String,
        size: Box<Expression>,
    },

    // Цикл: loop { ... }
    Loop {
        body: Box<Statement>, // Statement::Block
    },
    StructLiteral {
        name: String,
        fields: Vec<(String, Expression)>,
    },
    PropertyAccess {
        object: Box<Expression>,
        property: String,
    },

    // Условие: if (cond) { ... }
    If {
        condition: Box<Expression>,
        consequence: Box<Statement>,
        alternative: Option<Box<Statement>>,
    }
}

#[derive(Debug, Clone)]
pub struct Program {
    pub statements: Vec<Statement>,
    /// Source line where each top-level statement starts (added in the OS port, for runtime error reports).
    pub lines: Vec<usize>,
}

impl Program {
    pub fn new() -> Self {
        Self {
            statements: Vec::new(),
            lines: Vec::new(),
        }
    }
}
