// Ported from the olang project: src/evaluator/object.rs
// OS port: Arc<RwLock<..>> -> Rc<RefCell<..>> (single-threaded); TcpListener/TcpStream
// values are gone (no ring-3 sockets yet); function bodies and modules are shared with Rc.
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt;
use crate::ast::Statement;

#[derive(Clone)]
pub enum Object {
    Integer(i64),
    String(String),
    Ipv4(String),
    ByteArray(Rc<RefCell<Vec<u8>>>),
    Function {
        parameters: Rc<Vec<(String, String)>>,
        body: Rc<Vec<Statement>>,
    },
    Array(Rc<RefCell<Vec<Object>>>),
    Module(Rc<BTreeMap<String, Object>>),
    StructDefinition {
        name: String,
        fields: Vec<(String, String)>,
    },
    StructInstance {
        name: String,
        fields: Rc<RefCell<BTreeMap<String, Object>>>,
    },
    ReturnValue(Box<Object>),
    Null,
    Error(String),
}

impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Object::Integer(val) => write!(f, "Integer({})", val),
            Object::String(val) => write!(f, "String(\"{}\")", val),
            Object::Ipv4(val) => write!(f, "Ipv4({})", val),
            Object::ByteArray(buf) => write!(f, "ByteArray({} bytes)", buf.borrow().len()),
            Object::Function { .. } => write!(f, "Function"),
            Object::Module(_) => write!(f, "Module"),
            Object::StructDefinition { name, .. } => write!(f, "StructDef({})", name),
            Object::StructInstance { name, fields } => write!(f, "StructInstance({} {:?})", name, fields.borrow()),
            Object::Array(arr) => write!(f, "Array({:?})", arr.borrow()),
            Object::ReturnValue(val) => write!(f, "{}", val),
            Object::Null => write!(f, "Null"),
            Object::Error(msg) => write!(f, "Error(\"{}\")", msg),
        }
    }
}

impl PartialEq for Object {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Object::Integer(a), Object::Integer(b)) => a == b,
            (Object::String(a), Object::String(b)) => a == b,
            (Object::Ipv4(a), Object::Ipv4(b)) => a == b,
            (Object::Null, Object::Null) => true,
            (Object::Error(a), Object::Error(b)) => a == b,
            (Object::Function { .. }, Object::Function { .. }) => false,
            (Object::Module(_), Object::Module(_)) => false,
            (Object::StructDefinition { name: a, .. }, Object::StructDefinition { name: b, .. }) => a == b,
            (Object::StructInstance { fields: a, .. }, Object::StructInstance { fields: b, .. }) => Rc::ptr_eq(a, b),
            (Object::ReturnValue(a), Object::ReturnValue(b)) => a == b,
            (Object::Array(a), Object::Array(b)) => Rc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl fmt::Display for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Object::Integer(val) => write!(f, "{}", val),
            Object::String(val) => write!(f, "{}", val),
            Object::Ipv4(val) => write!(f, "{}", val),
            Object::ByteArray(buf) => write!(f, "<ByteArray {} bytes>", buf.borrow().len()),
            Object::Function { .. } => write!(f, "<Function>"),
            Object::Module(_) => write!(f, "<Module>"),
            Object::StructDefinition { name, .. } => write!(f, "<StructDef {}>", name),
            Object::StructInstance { name, fields } => {
                let mut props = Vec::new();
                for (k, v) in fields.borrow().iter() {
                    props.push(format!("{}: {}", k, v));
                }
                write!(f, "{} {{ {} }}", name, props.join(", "))
            }
            Object::Array(arr) => {
                let mut elements = Vec::new();
                for e in arr.borrow().iter() {
                    elements.push(e.to_string());
                }
                write!(f, "[{}]", elements.join(", "))
            }
            Object::ReturnValue(val) => write!(f, "{}", val),
            Object::Null => write!(f, "null"),
            Object::Error(msg) => write!(f, "ERROR: {}", msg),
        }
    }
}
