// Ported from the olang project: src/evaluator/builtins.rs
// OS port: synchronous; print/time go through liboos; the network builtins return a
// runtime error until ring-3 sockets exist; args/exit/input are additions.
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use crate::evaluator::object::Object;

pub const NO_NET: &str = "networking is not available to programs yet";

/// Script arguments for `args()`; set once by main before evaluation (single-threaded).
struct Args(core::cell::UnsafeCell<Vec<String>>);
// SAFETY: the interpreter is single-threaded.
unsafe impl Sync for Args {}
static ARGS: Args = Args(core::cell::UnsafeCell::new(Vec::new()));

pub fn set_args(args: Vec<String>) {
    // SAFETY: called from main before any evaluation, single thread.
    unsafe { *ARGS.0.get() = args; }
}

fn script_args() -> Vec<String> {
    // SAFETY: single thread, no outstanding mutable access.
    unsafe { (*ARGS.0.get()).clone() }
}

pub fn eval_builtin(name: &str, args: Vec<Object>) -> Object {
    match name {
        "print" => {
            let mut line = String::new();
            for arg in args {
                line.push_str(&arg.to_string());
                line.push(' ');
            }
            line.push('\n');
            liboos::print!("{}", line);
            Object::Null
        }
        // Milliseconds since boot (the original returns Unix time in milliseconds).
        "time" => Object::Integer(crate::sys::uptime_ms()),
        "args" => {
            let items: Vec<Object> = script_args().into_iter().map(Object::String).collect();
            Object::Array(Rc::new(RefCell::new(items)))
        }
        "exit" => {
            let code = match args.first() {
                Some(Object::Integer(c)) => *c as i32,
                _ => 0,
            };
            liboos::exit(code)
        }
        "input" => {
            if let Some(prompt) = args.first() {
                liboos::print!("{}", prompt);
            }
            match crate::sys::read_line() {
                Some(l) => Object::String(l),
                None => Object::Null,
            }
        }
        "listen" | "accept" | "write" | "read" | "close" => {
            Object::Error(format!("{}() failed: {}", name, NO_NET))
        }
        _ => Object::Error(format!("Builtin function '{}' not found", name)),
    }
}
