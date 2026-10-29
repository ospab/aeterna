// Ported from the olang project: src/evaluator/eval.rs (no_std + alloc, synchronous).
// OS port: synchronous (async/await and tokio removed), Rc<RefCell<..>> instead of
// Arc<RwLock<..>>, files through liboos, no networking, recursion depth limit.
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::ast::{Expression, Program, Statement};
use crate::evaluator::builtins::NO_NET;
use crate::evaluator::env::Environment;
use crate::evaluator::object::Object;

/// Lowest stack address the evaluator may use; calls below it fail with a runtime error
/// instead of faulting (set by main).
static STACK_FLOOR: AtomicUsize = AtomicUsize::new(0);

pub fn set_stack_floor(addr: usize) {
    STACK_FLOOR.store(addr, Ordering::Relaxed);
}

/// Directories searched for `import a::b` (-> a/b.ol), in order.
const MODULE_DIRS: [&str; 3] = ["", "/usr/share/olang/", "/usr/lib/olang/"];

/// Read an .ol module: as written, then in the system directories.
pub fn read_module(rel: &str) -> Result<String, String> {
    let mut last = String::new();
    for dir in MODULE_DIRS {
        let p = format!("{}{}", dir, rel);
        match crate::sys::read_file(&p) {
            Ok(c) => return Ok(c),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Like `eval_program`, but on a runtime error also returns the source line of the
/// top-level statement that failed (OS port addition).
pub fn eval_program_at(program: &Program, env: &mut Environment) -> (Object, usize) {
    let mut result = Object::Null;
    for (i, statement) in program.statements.iter().enumerate() {
        result = eval_statement(statement, env);
        if let Object::Error(_) = result {
            return (result, program.lines.get(i).copied().unwrap_or(0));
        }
    }
    (result, 0)
}

pub fn eval_program(program: &Program, env: &mut Environment) -> Object {
    let mut result = Object::Null;

    for statement in &program.statements {
        result = eval_statement(statement, env);
        if let Object::Error(_) = result {
            return result;
        }
    }
    result
}

fn call_body(body: &[Statement], env: &mut Environment) -> Object {
    let marker = 0u8;
    if (&marker as *const u8 as usize) < STACK_FLOOR.load(Ordering::Relaxed) {
        return Object::Error("Maximum call depth exceeded (out of stack)".to_string());
    }
    eval_block_statement(body, env)
}

fn is_truthy(obj: &Object) -> bool {
    match obj {
        Object::Integer(v) => *v != 0,
        Object::Null => false,
        Object::Error(_) => false,
        _ => true,
    }
}

fn eval_block_statement(statements: &[Statement], env: &mut Environment) -> Object {
    let mut result = Object::Null;
    for statement in statements {
        result = eval_statement(statement, env);
        match result {
            Object::ReturnValue(_) => return result,
            Object::Error(_) => return result,
            _ => {}
        }
    }
    result
}

fn eval_statement(statement: &Statement, env: &mut Environment) -> Object {
    match statement {
        Statement::Let { name, type_name: _, value } => {
            let val = eval_expression(value, env);
            if let Object::Error(_) = val {
                return val;
            }
            env.set(name.clone(), val.clone());
            val
        }
        Statement::Return(expr) => {
            let val = eval_expression(expr, env);
            if let Object::Error(_) = val { return val; }
            Object::ReturnValue(Box::new(val))
        }
        Statement::Assign { target, value } => {
            let val = eval_expression(value, env);
            if let Object::Error(_) = val { return val; }
            
            match target {
                Expression::Identifier(name) => {
                    if !env.update(name.clone(), val.clone()) {
                        return Object::Error(format!("Cannot assign to undefined variable '{}'", name));
                    }
                    val
                }
                Expression::PropertyAccess { object, property } => {
                    let obj = eval_expression(object, env);
                    if let Object::Error(_) = obj { return obj; }
                    match obj {
                        Object::StructInstance { name: _, fields } => {
                            if !fields.borrow().contains_key(property) {
                                return Object::Error(format!("Struct has no field '{}'", property));
                            }
                            fields.borrow_mut().insert(property.clone(), val.clone());
                            val
                        }
                        _ => Object::Error("Cannot assign property to non-struct object".to_string()),
                    }
                }
                _ => Object::Error("Invalid assignment target".to_string()),
            }
        }
        Statement::Expression(expr) => eval_expression(expr, env),
        Statement::Block(stmts) => eval_block_statement(stmts, env),
        Statement::Function { name, parameters, return_type: _, body } => {
            let func = Object::Function {
                parameters: Rc::new(parameters.clone()),
                body: Rc::new(body.clone()),
            };
            env.set(name.clone(), func);
            Object::Null
        }
        Statement::Import(path) => {
            let mut file_path = path.join("/");
            file_path.push_str(".ol");
            
            let content_res = read_module(&file_path);
            
            match content_res {
                Ok(content) => {
                    let scanner = crate::lexer::scanner::Scanner::new(&content);
                    let mut parser = crate::parser::parser::Parser::new(scanner);
                    let program = parser.parse_program();
                    
                    if !parser.errors.is_empty() {
                        return Object::Error(format!("Syntax error in imported module '{}': {:?}", file_path, parser.errors));
                    }
                    
                    let mut module_env = Environment::new();
                    let result = eval_program(&program, &mut module_env);
                    if let Object::Error(_) = result {
                        return result;
                    }
                    
                    let module_name = path.last().unwrap().clone();
                    let store = module_env.into_store();
                    env.set(module_name, Object::Module(Rc::new(store)));
                    Object::Null
                }
                Err(e) => Object::Error(format!("Failed to import '{}': {}", file_path, e)),
            }
        }
        Statement::Struct { name, fields } => {
            let def = Object::StructDefinition { name: name.clone(), fields: fields.clone() };
            env.set(name.clone(), def);
            Object::Null
        }
    }
}

fn eval_expression(expr: &Expression, env: &mut Environment) -> Object {
    match expr {
        Expression::Integer(val) => Object::Integer(*val),
        Expression::String(val) => Object::String(val.clone()),
        Expression::Ipv4(val) => Object::Ipv4(val.clone()),
        Expression::Identifier(name) => match env.get(name) {
            Some(val) => val,
            None => Object::Error(format!("Variable '{}' not found", name)),
        },
        Expression::FString(parts) => {
            let mut result = String::new();
            for part in parts {
                let val = eval_expression(part, env);
                if let Object::Error(_) = val { return val; }
                result.push_str(&val.to_string());
            }
            Object::String(result)
        }
        Expression::Array(elements) => {
            let mut arr = Vec::new();
            for el in elements {
                let val = eval_expression(el, env);
                if let Object::Error(_) = val { return val; }
                arr.push(val);
            }
            Object::Array(Rc::new(RefCell::new(arr)))
        }
        Expression::StructLiteral { name, fields } => {
            let def = env.get(name);
            match def {
                Some(Object::StructDefinition { name: def_name, fields: def_fields }) => {
                    let mut instance_fields = BTreeMap::new();
                    let mut provided = BTreeMap::new();
                    for (f_name, f_expr) in fields {
                        let val = eval_expression(f_expr, env);
                        if let Object::Error(_) = val { return val; }
                        provided.insert(f_name.clone(), val);
                    }
                    for (def_f_name, _def_f_type) in &def_fields {
                        if let Some(val) = provided.remove(def_f_name) {
                            instance_fields.insert(def_f_name.clone(), val);
                        } else {
                            return Object::Error(format!("Missing field '{}' in struct '{}'", def_f_name, def_name));
                        }
                    }
                    if !provided.is_empty() {
                        return Object::Error(format!("Unknown fields provided for struct '{}': {:?}", def_name, provided.keys()));
                    }
                    Object::StructInstance {
                        name: def_name.clone(),
                        fields: Rc::new(RefCell::new(instance_fields)),
                    }
                }
                Some(_) => Object::Error(format!("'{}' is not a struct", name)),
                None => Object::Error(format!("Unknown struct '{}'", name)),
            }
        }
        Expression::PropertyAccess { object, property } => {
            let obj = eval_expression(object, env);
            if let Object::Error(_) = obj { return obj; }
            match obj {
                Object::StructInstance { name: _, fields } => {
                    if let Some(val) = fields.borrow().get(property) {
                        val.clone()
                    } else {
                        Object::Error(format!("Struct has no field '{}'", property))
                    }
                }
                Object::Module(store) => {
                    if let Some(val) = store.get(property) {
                        val.clone()
                    } else {
                        Object::Error(format!("Module has no member '{}'", property))
                    }
                }
                _ => Object::Error("Property access is only supported on structs or modules".to_string()),
            }
        }
        Expression::Call { function, arguments } => {
            if function == "spawn" {
                if arguments.is_empty() { return Object::Error("spawn requires function name".to_string()); }
                let func_name_obj = eval_expression(&arguments[0], env);
                if let Object::Error(_) = func_name_obj { return func_name_obj; }
                let func_name = match func_name_obj {
                    Object::String(s) => s,
                    _ => return Object::Error("spawn arg 1 must be a string".to_string()),
                };
                let mut eval_args = Vec::new();
                for arg in arguments.iter().skip(1) {
                    let eval_arg = eval_expression(arg, env);
                    if let Object::Error(_) = eval_arg { return eval_arg; }
                    eval_args.push(eval_arg);
                }
                if let Some(Object::Function { parameters, body }) = env.get(&func_name) {
                    if eval_args.len() != parameters.len() {
                        return Object::Error(format!("Function '{}' expects {} args", func_name, parameters.len()));
                    }
                    let mut local_env = Environment::new_enclosed(env.clone());
                    for (i, param) in parameters.iter().enumerate() {
                        local_env.set(param.0.clone(), eval_args[i].clone());
                    }
                    // No threads: run the "spawned" function to completion right here.
                    let r = eval_block_statement(&body, &mut local_env);
                    if let Object::Error(_) = r { return r; }
                    return Object::Null;
                } else {
                    return Object::Error(format!("Cannot spawn unknown function: {}", func_name));
                }
            }
            
            let mut eval_args = Vec::new();
            for arg in arguments {
                let eval_arg = eval_expression(arg, env);
                if let Object::Error(_) = eval_arg { return eval_arg; }
                eval_args.push(eval_arg);
            }
            
            if let Some(Object::Function { parameters, body }) = env.get(function) {
                if eval_args.len() != parameters.len() {
                    return Object::Error(format!("Function '{}' expects {} arguments, got {}", function, parameters.len(), eval_args.len()));
                }
                
                let mut local_env = Environment::new_enclosed(env.clone());
                
                for (i, param) in parameters.iter().enumerate() {
                    local_env.set(param.0.clone(), eval_args[i].clone());
                }
                
                let result = call_body(&body, &mut local_env);
                if let Object::ReturnValue(val) = result {
                    return *val;
                }
                result
            } else {
                crate::evaluator::builtins::eval_builtin(function, eval_args)
            }
        }
        Expression::ArrayAllocation { element_type, size } => {
            if element_type != "byte" {
                return Object::Error(format!("Only byte arrays are supported currently, requested: {}", element_type));
            }
            let size_obj = eval_expression(size, env);
            let size_int = match size_obj {
                Object::Integer(s) => s as usize,
                _ => return Object::Error("Array size must be integer".to_string()),
            };
            Object::ByteArray(Rc::new(RefCell::new(vec![0; size_int])))
        }
        Expression::StaticMethodCall { class_name, method_name, arguments } => {
            let mut eval_args = Vec::new();
            for arg in arguments {
                let eval_arg = eval_expression(arg, env);
                if let Object::Error(_) = eval_arg { return eval_arg; }
                eval_args.push(eval_arg);
            }
            
            if let Some(Object::Module(store)) = env.get(class_name) {
                if let Some(Object::Function { parameters, body }) = store.get(method_name) {
                    if eval_args.len() != parameters.len() {
                        return Object::Error(format!("Function '{}::{}' expects {} arguments, got {}", class_name, method_name, parameters.len(), eval_args.len()));
                    }
                    
                    let mut local_env = Environment::new();
                    for (k, v) in store.iter() {
                        local_env.set(k.clone(), v.clone());
                    }
                    for (i, param) in parameters.iter().enumerate() {
                        local_env.set(param.0.clone(), eval_args[i].clone());
                    }
                    
                    let result = call_body(&body, &mut local_env);
                    if let Object::ReturnValue(val) = result {
                        return *val;
                    }
                    return result;
                } else {
                    return Object::Error(format!("Method '{}' not found in module '{}'", method_name, class_name));
                }
            }
            
            if class_name == "File" && method_name == "read_to_string" {
                if eval_args.len() != 1 { return Object::Error("File::read_to_string expects 1 argument".to_string()); }
                if let Object::String(path) = &eval_args[0] {
                    return match read_module_or_file(path) {
                        Ok(content) => Object::String(content),
                        Err(e) => Object::Error(format!("Failed to read file '{}': {}", path, e)),
                    };
                }
                Object::Error("File::read_to_string path must be string".to_string())
            } else if class_name == "File" && method_name == "write_to_string" {
                if eval_args.len() != 2 { return Object::Error("File::write_to_string expects 2 arguments".to_string()); }
                if let (Object::String(path), Object::String(content)) = (&eval_args[0], &eval_args[1]) {
                    return match crate::sys::write_file(path, content) {
                        Ok(_) => Object::Integer(content.len() as i64),
                        Err(e) => Object::Error(format!("Failed to write file '{}': {}", path, e)),
                    };
                }
                Object::Error("File::write_to_string args must be strings".to_string())
            } else if class_name == "Command" && method_name == "run" {
                Object::Error("Command::run failed: running other programs is not available to programs yet".to_string())
            } else if class_name == "TcpListener" && method_name == "bind" {
                Object::Error(format!("TcpListener::bind failed: {}", NO_NET))
            } else {
                Object::Error(format!("Unknown static method {}::{}", class_name, method_name))
            }
        }
        Expression::MethodCall { object, method_name, arguments } => {
            let obj = eval_expression(object, env);
            if let Object::Error(_) = obj { return obj; }

            // Arguments are evaluated before any borrow of the receiver is taken.
            let mut args = Vec::new();
            for a in arguments {
                let v = eval_expression(a, env);
                if let Object::Error(_) = v { return v; }
                args.push(v);
            }

            match obj {
                Object::String(text) => {
                    if method_name == "len" {
                        Object::Integer(text.chars().count() as i64)
                    } else if method_name == "char_at" {
                        if args.len() != 1 { return Object::Error("char_at expects 1 argument".to_string()); }
                        match &args[0] {
                            Object::Integer(idx) => {
                                let i = *idx as usize;
                                match text.chars().nth(i) {
                                    Some(c) if *idx >= 0 => Object::String(c.to_string()),
                                    _ => Object::String(String::new()),
                                }
                            }
                            _ => Object::Error("char_at index must be integer".to_string())
                        }
                    } else if method_name == "substring" {
                        if args.len() != 2 { return Object::Error("substring expects 2 args".to_string()); }
                        if let (Object::Integer(start), Object::Integer(end)) = (&args[0], &args[1]) {
                            let chars: Vec<char> = text.chars().collect();
                            if *start >= 0 && start <= end && (*end as usize) <= chars.len() {
                                let sub: String = chars[*start as usize..*end as usize].iter().collect();
                                Object::String(sub)
                            } else {
                                Object::String(String::new())
                            }
                        } else {
                            Object::Error("substring arguments must be integers".to_string())
                        }
                    } else {
                        Object::Error(format!("Unknown method {} on String", method_name))
                    }
                }
                Object::ByteArray(buf_rc) => {
                    if method_name == "to_string" {
                        if args.len() != 1 { return Object::Error("to_string expects 1 argument (size)".to_string()); }
                        match &args[0] {
                            Object::Integer(size) => {
                                let buf = buf_rc.borrow();
                                let s = (*size).max(0) as usize;
                                let s = s.min(buf.len());
                                Object::String(String::from_utf8_lossy(&buf[0..s]).into_owned())
                            }
                            _ => Object::Error("to_string argument must be integer".to_string()),
                        }
                    } else {
                        Object::Error(format!("Unknown method {} on ByteArray", method_name))
                    }
                }
                Object::Array(arr_rc) => {
                    if method_name == "push" {
                        if args.len() != 1 { return Object::Error("push expects 1 argument".to_string()); }
                        arr_rc.borrow_mut().push(args.remove(0));
                        Object::Null
                    } else if method_name == "len" {
                        Object::Integer(arr_rc.borrow().len() as i64)
                    } else if method_name == "get" {
                        if args.len() != 1 { return Object::Error("get expects 1 argument".to_string()); }
                        if let Object::Integer(i) = args[0] {
                            let arr = arr_rc.borrow();
                            if i >= 0 && (i as usize) < arr.len() {
                                arr[i as usize].clone()
                            } else {
                                Object::Error(format!("Index out of bounds: {}", i))
                            }
                        } else {
                            Object::Error("get index must be integer".to_string())
                        }
                    } else {
                        Object::Error(format!("Unknown method {} on Array", method_name))
                    }
                }
                _ => Object::Error("Method calls not supported on this object".to_string()),
            }
        }
        Expression::Infix { left, operator, right } => {
            // Short-circuit for AND / OR
            if operator == "&&" {
                let left_val = eval_expression(left, env);
                if let Object::Error(_) = left_val { return left_val; }
                if !is_truthy(&left_val) { return Object::Integer(0); }
                let right_val = eval_expression(right, env);
                if let Object::Error(_) = right_val { return right_val; }
                return if is_truthy(&right_val) { Object::Integer(1) } else { Object::Integer(0) };
            }
            if operator == "||" {
                let left_val = eval_expression(left, env);
                if let Object::Error(_) = left_val { return left_val; }
                if is_truthy(&left_val) { return Object::Integer(1); }
                let right_val = eval_expression(right, env);
                if let Object::Error(_) = right_val { return right_val; }
                return if is_truthy(&right_val) { Object::Integer(1) } else { Object::Integer(0) };
            }

            let left_val = eval_expression(left, env);
            if let Object::Error(_) = left_val { return left_val; }
            let right_val = eval_expression(right, env);
            if let Object::Error(_) = right_val { return right_val; }
            match (left_val, right_val) {
                (Object::Integer(l), Object::Integer(r)) => {
                    match operator.as_str() {
                        "+" => Object::Integer(l.wrapping_add(r)),
                        "-" => Object::Integer(l.wrapping_sub(r)),
                        "*" => Object::Integer(l.wrapping_mul(r)),
                        "/" => if r == 0 { Object::Error("Division by zero".to_string()) } else { Object::Integer(l.wrapping_div(r)) },
                        ">" => if l > r { Object::Integer(1) } else { Object::Integer(0) },
                        "<" => if l < r { Object::Integer(1) } else { Object::Integer(0) },
                        "==" => if l == r { Object::Integer(1) } else { Object::Integer(0) },
                        _ => Object::Error(format!("Unknown operator {}", operator)),
                    }
                }
                (Object::String(l), Object::String(r)) => {
                    match operator.as_str() {
                        "==" => if l == r { Object::Integer(1) } else { Object::Integer(0) },
                        "+" => Object::String(format!("{}{}", l, r)),
                        _ => Object::Error(format!("Unknown string operator {}", operator)),
                    }
                }
                _ => Object::Error("Infix expressions support integers and strings currently".to_string()),
            }
        }
        Expression::If { condition, consequence, alternative } => {
            let cond_val = eval_expression(condition, env);
            if is_truthy(&cond_val) {
                eval_statement(consequence, env)
            } else if let Some(alt) = alternative {
                eval_statement(alt, env)
            } else {
                Object::Null
            }
        }
        Expression::Loop { body } => {
            loop {
                let res = eval_statement(body, env);
                match res {
                    Object::ReturnValue(_) => return res,
                    Object::Error(_) => return res,
                    _ => {}
                }
            }
        }
        _ => Object::Error(format!("Expression not supported by evaluator: {:?}", expr)),
    }
}

/// `File::read_to_string`: the path as given, then (for relative paths) the olang system directories.
fn read_module_or_file(path: &str) -> Result<String, String> {
    match crate::sys::read_file(path) {
        Ok(c) => Ok(c),
        Err(e) => {
            if path.starts_with('/') { Err(e) } else { read_module(path).map_err(|_| e) }
        }
    }
}
