// Ported from the olang project: src/evaluator/env.rs (HashMap -> BTreeMap for no_std).
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;
use crate::evaluator::object::Object;

// OS port: scopes are shared with Rc instead of deep-cloned on every call. The original
// cloned the whole scope chain per function call, which is quadratic in memory for
// recursion (the ring-3 heap is 4 MiB) and made assignments to outer variables from
// inside a function vanish; with shared scopes they now take effect.
#[derive(Debug)]
struct Scope {
    store: BTreeMap<String, Object>,
    outer: Option<Environment>,
}

#[derive(Debug, Clone)]
pub struct Environment(Rc<RefCell<Scope>>);

impl Environment {
    pub fn new() -> Self {
        Environment(Rc::new(RefCell::new(Scope { store: BTreeMap::new(), outer: None })))
    }

    pub fn new_enclosed(outer: Environment) -> Self {
        Environment(Rc::new(RefCell::new(Scope { store: BTreeMap::new(), outer: Some(outer) })))
    }

    pub fn get(&self, name: &str) -> Option<Object> {
        let scope = self.0.borrow();
        match scope.store.get(name) {
            Some(val) => Some(val.clone()),
            None => match &scope.outer {
                Some(outer) => outer.get(name),
                None => None,
            },
        }
    }

    pub fn set(&mut self, name: String, val: Object) {
        self.0.borrow_mut().store.insert(name, val);
    }

    pub fn update(&mut self, name: String, val: Object) -> bool {
        let mut scope = self.0.borrow_mut();
        if scope.store.contains_key(&name) {
            scope.store.insert(name, val);
            true
        } else if let Some(outer) = &mut scope.outer {
            outer.update(name, val)
        } else {
            false
        }
    }

    pub fn into_store(self) -> BTreeMap<String, Object> {
        self.0.borrow().store.clone()
    }
}
