// SPDX-License-Identifier: AGPL-3.0-only
//! Process start-up. The kernel enters `_start` with RSP pointing at:
//! argc, argv[0..argc], NULL, envp..., NULL, auxv pairs..., AT_NULL.

/// Command-line arguments as passed by the kernel.
#[derive(Clone, Copy)]
pub struct Args {
    argc: usize,
    argv: *const *const u8,
}

impl Args {
    pub fn len(&self) -> usize {
        self.argc
    }

    pub fn is_empty(&self) -> bool {
        self.argc == 0
    }

    /// Argument `i`, if present and valid UTF-8.
    pub fn get(&self, i: usize) -> Option<&'static str> {
        if i >= self.argc {
            return None;
        }
        // SAFETY: the kernel placed argc valid, NUL-terminated pointers on the stack.
        unsafe {
            let p = *self.argv.add(i);
            let mut n = 0;
            while *p.add(n) != 0 {
                n += 1;
            }
            core::str::from_utf8(core::slice::from_raw_parts(p, n)).ok()
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &'static str> + '_ {
        (0..self.argc).filter_map(move |i| self.get(i))
    }
}

extern "Rust" {
    fn __oos_main(args: Args) -> i32;
}

/// Entry point. Pass the initial stack pointer to Rust and keep the stack 16-byte aligned.
#[no_mangle]
#[link_section = ".text._start"]
#[unsafe(naked)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, rsp",
        "and rsp, -16",
        "call {}",
        "ud2",
        sym start_rust,
    );
}

unsafe extern "C" fn start_rust(sp: *const u64) -> ! {
    let args = Args {
        argc: *sp as usize,
        argv: sp.add(1) as *const *const u8,
    };
    crate::heap::init();
    let code = __oos_main(args);
    crate::exit(code)
}
