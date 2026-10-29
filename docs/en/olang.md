# olang on ospab.os

`ol` is the interpreter of the olang language (the owner's own language) as a ring-3 program.
It is a no_std + alloc port of the olang lexer, parser and tree-walking evaluator; the source is in
`apps/olang/` (each copied file names its origin in the olang project in a header comment).

## Install and run

```
# tomato install olang
# ol script.ol [args...]      run a script; args() returns the arguments
# ol -e 'print(1 + 2)'        evaluate a string
# ol                          REPL: ">>> " prompt, reads stdin; "... " continues an open { ( [
```

Errors print the line and column (syntax errors) or the line of the failing top-level statement
(runtime errors), and the exit status is 1. `$?` in plum is the exit status; a script can set it
with `exit(n)`. Example scripts are in `/usr/share/olang/examples/` (`hello`, `fib`, `structs`,
`strings`, `modules`, `readfile`, `depth`, `net`).

## Language

Unchanged from the original: `let`, `fn`, `struct` / `new`, `if` / `else`, `loop`, `return`,
integers, strings, f-strings (`f"{x}"`), arrays, `byte[n]`, `ipv4` literals, `&&` `||`, and `import
a::b`. See the olang `docs/language_guide.md` and `docs/standard_library.md`.

Built-ins that work: `print`, `time`, `File::read_to_string`, `File::write_to_string`, string methods
(`len`, `char_at`, `substring`), array methods (`push`, `len`, `get`), `byte[n].to_string(n)`,
`std::math` (`abs`, `pow`). Additions for the OS: `args()`, `exit(code)`, `input(prompt)` (one line
from stdin, `null` at end of input).

`import a::b` reads `a/b.ol` relative to the current directory, then from `/usr/share/olang/` and
`/usr/lib/olang/` (the package installs `std/math.ol` there).

## Differences from the original

- No JIT (`--vm`): the Cranelift backend needs `std` and executable memory, which ring 3 does not
  get (W^X). Only the interpreter exists. The `build` / `check` commands and bundling a script into
  an executable are not ported either.
- No networking yet: `listen`, `accept`, `read`, `write`, `close`, `TcpListener::bind` stay in the
  language but fail with the runtime error "networking is not available to programs yet". Ring-3
  sockets arrive with the network server. `Command::run` fails the same way (no way to start a
  program from a program yet).
- Synchronous: no tokio. `spawn("f", args)` runs `f` to completion in place instead of on a green
  thread.
- `time()` returns milliseconds since boot (the original returns Unix time).
- Scopes are shared instead of copied on every call. The original cloned the whole scope chain per
  call (quadratic memory for recursion), so assigning to an outer variable from inside a function
  was lost; here it takes effect.
- Division by zero is a runtime error instead of a crash; integer overflow wraps.
- Calls nest as deep as the interpreter stack allows (2 MiB, about 500+ levels of simple
  recursion); beyond that you get a runtime error. The program heap is 4 MiB (liboos), so large
  arrays or strings run out of memory quickly.
- Struct fields print in alphabetical order (BTreeMap instead of HashMap).
- Files go through the VFS syscalls: `File::write_to_string` writes with open mode 1; stdin is
  read one byte at a time, so the REPL line editor only supports Backspace.

## Examples

```
# ol -e 'print(f"{6 * 7} from ol")'
42 from ol
# ol /usr/share/olang/examples/structs.ol
# echo 'print(40 + 2)' | ol
```
