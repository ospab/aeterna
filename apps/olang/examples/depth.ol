# depth.ol: deep recursion works (the interpreter runs on its own 2 MiB stack); running out of stack is a runtime error, not a crash
fn down(n: int) -> int {
    if n == 0 {
        return 0
    }
    return down(n - 1) + 1
}
print("down(150) =", down(150))
print("down(500) =", down(500))
