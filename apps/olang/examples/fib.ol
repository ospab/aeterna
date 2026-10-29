# fib.ol: recursion and the call depth limit
fn fib(n: int) -> int {
    if n < 2 {
        return n
    }
    return fib(n - 1) + fib(n - 2)
}

let t0 = time()
print("fib(15) =", fib(15))
print("took ms:", time() - t0)
