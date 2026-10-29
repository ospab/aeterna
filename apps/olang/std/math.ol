# std/math.ol (from the olang project: src/std/math.ol)
# olang Standard Math Library

fn abs(val: int) -> int {
    if val < 0 {
        return 0 - val
    }
    return val
}

fn pow(base: int, exp: int) -> int {
    let result = 1
    let i = 0
    loop {
        if i == exp {
            return result
        }
        let result = result * base
        let i = i + 1
    }
    return result
}
