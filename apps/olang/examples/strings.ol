# strings.ol (from the olang project: test4.ol): string methods, || and &&
let s = "Hello, world!"
print("Length:", s.len())
print("First char:", s.char_at(0))
print("Substring 0-5:", s.substring(0, 5))

let x = 1
let y = 0
if x == 1 || y == 1 {
    print("OR works!")
}
if x == 1 && y == 0 {
    print("AND works!")
}

let sumstr = "Hello" + " " + "World"
print(sumstr)
