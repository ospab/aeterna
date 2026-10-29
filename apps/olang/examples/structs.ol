# structs.ol (from the olang project: test3.ol): structs, field assignment, loop
# Testing structs and assignments!

struct Token {
    token_type: string,
    line: int,
    column: int
}

print("--- Testing Struct Initialization ---")
let t = new Token {
    token_type: "Ident",
    line: 1,
    column: 5
}
print("Token type:", t.token_type)
print("Line:", t.line)

print("\n--- Testing Struct Mutation ---")
t.line = 10
t.token_type = "Keyword"
print("Mutated type:", t.token_type)
print("Mutated line:", t.line)

print("\n--- Testing Variable Reassignment ---")
let i = 0
loop {
    if i == 3 {
        return 0
    }
    print("Loop iteration:", i)
    # Using our new assignment operator!
    i = i + 1
}
