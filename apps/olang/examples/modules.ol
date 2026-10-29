# modules.ol (from the olang project: test2.ol): import of std::math
# Testing module imports!

import std::math

let negative = 0 - 42
print("Negative:", negative)

let absolute = math::abs(negative)
print("Absolute value using math::abs:", absolute)

let base = 2
let exp = 10
let power = math::pow(base, exp)
print(f"{base} ^ {exp} = {power}")
