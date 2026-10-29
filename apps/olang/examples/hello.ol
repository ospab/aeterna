# hello.ol: variables, f-strings, arrays, time()
let name = "ospab.os"
print("Hello from olang on", name)
let items = ["one", "two"]
items.push("three")
print(f"{items.len()} items: {items}")
print("uptime ms:", time())
print("args:", args())
