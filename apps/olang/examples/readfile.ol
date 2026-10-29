# readfile.ol: File::read_to_string and File::write_to_string
let n = File::write_to_string("/tmp/olang-demo.txt", "written by olang\n")
print("wrote bytes:", n)
let text = File::read_to_string("/tmp/olang-demo.txt")
print("read back:", text)
print("length:", text.len())
