fn main() {
    let mut buf = itoa::Buffer::new();
    println!("{}", buf.format(42));
}
