fn main() {
    let str1 = String::new();

    str1.push_str("hello");
    let s1 = &str1;
    println!("{}", str1);
}
