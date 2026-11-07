fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.ends_with("-linux-gnu") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
    } else if target.contains("apple-darwin") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path");
    }
}
