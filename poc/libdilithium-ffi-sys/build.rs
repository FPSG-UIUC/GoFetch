fn main() {
    let path = "./src";
    let lib = "dilithium";

    println!("cargo:rustc-link-search=native={}", path);
    println!("cargo:rustc-link-lib=static={}", lib);
}