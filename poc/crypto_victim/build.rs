fn main() {
    // set linker flags for kyber
    #[cfg(all(feature="kyber", target_os = "macos"))]
    println!("cargo:rustc-link-arg=-lcrypto");
    #[cfg(all(feature="kyber", target_os = "macos"))]
    println!("cargo:rustc-link-arg=-L/opt/homebrew/opt/openssl@3/lib");
}