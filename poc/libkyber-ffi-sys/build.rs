use cc;

fn main() {
    let src = [
        "src/cbd.c",
        "src/fips202.c",
        "src/indcpa.c",
        "src/kem.c",
        "src/ntt.c",
        "src/poly.c",
        "src/polyvec.c",
        "src/reduce.c",
        "src/rng.c",
        "src/verify.c",
        "src/symmetric-shake.c"
    ];

    let mut builder = cc::Build::new();
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    let build = builder
        .files(src.iter())
        .include("src")
        .include("/opt/homebrew/opt/openssl@3/include")
        .flag("-fomit-frame-pointer")
        .define("PRINT", "1")
        .target("aarch64-apple-darwin");
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    let build = builder
        .files(src.iter())
        .include("src")
        .flag("-fomit-frame-pointer")
        .define("PRINT", "1")
        .target("aarch64-unknown-linux-gnu");

    build.compile("kyber-ffi");
}


