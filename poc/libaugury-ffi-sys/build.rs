use cc;

fn main() {
    let src = [
        "src/c_augury.c"
    ];

    let mut builder = cc::Build::new();
    let build = builder
        .files(src.iter())
        .include("src")
        .static_flag(true)
        .target("aarch64-apple-darwin");

    build.compile("augury-ffi");
}
