extern crate bindgen;
extern crate cc;

use std::env;
use std::path::Path;

fn main() {
    let mut builder = cc::Build::new();
    builder
        .files(&[
            "phc-winner-argon2/src/argon2.c",
            "phc-winner-argon2/src/core.c",
            "phc-winner-argon2/src/blake2/blake2b.c",
            "phc-winner-argon2/src/encoding.c",
            "phc-winner-argon2/src/ref.c",
            "phc-winner-argon2/src/thread.c",
        ])
        .include("include")
        .flag_if_supported("-g")
        .flag_if_supported("-O3")
        .flag_if_supported("-pthread")
        .flag_if_supported("-std=c89")
        .warnings(false)
        .extra_warnings(false)
        .compile("argon2");

    let out_dir = env::var("OUT_DIR").unwrap();
    let path = Path::new(&out_dir).join("bindings.rs");
    let bindings = bindgen::Builder::default()
        .header("include/argon2.h")
        .header("include/encoding.h")
        .whitelist_function("argon2_ctx")
        .whitelist_function("argon2_encodedlen")
        .whitelist_function("argon2_verify_ctx")
        .whitelist_function("decode_string")
        .whitelist_function("encode_string")
        .whitelist_type("Argon2_ErrorCodes")
        // .blacklist_type("max_align_t")
        .layout_tests(true)
        .rustfmt_bindings(false)
        .generate()
        .expect("Build failed. Failed to generate bindings");
    bindings
        .write_to_file(path)
        .expect("Build failed. Failed write bindings");
}
