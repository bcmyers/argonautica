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
    let out_dir = Path::new(&out_dir);
    let bindings = bindgen::Builder::default()
        .header("include/argon2.h")
        .header("include/encoding.h")
        .layout_tests(true)
        .rustfmt_bindings(false)
        .generate()
        .expect("failed to generate bindings");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed write bindings");
}
