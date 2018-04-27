extern crate bindgen;
extern crate cc;

use std::env;
use std::fs;
use std::path::Path;

#[cfg_attr(rustfmt, rustfmt_skip)]
fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);
    if out_dir.exists() {
        fs::remove_dir_all(out_dir).unwrap();
    }
    fs::create_dir_all(out_dir).unwrap();

    let base_dir = Path::new("/Users/bcmyers/dev/a2");
    cc::Build::new()
        .files(&[
            base_dir.join("external/phc-winner-argon2/src/argon2.c"),
            base_dir.join("external/phc-winner-argon2/src/bench.c"),
            base_dir.join("external/phc-winner-argon2/src/core.c"),
            base_dir.join("external/phc-winner-argon2/src/blake2/blake2b.c"),
            base_dir.join("external/phc-winner-argon2/src/encoding.c"),
            base_dir.join("external/phc-winner-argon2/src/genkat.c"),
            // base_dir.join("external/phc-winner-argon2/src/opt.c"),
            base_dir.join("external/phc-winner-argon2/src/ref.c"),
            base_dir.join("external/phc-winner-argon2/src/run.c"),
            base_dir.join("external/phc-winner-argon2/src/test.c"),
            base_dir.join("external/phc-winner-argon2/src/thread.c"),
        ])
        .flag_if_supported("-pthread")
        .flag_if_supported("-std=c89")
        .flag_if_supported("-O3")
        .flag_if_supported("-Wall")
        .flag_if_supported("-g")
        .include(base_dir.join("include/"))
        .warnings(true)
        .compile("argon2");

    let bindings = bindgen::Builder::default()
        .header("include/argon2.h")
        .rustfmt_bindings(false)
        .rust_target(bindgen::RustTarget::Stable_1_25)
        .layout_tests(true)
        .generate()
        .expect("failed to generate bindings");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed write bindings");
}
