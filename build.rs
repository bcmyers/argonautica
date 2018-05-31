extern crate bindgen;
extern crate cc;
extern crate failure;

use std::env;
use std::path::Path;

#[cfg(feature = "without_simd")]
const IMPLEMENTATION: &str = "phc-winner-argon2/src/ref.c";

#[cfg(not(feature = "without_simd"))]
const IMPLEMENTATION: &str = "phc-winner-argon2/src/opt.c";

fn main() -> Result<(), failure::Error> {
    let opt_level = env::var("OPT_LEVEL")?.parse::<usize>()?;
    let mut builder = cc::Build::new();
    builder
        .files(&[
            "phc-winner-argon2/src/argon2.c",
            "phc-winner-argon2/src/core.c",
            "phc-winner-argon2/src/blake2/blake2b.c",
            "phc-winner-argon2/src/encoding.c",
            "phc-winner-argon2/src/thread.c",
            IMPLEMENTATION,
        ])
        .include("include")
        .flag_if_supported("-pthread")
        .flag_if_supported("-std=c89")
        .warnings(false)
        .extra_warnings(false);
    if opt_level < 3 {
        builder.flag_if_supported("-g");
    }
    builder.compile("argon2");

    let out_dir = env::var("OUT_DIR")?;
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
        .layout_tests(true)
        .rustfmt_bindings(false)
        .generate()
        .map_err(|_| failure::err_msg("failed to generate bindings"))?;
    bindings.write_to_file(path)?;
    Ok(())
}
