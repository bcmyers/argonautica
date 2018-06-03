extern crate bindgen;
extern crate cc;
extern crate failure;
extern crate tempdir;

use std::env;
use std::fs;
use std::path::Path;

#[cfg(feature = "without_simd")]
const BLAKE2_IMPLEMENTATION: &str = "phc-winner-argon2/src/ref.c";

#[cfg(not(feature = "without_simd"))]
const BLAKE2_IMPLEMENTATION: &str = "phc-winner-argon2/src/opt.c";

fn main() -> Result<(), failure::Error> {
    let temp = tempdir::TempDir::new("a2")?;
    let temp_dir = temp.path();
    let temp_dir_str = temp_dir.to_str().unwrap();
    for header_path_str in &[
        "phc-winner-argon2/include/argon2.h",
        "phc-winner-argon2/src/core.h",
        "phc-winner-argon2/src/encoding.h",
        "phc-winner-argon2/src/thread.h",
        "phc-winner-argon2/src/blake2/blake2-impl.h",
        "phc-winner-argon2/src/blake2/blake2.h",
        "phc-winner-argon2/src/blake2/blamka-round-opt.h",
        "phc-winner-argon2/src/blake2/blamka-round-ref.h",
    ] {
        let header_path = Path::new(*header_path_str);
        let header_filename = header_path.file_name().unwrap();
        let from = header_path;
        let to = temp_dir.join(header_filename);
        fs::copy(from, to)?;
    }

    let mut builder = cc::Build::new();
    builder
        .files(&[
            "phc-winner-argon2/src/argon2.c",
            "phc-winner-argon2/src/core.c",
            "phc-winner-argon2/src/blake2/blake2b.c",
            "phc-winner-argon2/src/encoding.c",
            "phc-winner-argon2/src/thread.c",
            BLAKE2_IMPLEMENTATION,
        ])
        .include(temp_dir)
        .flag_if_supported("-pthread")
        .flag_if_supported("-std=c89")
        .warnings(false)
        .extra_warnings(false);
    let opt_level = env::var("OPT_LEVEL")?.parse::<usize>()?;
    if opt_level < 3 {
        builder.flag_if_supported("-g");
    }
    builder.compile("argon2");

    let out_dir_str = env::var("OUT_DIR")?;
    let out_path = Path::new(&out_dir_str).join("bindings.rs");
    let bindings = bindgen::Builder::default()
        .header(format!("{}/argon2.h", temp_dir_str))
        .header(format!("{}/encoding.h", temp_dir_str))
        .whitelist_function("argon2_ctx")
        .whitelist_function("argon2_encodedlen")
        .whitelist_function("argon2_error_message")
        .whitelist_function("argon2_verify_ctx")
        .whitelist_function("decode_string")
        .whitelist_function("encode_string")
        .whitelist_type("Argon2_ErrorCodes")
        .ctypes_prefix("libc")
        .layout_tests(true)
        .raw_line("use libc;")
        .rust_target(bindgen::RustTarget::Stable_1_25) // TODO: Update when 1.26 is available
        .rustfmt_bindings(false)
        .generate()
        .map_err(|_| failure::err_msg("failed to generate bindings"))?;
    bindings.write_to_file(out_path)?;
    Ok(())
}
