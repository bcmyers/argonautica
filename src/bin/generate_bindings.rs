extern crate bindgen;
extern crate failure;
extern crate tempdir;

use std::fs;
use std::io::Write;
use std::path::Path;

fn main() -> Result<(), failure::Error> {
    // Create temp dir
    let temp = tempdir::TempDir::new("a2")?;
    let temp_dir = temp.path();
    let temp_dir_str = temp_dir.to_str().unwrap();

    // Write blake2.h to temp dir
    let blake2_header = fs::read_to_string("phc-winner-argon2/src/blake2/blake2.h")?;
    let blake2_header = blake2_header.replace("#include <argon2.h>", "#include \"argon2.h\"");
    {
        let mut file = fs::File::create(temp_dir.join("blake2.h"))?;
        file.write_all(blake2_header.as_bytes())?;
    }

    // Write other headers to temp dir
    for header_path_str in &[
        "phc-winner-argon2/include/argon2.h",
        "phc-winner-argon2/src/core.h",
        "phc-winner-argon2/src/encoding.h",
        "phc-winner-argon2/src/thread.h",
        "phc-winner-argon2/src/blake2/blake2-impl.h",
        // "phc-winner-argon2/src/blake2/blamka-round-opt.h",
        "phc-winner-argon2/src/blake2/blamka-round-ref.h",
    ] {
        let header_path = Path::new(*header_path_str);
        let header_filename = header_path.file_name().unwrap();
        let from = header_path;
        let to = temp_dir.join(header_filename);
        fs::copy(from, to)?;
    }

    // Create bindings
    let builder = bindgen::Builder::default()
        .header(format!("{}/argon2.h", temp_dir_str))
        .header(format!("{}/core.h", temp_dir_str))
        .header(format!("{}/encoding.h", temp_dir_str))
        .header(format!("{}/thread.h", temp_dir_str))
        .header(format!("{}/blake2-impl.h", temp_dir_str))
        .header(format!("{}/blake2.h", temp_dir_str))
        // .header(format!("{}/blamka-round-opt.h", temp_dir_str))
        .header(format!("{}/blamka-round-ref.h", temp_dir_str))
        .clang_arg("-std=c89")
        .ctypes_prefix("libc")
        .layout_tests(false)
        .rust_target(bindgen::RustTarget::Stable_1_25)
        .rustfmt_bindings(true);
    // println!("{:#?}", builder.command_line_flags());
    let bindings = builder
        .generate()
        .map_err(|_| failure::err_msg("failed to generate bindings"))?;

    // Write bindings to disk
    bindings.write_to_file("./bindings.rs")?;

    Ok(())
}
