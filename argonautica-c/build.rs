extern crate cbindgen;

use std::path::Path;

fn main() {
    // let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let bindings = cbindgen::Builder::new()
        .with_crate(".")
        .with_language(cbindgen::Language::C)
        .generate()
        .expect("Unable to generate bindings");
    bindings.write_to_file("include/argonautica.h");

    let dir = Path::new("../argonautica-py/argonautica");
    if dir.exists() {
        let path = dir.join("argonautica.h");
        bindings.write_to_file(&path);
    }
}
