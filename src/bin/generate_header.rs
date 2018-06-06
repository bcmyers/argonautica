extern crate cbindgen;

use std::env::current_dir;

fn main() {
    let crate_dir = current_dir().unwrap();
    let path = crate_dir.join("argonautica.h");
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_documentation(false)
        .with_language(cbindgen::Language::C)
        .generate()
        .expect("failed to generate argonautica.h")
        .write_to_file(path);
}
