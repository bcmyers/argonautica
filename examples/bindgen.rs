extern crate bindgen;

use std::fs;
use std::path::Path;

fn main() {
    let out_dir = Path::new("./data");
    if out_dir.exists() {
        fs::remove_dir_all(out_dir).unwrap();
    }
    fs::create_dir_all(out_dir).unwrap();
    let bindings = bindgen::Builder::default()
        .header("include/argon2.h")
        .layout_tests(false)
        .rustfmt_bindings(false)
        .generate()
        .expect("failed to generate bindings");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed write bindings");
}
