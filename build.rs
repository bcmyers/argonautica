extern crate bindgen;
extern crate cc;

use std::env;
use std::path::PathBuf;

fn main() {
    cc::Build::new()
        .file("src/foo.c")
        .define("FOO", Some("bar"))
        .include("src")
        .compile("foo");


    println!("cargo:rustc-link-lib=argon2");
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .generate()
        .expect("failed to generate bindings");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed write bindings");
}
