extern crate bindgen;

fn main() {
    let bindings = bindgen::Builder::default()
        .header("include/argon2.h")
        .header("include/encoding.h")
        .layout_tests(false)
        .rustfmt_bindings(false)
        .generate()
        .expect("failed to generate bindings");
    bindings
        .write_to_file("./bindings.rs")
        .expect("failed write bindings");
}
