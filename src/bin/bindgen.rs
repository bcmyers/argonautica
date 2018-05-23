#[cfg(feature = "development")]
extern crate bindgen;

#[cfg(feature = "development")]
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

#[cfg(not(feature = "development"))]
fn main() {
    println!("To run the bindgen bin, use --features development");
}
