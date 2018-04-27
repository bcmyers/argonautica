extern crate bindgen;

fn main() {
    let bindings = bindgen::Builder::default()
        .header("/Users/bcmyers/dev/passwords/a2/wrapper.h")
        .rust_target(bindgen::RustTarget::Stable_1_25)
        .layout_tests(false)
        .generate()
        .expect("failed to generate bindings");
    bindings
        .write_to_file("./a2/data/bindings.rs")
        .expect("failed write bindings");
}
