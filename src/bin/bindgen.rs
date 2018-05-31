#[cfg(feature = "development")]
extern crate bindgen;

#[cfg(feature = "development")]
#[macro_use]
extern crate failure;

#[cfg(feature = "development")]
fn main() -> Result<(), failure::Error> {
    let bindings = bindgen::Builder::default()
        .header("include/argon2.h")
        .header("include/encoding.h")
        .layout_tests(false)
        .rustfmt_bindings(true)
        .generate()
        .map_err(|e| format_err!("{:?}", e))?;
    bindings.write_to_file("./bindings.rs")?;
    Ok(())
}

#[cfg(not(feature = "development"))]
fn main() {}
