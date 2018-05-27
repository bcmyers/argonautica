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
        .whitelist_function("argon2_ctx")
        .whitelist_function("argon2_encodedlen")
        .whitelist_function("argon2_verify_ctx")
        .whitelist_function("decode_string")
        .whitelist_function("encode_string")
        .whitelist_type("Argon2_ErrorCodes")
        .layout_tests(false)
        .rustfmt_bindings(true)
        .generate()
        .map_err(|e| format_err!("{:?}", e))?;
    bindings.write_to_file("./bindings.rs")?;
    Ok(())
}

#[cfg(not(feature = "development"))]
fn main() {}
