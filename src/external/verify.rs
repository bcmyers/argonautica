#![allow(non_camel_case_types)]

#![allow(non_camel_case_types)]

use std::ffi::CStr;

use libc::{c_char, c_int, uint32_t, uint8_t};

use config::Backend;
use external::{argonautica_backend_t, argonautica_error_t};
use Verifier;

/// Verify function that can be called from C. Unlike `argonautica_hash`, this
/// function does <b>not</b> allocate memory that you need to free; so there is no need
/// to call `argonautica_free` after using this function
///
/// `encoded` is the string-encoded hash as a `char*`.
///
/// For a description of the other arguments, see documentation for
/// [`argonautica_hash`](function.argonautica_hash.html)
#[no_mangle]
pub extern "C" fn argonautica_verify(
    additional_data: *const uint8_t,
    additional_data_len: uint32_t,
    encoded: *const c_char,
    password: *mut uint8_t,
    password_len: uint32_t,
    secret_key: *mut uint8_t,
    secret_key_len: uint32_t,
    backend: argonautica_backend_t,
    password_clearing: c_int,
    secret_key_clearing: c_int,
    threads: uint32_t,
) -> argonautica_error_t {
    if encoded.is_null() || password.is_null() {
        return argonautica_error_t::ARGONAUTICA_ERROR1;
    }

    let backend: Backend = backend.into();
    let password_clearing = if password_clearing == 0 { false } else { true };
    let secret_key_clearing = if secret_key_clearing == 0 { false } else { true };

    let mut verifier = Verifier::default();
    verifier
        .configure_backend(backend)
        .configure_password_clearing(password_clearing)
        .configure_secret_key_clearing(secret_key_clearing)
        .configure_threads(threads);

    // Hash
    let encoded_cstr = unsafe { CStr::from_ptr(encoded) };
    let encoded = match encoded_cstr.to_str() {
        Ok(encoded) => encoded,
        Err(_) => return argonautica_error_t::ARGONAUTICA_ERROR1, // Utf-8 Error
    };
    verifier.with_hash(encoded);

    // Additional data
    if !additional_data.is_null() {
        let additional_data =
            unsafe { ::std::slice::from_raw_parts(additional_data, additional_data_len as usize) };
        verifier.with_additional_data(additional_data);
    }

    // Password
    let password = unsafe { ::std::slice::from_raw_parts(password, password_len as usize) };
    verifier.with_password(password);

    // Secret key
    if !secret_key.is_null() {
        let secret_key =
            unsafe { ::std::slice::from_raw_parts(secret_key, secret_key_len as usize) };
        verifier.with_secret_key(secret_key);
    }

    let is_valid = match verifier.verify() {
        Ok(is_valid) => is_valid,
        Err(_) => return argonautica_error_t::ARGONAUTICA_ERROR1,
    };

    if is_valid {
        argonautica_error_t::ARGONAUTICA_OK
    } else {
        argonautica_error_t::ARGONAUTICA_ERROR1
    }
}
