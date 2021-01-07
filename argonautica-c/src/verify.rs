#![allow(non_camel_case_types)]

use std::ffi::CStr;

use argonautica::config::Backend;
use argonautica::Verifier;
use libc::{c_char, c_int};

use {argonautica_backend_t, argonautica_error_t};

/// Function that verifies a password against a hash. It will modify the provided `is_valid` int
/// and return an `argonautica_error_t` indicating whether or not the verification was successful.
///
/// On success, `is_valid` will be modified to be `1` if the hash / password combination is valid
/// or `0` if the hash / password combination is not valid.
///
/// `encoded` is a `char*` pointing to the string-encoded hash.
///
/// For a description of the other arguments, see the documentation for
/// `argonautica_hash`
#[no_mangle]
pub extern "C" fn argonautica_verify(
    is_valid: *mut c_int,
    additional_data: *const u8,
    additional_data_len: u32,
    encoded: *const c_char,
    password: *mut u8,
    password_len: u32,
    secret_key: *mut u8,
    secret_key_len: u32,
    backend: argonautica_backend_t,
    password_clearing: c_int,
    secret_key_clearing: c_int,
    threads: u32,
) -> argonautica_error_t {
    if is_valid.is_null() || encoded.is_null() || password.is_null() {
        return argonautica_error_t::ARGONAUTICA_ERROR_NULL_PTR;
    }

    let backend: Backend = backend.into();
    let password_clearing = password_clearing != 0;
    let secret_key_clearing = secret_key_clearing != 0;

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
        Err(_) => return argonautica_error_t::ARGONAUTICA_ERROR_UTF8_ENCODE,
    };
    verifier.with_hash(encoded);

    // Additional data
    if !additional_data.is_null() {
        let additional_data =
            unsafe { ::std::slice::from_raw_parts(additional_data, additional_data_len as usize) };
        verifier.with_additional_data(additional_data);
    }

    // Password
    let password = unsafe { ::std::slice::from_raw_parts_mut(password, password_len as usize) };
    verifier.with_password(password);

    // Secret key
    if !secret_key.is_null() {
        let secret_key =
            unsafe { ::std::slice::from_raw_parts_mut(secret_key, secret_key_len as usize) };
        verifier.with_secret_key(secret_key);
    }

    let valid = match verifier.verify() {
        Ok(valid) => valid,
        Err(e) => return e.into(),
    };

    if valid {
        unsafe {
            *is_valid = 1;
        };
    } else {
        unsafe {
            *is_valid = 0;
        };
    }

    argonautica_error_t::ARGONAUTICA_OK
}
