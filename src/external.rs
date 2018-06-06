//! "extern" functions that can be called from C
use std::ffi::{CStr, CString};

use libc::{c_char, c_int, uint32_t, uint8_t};

use config::{Backend, Variant, Version};
use input::Salt;
use {Hasher, Verifier};

/// Frees memory associated with a pointer that was previously returned from `argonautica_hash`
#[no_mangle]
pub extern "C" fn argonautica_free(string: *mut c_char) -> c_int {
    if string.is_null() {
        return -1;
    }
    unsafe {
        CString::from_raw(string);
    };
    return 0;
}

// TODO: Does the pointer actually get set to zero?

/// Hash function that can be called from C. This function allocates memory and hands ownership
/// of that memory over to C; so in your C code you must call `argonautica_free` at some point
/// after using the pointer returned from this function in order to avoid leaking
/// memory
///
/// <b><u>Arguments (from the perspective of C code):</u></b>
/// * <b>Additional data</b>:
///     * To hash <b>with</b> additional data:
///         * `additional_data_ptr` = a `uint32_t*` pointing to the additional data buffer
///         * `additional_data_len` = a `size_t` indicating the number of bytes in the additional data buffer
///         * If `additional_data_len` exceeds 2^32 -1, this function will return `NULL`
///         * This function will <b>not</b> modify the additional data buffer
///     * To hash <b>without</b> additional data:
///         * `additional_data_ptr` = `NULL`
///         * `additional_data_len` = `0`
/// * <b>Password</b>:
///     * `password_ptr` = a `uint32_t*` pointing to the password buffer
///     * `password_len` = a `size_t` indicating the number of bytes in the password buffer
///     * If `password_len` exceeds 2^32 -1, this function will return `NULL`
///     * If `password_clearing` = `1` (see below), this function will set the `password_ptr` to `NULL`, set the `password_len` to `0`, and zero out the bytes in the password buffer
/// * <b>Salt</b>:
///     * To hash with a <b>random</b> salt:
///         * `salt_ptr` = `NULL`
///         * `salt_len` = a `size_t` indicating the length of the salt (in number of bytes)
///         * If `salt_len` is less than 8 or exceeds 2^32 -1, this function will return `NULL`
///     * To hash with a <b>deterministic</b> salt
///         * `salt_ptr` = a `uint32_t*` pointing to the salt buffer
///         * `salt_len` = a `size_t` indicating the number of bytes in the salt buffer
///         * If `salt_len` is less than 8 or exceeds 2^32 -1, this function will return `NULL`
///         * This function will <b>not</b> modify the salt buffer
/// * <b>Secret key</b>:
///     * To hash <b>with</b> a secret key:
///         * `secret_key_ptr` = a `uint32_t*` pointing to the secret key buffer
///         * `secret_key_len` = a `size_t` indicating the number of bytes in the secret key buffer
///         * If `secret_key_len` exceeds 2^32 -1, this function will return `NULL`
///         * If `secret_key_clearing` = `1` (see below), this function will set the `secret_key_ptr` to `NULL`, set the `secret_key_len` to `0`, and zero out the bytes in the secret key buffer
///     * To hash <b>without</b> a secret key:
///         * `secret_key_ptr` = `NULL`
///         * `secret_key_len` = `0`
/// * <b>Backend</b>
///     * `backend` = `1` for the C backend
///     * `backend` = `2` for the Rust backend
///     * If `backend` is anything else, this function will return `NULL`
/// *<b>Hash length</b>: `hash_length` = a `size_t` indicating the desired length of the hash (in number of bytes)
/// *<b>Iterations</b>: `iterations` = a `size_t` indicating the desired number of iterations
#[no_mangle]
pub extern "C" fn argonautica_hash(
    additional_data: *const uint8_t,
    additional_data_len: uint32_t,
    password: *mut uint8_t,
    password_len: uint32_t,
    salt: *const uint8_t,
    salt_len: uint32_t,
    secret_key: *mut uint8_t,
    secret_key_len: uint32_t,
    backend: uint32_t,
    hash_len: uint32_t,
    iterations: uint32_t,
    lanes: uint32_t,
    memory_size: uint32_t,
    password_clearing: c_int,
    secret_key_clearing: c_int,
    threads: uint32_t,
    variant: *const c_char,
    version: uint32_t,
    error_code: *mut c_int,
) -> *const c_char {
    if password.is_null() || variant.is_null() {
        if error_code.is_null() {
            return ::std::ptr::null();
        } else {
            unsafe {
                *error_code = -1;
            };
            return ::std::ptr::null();
        }
    }

    // Backend
    let backend = match Backend::from_u32(backend) {
        Ok(backend) => backend,
        Err(_) => {
            unsafe {
                *error_code = -2;
            };
            return ::std::ptr::null();
        }
    };

    // Variant
    let variant_cstr = unsafe { CStr::from_ptr(variant) };
    let variant = match variant_cstr.to_str() {
        Ok(s) => match s.parse::<Variant>() {
            Ok(variant) => variant,
            Err(_) => {
                unsafe {
                    *error_code = -3;
                };
                return ::std::ptr::null();
            }
        },
        Err(_) => {
            unsafe {
                *error_code = -4;
            };
            return ::std::ptr::null();
        }
    };

    // Version
    let version = match Version::from_u32(version) {
        Ok(version) => version,
        Err(_) => {
            unsafe {
                *error_code = -5;
            };
            return ::std::ptr::null();
        }
    };

    let mut hasher = Hasher::default();
    hasher
        .configure_backend(backend)
        .configure_hash_length(hash_len)
        .configure_iterations(iterations)
        .configure_lanes(lanes)
        .configure_memory_size(memory_size)
        .configure_password_clearing(false) // TODO:
        .configure_secret_key_clearing(false) // TODO:
        .configure_threads(threads)
        .configure_variant(variant)
        .configure_version(version)
        .opt_out_of_random_salt(true)
        .opt_out_of_secret_key(true);

    // Additional data
    if !additional_data.is_null() {
        let additional_data = unsafe {
            ::std::slice::from_raw_parts(additional_data, additional_data_len as usize)
        };
        hasher.with_additional_data(additional_data);
    }

    // Password
    let password = unsafe { ::std::slice::from_raw_parts(password, password_len as usize) };
    hasher.with_password(password);

    // Salt
    if salt.is_null() {
        let salt = Salt::random(salt_len);
        hasher.with_salt(salt);
    } else {
        let salt = unsafe { ::std::slice::from_raw_parts(salt, salt_len as usize) };
        hasher.with_salt(salt);
    };

    // Secret key
    if !secret_key.is_null() {
        let secret_key = unsafe {
            ::std::slice::from_raw_parts(secret_key, secret_key_len as usize)
        };
        hasher.with_secret_key(secret_key);
    };

    let hash = match hasher.hash() {
        Ok(hash) => hash,
        Err(_) => {
            unsafe {
                *error_code = -6;
            };
            return ::std::ptr::null();
        }
    };

    let hash_cstring = CString::new(hash.as_bytes()).unwrap();
    unsafe {
        *error_code = 0;
    };

    hash_cstring.into_raw() as *const c_char
}

/// Verify function that can be called from C. Unlike `argonautica_hash`, this
/// function does <b>not</b> allocate memory that needs to be freed from C; so there is no need
/// to call `argonautica_free` after using this function
#[no_mangle]
pub extern "C" fn argonautica_verify(
    hash: *const c_char,
    additional_data: *const uint8_t,
    additional_data_len: uint32_t,
    password: *mut uint8_t,
    password_len: uint32_t,
    secret_key: *mut uint8_t,
    secret_key_len: uint32_t,
    backend: uint32_t,
    password_clearing: c_int,
    secret_key_clearing: c_int,
    threads: uint32_t,
) -> c_int {
    if hash.is_null() || password.is_null() {
        return -1;
    }

    // Backend
    let backend = match Backend::from_u32(backend) {
        Ok(backend) => backend,
        Err(_) => return -1,
    };

    let mut verifier = Verifier::default();
    verifier
        .configure_backend(backend)
        .configure_password_clearing(false) // TODO:
        .configure_secret_key_clearing(false) // TODO:
        .configure_threads(threads);

    // Hash
    let hash_cstr = unsafe { CStr::from_ptr(hash) };
    let hash = match hash_cstr.to_str() {
        Ok(hash) => hash,
        Err(_) => return -1, // Utf-8 Error
    };
    verifier.with_hash(hash);

    // Additional data
    if !additional_data.is_null() {
        let additional_data = unsafe {
            ::std::slice::from_raw_parts(additional_data, additional_data_len as usize)
        };
        verifier.with_additional_data(additional_data);
    }

    // Password
    let password = unsafe { ::std::slice::from_raw_parts(password, password_len as usize) };
    verifier.with_password(password);

    // Secret key
    if !secret_key.is_null() {
        let secret_key = unsafe {
            ::std::slice::from_raw_parts(secret_key, secret_key_len as usize)
        };
        verifier.with_additional_data(secret_key);
    }

    let is_valid = match verifier.verify() {
        Ok(is_valid) => is_valid,
        Err(_) => return -1,
    };

    if is_valid {
        1
    } else {
        0
    }
}
