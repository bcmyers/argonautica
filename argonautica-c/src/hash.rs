#![allow(non_camel_case_types)]

use std::ffi::CString;

use argonautica::Hasher;
use argonautica::config::{Backend, Variant, Version};
use argonautica::input::Salt;
use libc::{c_char, c_int, uint32_t, uint8_t};

use {argonautica_backend_t, argonautica_error_t, argonautica_variant_t, argonautica_version_t};

/// Hash function that can be called from C that returns a string-encoded hash. This function
/// allocates memory and hands ownership of that memory over to C; so in your C code you must
/// call `argonautica_free` at some point after using the pointer returned from this function
/// in order to avoid leaking memory
///
/// <u>Arguments (from the perspective of C code):</u>
/// * <b>Additional data</b>:
///     * To hash <b>with</b> additional data:
///         * `additional_data` = a `uint8_t*` pointing to the additional data buffer
///         * `additional_data_len` = a `uint32_t` indicating the number of bytes in the additional data buffer
///         * This function will <b>not</b> modify the additional data buffer
///     * To hash <b>without</b> additional data:
///         * `additional_data` = `NULL`
///         * `additional_data_len` = `0`
/// * <b>Password</b>:
///     * `password` = a `uint8_t*` pointing to the password buffer
///     * `password_len` = a `uint32_t` indicating the number of bytes in the password buffer
///     * If `password_clearing` (see below) is <b>any value other than zero</b>, this function will set `password` to `NULL`, set `password_len` to `0`, and zero out the bytes in the password buffer
/// * <b>Salt</b>:
///     * To hash with a <b>random</b> salt:
///         * `salt` = `NULL`
///         * `salt_len` = a `uint32_t` indicating the length of the salt (in number of bytes)
///     * To hash with a <b>deterministic</b> salt
///         * `salt` = a `uint8_t*` pointing to the salt buffer
///         * `salt_len` = a `uint32_t` indicating the number of bytes in the salt buffer
///         * This function will <b>not</b> modify the salt buffer
/// * <b>Secret key</b>:
///     * To hash <b>with</b> a secret key:
///         * `secret_key` = a `uint8_t*` pointing to the secret key buffer
///         * `secret_key_len` = a `uint32_t` indicating the number of bytes in the secret key buffer
///         * If `secret_key_clearing` (see below) is <b>any value other than zero</b>, this function will set `secret_key` to `NULL`, set `secret_key_len` to `0`, and zero out the bytes in the secret key buffer
///     * To hash <b>without</b> a secret key:
///         * `secret_key` = `NULL`
///         * `secret_key_len` = `0`
/// * <b>Backend</b>
///     * `backend` = `ARGONAUTICA_C` for the C backend
///     * `backend` = `ARGONAUTICA_RUST` for the Rust backend
/// * <b>Hash length</b>
///     * `hash_len` = a `uint32_t` indicating the desired hash length (in number of bytes)
/// * <b>Iterations</b>
///     * `iterations` = a `uint32_t` indicating the desired number of iterations
/// * <b>Lanes</b>
///     * `lanes` = a `uint32_t` indicating the desired number of lanes
/// * <b>Memory size</b>
///     * `memory_size` = a `uint32_t` indicating the desired memory size (in kibibytes)
/// * <b>Password clearing</b>
///     * If `password_clearing` is <b>any value other than zero</b>, this function will set `password` to `NULL`, set `password_len` to `0`, and zero out the bytes in the password buffer
/// * <b>Secret key clearing</b>
///     * If `secret_key_clearing` is <b>any value other than zero</b>, this function will set `secret_key` to `NULL`, set `secret_key_len` to `0`, and zero out the bytes in the secret key buffer
/// * <b>Threads</b>
///     * `threads` = a `uint32_t` indicating the desired number of threads
/// * <b>Variant</b>
///     * `variant` = `ARGONAUTICA_ARGON2D` for argon2d
///     * `variant` = `ARGONAUTICA_ARGON2I` for argon2i
///     * `variant` = `ARGONAUTICA_ARGON2ID` for argon2id
/// * <b>Version</b>
///     * `version` = `ARGONAUTICA_0x10` for 0x10
///     * `version` = `ARGONAUTICA_0x13` for 0x13
/// * <b>Error code</b>
///     * `error_code` = an `argonautica_error_t*` that will be set to `ARGONAUTICA_OK` if there
///       was no error and another variant of `argonautica_error_t` if an error occurred
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
    backend: argonautica_backend_t,
    hash_len: uint32_t,
    iterations: uint32_t,
    lanes: uint32_t,
    memory_size: uint32_t,
    password_clearing: c_int,
    secret_key_clearing: c_int,
    threads: uint32_t,
    variant: argonautica_variant_t,
    version: argonautica_version_t,
    error_code: *mut argonautica_error_t,
) -> *const c_char {
    if password.is_null() {
        if error_code.is_null() {
            return ::std::ptr::null();
        } else {
            unsafe {
                *error_code = argonautica_error_t::ARGONAUTICA_ERROR1;
            };
            return ::std::ptr::null();
        }
    }

    let backend: Backend = backend.into();
    let password_clearing = if password_clearing == 0 { false } else { true };
    let secret_key_clearing = if secret_key_clearing == 0 { false } else { true };
    let variant: Variant = variant.into();
    let version: Version = version.into();

    let mut hasher = Hasher::default();
    hasher
        .configure_backend(backend)
        .configure_hash_length(hash_len)
        .configure_iterations(iterations)
        .configure_lanes(lanes)
        .configure_memory_size(memory_size)
        .configure_opt_out_of_secret_key(true)
        .configure_password_clearing(password_clearing)
        .configure_secret_key_clearing(secret_key_clearing)
        .configure_threads(threads)
        .configure_variant(variant)
        .configure_version(version);

    // Additional data
    if !additional_data.is_null() {
        let additional_data =
            unsafe { ::std::slice::from_raw_parts(additional_data, additional_data_len as usize) };
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
        let secret_key =
            unsafe { ::std::slice::from_raw_parts(secret_key, secret_key_len as usize) };
        hasher.with_secret_key(secret_key);
    };

    let hash = match hasher.hash() {
        Ok(hash) => hash,
        Err(_) => {
            unsafe {
                *error_code = argonautica_error_t::ARGONAUTICA_ERROR1;
            };
            return ::std::ptr::null();
        }
    };

    let hash_cstring = CString::new(hash.as_bytes()).unwrap();
    unsafe {
        *error_code = argonautica_error_t::ARGONAUTICA_OK;
    };

    hash_cstring.into_raw() as *const c_char
}
