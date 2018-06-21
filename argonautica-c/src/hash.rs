#![allow(non_camel_case_types)]

use std::ffi::CString;

use argonautica::config::{Backend, Variant, Version};
use argonautica::input::Salt;
use argonautica::Hasher;
use libc::{c_char, c_int, uint32_t, uint8_t};

use {argonautica_backend_t, argonautica_error_t, argonautica_variant_t, argonautica_version_t};

/// Function that hashes a password. It will modify the provided `encoded` buffer
/// and return an `argonautica_error_t` indicating whether or not the hash was successful.
///
/// Arguments (from the perspective of C code):
/// * Encoded:
///     * `encoded` = a `char*` that points to a buffer whose length (in bytes) is sufficient
///       to hold the resulting string-encoded hash (including it's NULL byte)
///     * To determine what the length of the string-encoded hash will be
///       ahead of time (including the NULL byte), use the `argonautica_encoded_len` function
///     * This function will modify the encoded buffer (that's it's whole point :))
/// * Additional data:
///     * To hash with additional data:
///         * `additional_data` = a `uint8_t*` pointing to the additional data buffer
///         * `additional_data_len` = a `uint32_t` indicating the number of bytes in the additional data buffer
///         * This function will not modify the additional data buffer
///     * To hash <b>without</b> additional data:
///         * `additional_data` = `NULL`
///         * `additional_data_len` = `0`
/// * Password:
///     * `password` = a `uint8_t*` pointing to the password buffer
///     * `password_len` = a `uint32_t` indicating the number of bytes in the password buffer
///     * If `password_clearing` (see below) is any value other than zero, this function will set `password` to `NULL`, set `password_len` to `0`, and zero out the bytes in the password buffer
/// * Salt:
///     * To hash with a random salt (which is recommended):
///         * `salt` = `NULL`
///         * `salt_len` = a `uint32_t` indicating the length of the salt (in number of bytes)
///     * To hash with a deterministic salt (which is not recommended)
///         * `salt` = a `uint8_t*` pointing to the salt buffer
///         * `salt_len` = a `uint32_t` indicating the number of bytes in the salt buffer
///         * This function will not modify the salt buffer
/// * Secret key:
///     * To hash with a secret key (which is recommended):
///         * `secret_key` = a `uint8_t*` pointing to the secret key buffer
///         * `secret_key_len` = a `uint32_t` indicating the number of bytes in the secret key buffer
///         * If `secret_key_clearing` (see below) is any value other than zero, this function will set `secret_key` to `NULL`, set `secret_key_len` to `0`, and zero out the bytes in the secret key buffer
///     * To hash without a secret key (which is not recommended):
///         * `secret_key` = `NULL`
///         * `secret_key_len` = `0`
/// * Backend:
///     * `backend` = `ARGONAUTICA_C` for the C backend
///     * `backend` = `ARGONAUTICA_RUST` for the Rust backend
/// * Hash length:
///     * `hash_len` = a `uint32_t` indicating the desired hash length (in number of bytes)
/// * Iterations:
///     * `iterations` = a `uint32_t` indicating the desired number of iterations
/// * Lanes:
///     * `lanes` = a `uint32_t` indicating the desired number of lanes
/// * Memory size:
///     * `memory_size` = a `uint32_t` indicating the desired memory size (in kibibytes)
/// * Password clearing:
///     * If `password_clearing` is any value other than zero, this function will set `password` to `NULL`, set `password_len` to `0`, and zero out the bytes in the password buffer
/// * Secret key clearing:
///     * If `secret_key_clearing` is any value other than zero, this function will set `secret_key` to `NULL`, set `secret_key_len` to `0`, and zero out the bytes in the secret key buffer
/// * Threads:
///     * `threads` = a `uint32_t` indicating the desired number of threads
/// * Variant:
///     * `variant` = `ARGONAUTICA_ARGON2D` for argon2d
///     * `variant` = `ARGONAUTICA_ARGON2I` for argon2i
///     * `variant` = `ARGONAUTICA_ARGON2ID` for argon2id
/// * Version:
///     * `version` = `ARGONAUTICA_0x10` for 0x10
///     * `version` = `ARGONAUTICA_0x13` for 0x13
#[no_mangle]
pub extern "C" fn argonautica_hash(
    encoded: *mut c_char,
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
) -> argonautica_error_t {
    if encoded.is_null() || password.is_null() {
        return argonautica_error_t::ARGONAUTICA_ERROR_NULL_PTR;
    }

    let backend: Backend = backend.into();
    let password_clearing = if password_clearing == 0 { false } else { true };
    let secret_key_clearing = if secret_key_clearing == 0 {
        false
    } else {
        true
    };
    let variant: Variant = variant.into();
    let version: Version = version.into();

    let mut hasher = Hasher::default();
    hasher
        .configure_backend(backend)
        .configure_hash_len(hash_len)
        .configure_iterations(iterations)
        .configure_lanes(lanes)
        .configure_memory_size(memory_size)
        .configure_password_clearing(password_clearing)
        .configure_secret_key_clearing(secret_key_clearing)
        .configure_threads(threads)
        .configure_variant(variant)
        .configure_version(version)
        .opt_out_of_secret_key(true);

    // Additional data
    if !additional_data.is_null() {
        let additional_data =
            unsafe { ::std::slice::from_raw_parts(additional_data, additional_data_len as usize) };
        hasher.with_additional_data(additional_data);
    }

    // Password
    let password = unsafe { ::std::slice::from_raw_parts_mut(password, password_len as usize) };
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
            unsafe { ::std::slice::from_raw_parts_mut(secret_key, secret_key_len as usize) };
        hasher.with_secret_key(secret_key);
    };

    let hash = match hasher.hash() {
        Ok(hash) => hash,
        Err(e) => return e.into(),
    };

    let hash_cstring = CString::new(hash.as_bytes()).unwrap();
    let hash_cstring_len = hash_cstring.as_bytes_with_nul().len();
    let hash_ptr = hash_cstring.as_ptr();

    unsafe {
        ::std::ptr::copy_nonoverlapping(hash_ptr, encoded, hash_cstring_len);
    }

    argonautica_error_t::ARGONAUTICA_OK
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;
    use {argonautica_encoded_len, argonautica_variant_t};

    #[test]
    fn test_clearing() {
        let hash_len = 32;
        let iterations = 128;
        let lanes = 4;
        let memory_size = 128;
        let salt_len = 8;
        let variant = argonautica_variant_t::ARGONAUTICA_ARGON2ID;
        let encoded_len = argonautica_encoded_len(
            /* hash_len */ hash_len,
            /* iterations */ iterations,
            /* lanes */ lanes,
            /* memory_size */ memory_size,
            /* salt_len */ salt_len,
            /* variant */ variant,
        );
        let encoded = vec![1u8; encoded_len as usize];
        let cstring = unsafe { CString::from_vec_unchecked(encoded) };
        let encoded_ptr = cstring.into_raw();
        let password = "11111111".to_string();
        let password_ptr = password.as_bytes().as_ptr() as *mut uint8_t;
        let password_len = password.as_bytes().len();
        let secret_key = "22222222".to_string();
        let secret_key_ptr = secret_key.as_bytes().as_ptr() as *mut uint8_t;
        let secret_key_len = secret_key.as_bytes().len();
        let err = argonautica_hash(
            /* encoded */ encoded_ptr,
            /* additional_data */ ::std::ptr::null(),
            /* additional_data_len */ 0,
            /* password */ password_ptr,
            /* password_len */ password_len as uint32_t,
            /* salt */ ::std::ptr::null(),
            /* salt_len */ salt_len,
            /* secret_key */ secret_key_ptr,
            /* secret_key_len */ secret_key_len as uint32_t,
            /* backend */ argonautica_backend_t::ARGONAUTICA_C,
            /* hash_len */ hash_len,
            /* iterations */ iterations,
            /* lanes */ lanes,
            /* memory_size */ memory_size,
            /* password_clearing */ 1,
            /* secret_key_clearing */ 1,
            /* threads */ lanes,
            /* variant */ variant,
            /* version */ argonautica_version_t::ARGONAUTICA_0x13,
        );
        assert_eq!(err, argonautica_error_t::ARGONAUTICA_OK);
        let password =
            unsafe { ::std::slice::from_raw_parts(password_ptr as *mut uint8_t, password_len) };
        assert_eq!(password, &[0u8; 8][..]);
        let secret_key =
            unsafe { ::std::slice::from_raw_parts(secret_key_ptr as *mut uint8_t, secret_key_len) };
        assert_eq!(secret_key, &[0u8; 8][..]);
        let _ = unsafe { CString::from_raw(encoded_ptr) };
    }
}
