//! "extern" functions that can be called from C

use std::ffi::{CStr, CString};

use libc;

// TODO: Password clearing, secret key clearing, opt outs

use config::{Backend, Variant, Version};
use {Hasher, Verifier};

/// Frees memory associated with a pointer that was previously returned from
/// [`a2_hash`](function.a2_hash.html). See [`a2_hash`](function.a2_hash.html) below
/// for more information
#[no_mangle]
pub unsafe extern "C" fn a2_free(cstring_ptr: *mut libc::c_char) {
    CString::from_raw(cstring_ptr);
}

/// Hash function that can be called from C. This function allocates memory and hands ownership
/// of that memory over to C; so in your C code you must call [`a2_free`](function.a2_free.html)
/// at some point after using the pointer returned from this function in order to avoid leaking
/// memory
#[no_mangle]
pub unsafe extern "C" fn a2_hash(
    password_ptr: *const libc::uint8_t,
    password_len: libc::size_t,
    backend: libc::uint32_t,
    hash_length: libc::uint32_t,
    iterations: libc::uint32_t,
    lanes: libc::uint32_t,
    memory_size: libc::uint32_t,
    threads: libc::uint32_t,
    variant_ptr: *const libc::c_char,
    version: libc::uint32_t,
    error_code_ptr: *mut libc::c_int,
) -> *const libc::c_char {
    let backend = match Backend::from_u32(backend) {
        Ok(backend) => backend,
        Err(_) => {
            *error_code_ptr = -1;
            return ::std::ptr::null();
        }
    };
    let variant = match CStr::from_ptr(variant_ptr).to_str() {
        Ok(s) => match s.parse::<Variant>() {
            Ok(variant) => variant,
            Err(_) => {
                *error_code_ptr = -1;
                return ::std::ptr::null();
            }
        },
        Err(_) => {
            *error_code_ptr = -1;
            return ::std::ptr::null();
        }
    };
    let version = match Version::from_u32(version) {
        Ok(version) => version,
        Err(_) => {
            return {
                *error_code_ptr = -1;
                ::std::ptr::null()
            }
        }
    };

    let mut hasher = Hasher::default();
    hasher
        .configure_backend(backend)
        .configure_hash_length(hash_length)
        .configure_iterations(iterations)
        .configure_lanes(lanes)
        .configure_memory_size(memory_size)
        .configure_password_clearing(false)
        .configure_secret_key_clearing(false)
        .configure_threads(threads)
        .configure_variant(variant)
        .configure_version(version)
        .opt_out_of_random_salt(true)
        .opt_out_of_secret_key(true)
        .with_salt("somesalt"); // TODO
    let password = ::std::slice::from_raw_parts(password_ptr, password_len);
    let hash = match hasher.with_password(password).hash() {
        Ok(hash) => hash,
        Err(_) => {
            *error_code_ptr = -1;
            return ::std::ptr::null();
        }
    };
    let hash_cstring = CString::new(hash.as_bytes()).unwrap();
    *error_code_ptr = 0;
    hash_cstring.into_raw()
}

/// Verify function that can be called from C. Unlike [`a2_hash`](function.a2_hash.html), this
/// function does <b>not</b> allocate memory that needs to be freed from C; so there is no need
/// to call [`a2_free`](function.a2_free.html) after using this function
#[no_mangle]
pub unsafe extern "C" fn a2_verify(
    hash_ptr: *const libc::c_char,
    password_ptr: *const libc::uint8_t,
    password_len: libc::size_t,
    backend: libc::uint32_t,
) -> libc::c_int {
    let hash = match CStr::from_ptr(hash_ptr).to_str() {
        Ok(hash) => hash,
        Err(_) => return -1, // Utf-8 Error
    };
    let hash2 = "$argon2id$v=19$m=4096,t=128,p=2$c29tZXNhbHQ$WwD2/wGGTuw7u4BW8sLM0Q";
    assert_eq!(&hash, &hash2);
    let password = ::std::slice::from_raw_parts(password_ptr, password_len);
    let backend = match Backend::from_u32(backend) {
        Ok(backend) => backend,
        Err(_) => return -1,
    };
    let password2 = String::from_utf8(password.to_vec()).unwrap();
    assert_eq!("P@ssw0rd", &password2);
    let mut verifier = Verifier::default();
    let is_valid = match verifier
        .configure_backend(backend)
        .configure_password_clearing(false)
        .configure_secret_key_clearing(false)
        .with_hash(hash)
        .with_password(password)
        .verify()
    {
        Ok(is_valid) => is_valid,
        Err(_) => return -1,
    };
    if is_valid {
        1
    } else {
        0
    }
}
