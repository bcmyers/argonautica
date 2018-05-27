//! "extern" functions that can be called from C

use std::ffi::{CStr, CString};

use libc;

// TODO: Password clearing, secret key clearing, opt outs

use config::{Backend, Variant, Version};
use hasher::Hasher;

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
        .configure_threads(threads)
        .configure_variant(variant)
        .configure_version(version)
        .opt_out_of_random_salt(true)
        .opt_out_of_secret_key(true);
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
