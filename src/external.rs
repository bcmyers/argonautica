//! "extern" functions that can be called from C

use std::ffi::{CStr, CString};

use libc;

// TODO: Password clearing, secret key clearing, opt outs

use config::{Backend, Variant, Version};
use {Hasher, Verifier};

/// Frees memory associated with a pointer that was previously returned from
/// [`a2_hash`](function.a2_hash.html)
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
            *error_code_ptr = -2;
            return ::std::ptr::null();
        }
    };
    let variant = match CStr::from_ptr(variant_ptr).to_str() {
        Ok(s) => match s.parse::<Variant>() {
            Ok(variant) => variant,
            Err(_) => {
                *error_code_ptr = -3;
                return ::std::ptr::null();
            }
        },
        Err(_) => {
            *error_code_ptr = -4;
            return ::std::ptr::null();
        }
    };
    let version = match Version::from_u32(version) {
        Ok(version) => version,
        Err(_) => {
            *error_code_ptr = -5;
            return ::std::ptr::null();
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
            *error_code_ptr = -6;
            return ::std::ptr::null();
        }
    };
    let hash_cstring = CString::new(hash.as_bytes()).unwrap();
    *error_code_ptr = 0;
    hash_cstring.into_raw() as *const libc::c_char
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
    let password = ::std::slice::from_raw_parts(password_ptr, password_len);
    let backend = match Backend::from_u32(backend) {
        Ok(backend) => backend,
        Err(_) => return -1,
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use config::Backend;

    const HASH_LENGTHS: [u32; 2] = [8, 32];
    const ITERATIONS: [u32; 7] = [1, 2, 4, 8, 32, 64, 128];
    const LANES: [u32; 6] = [1, 2, 3, 4, 5, 6];
    const PASSWORDS: [&str; 2] = ["P@ssw0rd", "😊"];
    const VARIANTS: [&str; 3] = ["argon2d", "argon2i", "argon2id"];

    #[inline(always)]
    fn memory_size(lanes: u32) -> u32 {
        let mut counter = 1;
        loop {
            if 2u32.pow(counter) < 8 * lanes {
                counter += 1;
                continue;
            }
            break 2u32.pow(counter);
        }
    }

    fn test(hash_length: u32, iterations: u32, lanes: u32, password: &str, variant: &str) {
        let mut password_bytes = password.as_bytes().to_vec();
        let password_ptr = (&mut password_bytes).as_mut_ptr();
        let password_len = password.as_bytes().len();

        let variant_cstring = CString::new(variant).unwrap();
        let variant_ptr = variant_cstring.as_ptr();

        let mut error_code: libc::c_int = -1;
        let error_code_ptr = &mut error_code as *mut libc::c_int;

        let backend = Backend::C as u32;

        let hash_ptr = unsafe {
            a2_hash(
                /* password_ptr */ password_ptr,
                /* password_len */ password_len,
                /* backend */ backend,
                /* hash_length */ hash_length,
                /* iterations */ iterations,
                /* lanes */ lanes,
                /* memory_size */ memory_size(lanes),
                /* threads */ lanes,
                /* variant_ptr */ variant_ptr,
                /* version */ 19,
                /* error_code_ptr */ error_code_ptr,
            )
        };
        if hash_ptr == ::std::ptr::null_mut() {
            panic!("Error code: {}", unsafe { *error_code_ptr });
        }
        let result = unsafe {
            a2_verify(
                hash_ptr as *const libc::c_char,
                password_ptr as *const libc::uint8_t,
                password_len,
                backend,
            )
        };
        unsafe { a2_free(hash_ptr as *mut libc::c_char) };
        let is_valid = if result == 1 { true } else { false };
        assert!(is_valid);
    }

    #[test]
    #[ignore] // TODO:
    fn test_external() {
        for hash_length in &HASH_LENGTHS {
            for iterations in &ITERATIONS {
                for lanes in &LANES {
                    for password in &PASSWORDS {
                        for variant in &VARIANTS {
                            test(*hash_length, *iterations, *lanes, *password, *variant);
                        }
                    }
                }
            }
        }
    }
}
