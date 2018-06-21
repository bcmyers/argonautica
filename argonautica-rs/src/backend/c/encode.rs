#![cfg(test)]

use std::ffi::CStr;

use libc;

use output::HashRaw;
use {ffi, Error, ErrorKind};

pub(crate) fn encode_c(hash_raw: &HashRaw) -> Result<String, Error> {
    let encoded_len = unsafe {
        ffi::argon2_encodedlen(
            hash_raw.iterations(),
            hash_raw.memory_size(),
            hash_raw.lanes(),
            hash_raw.raw_salt_bytes().len() as u32,
            hash_raw.raw_hash_bytes().len() as u32,
            hash_raw.variant() as ffi::argon2_type,
        )
    };
    let mut encoded = vec![0 as libc::c_char; encoded_len];
    let encoded_ptr = encoded.as_mut_ptr();
    let mut context = ffi::Argon2_Context {
        out: hash_raw.raw_hash_bytes().as_ptr() as *mut u8,
        outlen: hash_raw.raw_hash_bytes().len() as u32,
        pwd: ::std::ptr::null_mut(),
        pwdlen: 0,
        salt: hash_raw.raw_salt_bytes().as_ptr() as *mut u8,
        saltlen: hash_raw.raw_salt_bytes().len() as u32,
        secret: ::std::ptr::null_mut(),
        secretlen: 0,
        ad: ::std::ptr::null_mut(),
        adlen: 0,
        t_cost: hash_raw.iterations(),
        m_cost: hash_raw.memory_size(),
        lanes: hash_raw.lanes(),
        threads: 1,
        version: hash_raw.version() as u32,
        allocate_cbk: None,
        free_cbk: None,
        flags: 0,
    };
    let context_ptr = &mut context as *mut ffi::argon2_context;
    let variant = hash_raw.variant() as ffi::argon2_type;
    let err = unsafe { ffi::encode_string(encoded_ptr, encoded_len, context_ptr, variant) };
    check_error(err, hash_raw)?;
    let c_str: &CStr = unsafe { CStr::from_ptr(encoded_ptr) };
    let s = c_str.to_str().unwrap().to_string();
    Ok(s)
}

fn check_error(err: ffi::Argon2_ErrorCodes, hash_raw: &HashRaw) -> Result<(), Error> {
    match err {
        ffi::Argon2_ErrorCodes_ARGON2_OK => Ok(()),
        ffi::Argon2_ErrorCodes_ARGON2_MEMORY_ALLOCATION_ERROR => {
            Err(Error::new(ErrorKind::MemoryAllocationError))
        }
        ffi::Argon2_ErrorCodes_ARGON2_THREAD_FAIL => Err(Error::new(ErrorKind::ThreadError)),
        ffi::Argon2_ErrorCodes_ARGON2_ENCODING_FAIL => Err(
            Error::new(ErrorKind::HashEncodeError).add_context(format!("HashRaw: {:?}", hash_raw))
        ),
        _ => {
            let err_msg_ptr = unsafe { ffi::argon2_error_message(err) };
            let err_msg_cstr = unsafe { CStr::from_ptr(err_msg_ptr) };
            let err_msg = err_msg_cstr.to_str().unwrap(); // Safe; see argon2_error_message
            Err(Error::new(ErrorKind::Bug).add_context(format!(
                "Unhandled error from C. Error code: {}. Error {}",
                err, err_msg,
            )))
        }
    }
}
