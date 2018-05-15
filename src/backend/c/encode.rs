#![cfg(test)]

use std::ffi::CStr;
use std::os::raw::c_char;

use error::{Error, ErrorKind};
use ffi;
use output::HashRaw;

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
    // TODO: Check error? Here and in other place
    let mut encoded = vec![0 as c_char; encoded_len];
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
    let type_ = hash_raw.variant() as ffi::argon2_type;

    let err = unsafe { ffi::encode_string(encoded_ptr, encoded_len, context_ptr, type_) };
    if err != 0 {
        return Err(ErrorKind::HashEncoding.into()); // TODO????
    }

    let c_str: &CStr = unsafe { CStr::from_ptr(encoded_ptr) };
    let s = c_str.to_str().unwrap().to_string();
    Ok(s)
}
