use std::ffi::CString;
use std::os::raw::c_char;

use config::Variant;
use data::{Data, DataPrivate};
use errors::DataError;
use verifier::Verifier;
use {ffi, Error, ErrorKind};

pub(crate) fn verify_c(verifier: &mut Verifier) -> Result<bool, Error> {
    let (mut context, variant) = {
        let hash = match verifier.hash() {
            Some(hash) => hash,
            None => {
                return Err(Error::new(ErrorKind::Bug)
                    .add_context("Attempting to verify without a hash. This should be unreachable"))
            }
        };
        let max_len = hash.len();
        let mut buffer = vec![0u8; max_len];
        let mut salt = vec![0u8; max_len];
        let mut context = ffi::Argon2_Context {
            out: buffer.as_mut_ptr(),
            outlen: buffer.len() as u32,
            pwd: ::std::ptr::null_mut(),
            pwdlen: 0,
            salt: salt.as_mut_ptr(),
            saltlen: salt.len() as u32,
            secret: ::std::ptr::null_mut(),
            secretlen: 0,
            ad: ::std::ptr::null_mut(),
            adlen: 0,
            t_cost: 0,
            m_cost: 0,
            lanes: 0,
            threads: 0,
            version: 0,
            allocate_cbk: None,
            free_cbk: None,
            flags: 0,
        };
        let context_ptr = &mut context as *mut ffi::argon2_context;
        let hash_cstring = CString::new(hash).map_err(|_| {
            Error::new(ErrorKind::DataError(DataError::HashInvalidError)).add_context(format!(
                "Hash cannot contain an interior null byte. Hash: {}",
                &hash
            ))
        })?;
        let hash_cstring_ptr = hash_cstring.as_ptr();
        let (_, variant) = parse_variant(&hash).map_err(|_| {
            Error::new(ErrorKind::DataError(DataError::HashInvalidError))
                .add_context(format!("Hash: {}", &hash))
        })?;
        let err = unsafe {
            ffi::decode_string(context_ptr, hash_cstring_ptr, variant as ffi::argon2_type)
        };
        if err != 0 {
            return Err(
                Error::new(ErrorKind::DataError(DataError::HashInvalidError))
                    .add_context(format!("Hash: {}", &hash)),
            );
        }
        (context, variant)
    };
    let hash_ptr = context.out as *const c_char;
    let mut buffer = vec![0u8; context.outlen as usize];
    context.ad = verifier.additional_data_mut().as_mut_ptr();
    context.adlen = verifier.additional_data().len() as u32;
    context.out = buffer.as_mut_ptr();
    context.outlen = buffer.len() as u32;
    context.pwd = verifier.password_mut().as_mut_ptr();
    context.pwdlen = verifier.password().len() as u32;
    context.secret = verifier.secret_key_mut().as_mut_ptr();
    context.secretlen = verifier.secret_key().len() as u32;
    let context_ptr = &mut context as *mut ffi::argon2_context;
    let err = unsafe { ffi::argon2_verify_ctx(context_ptr, hash_ptr, variant as ffi::argon2_type) };
    let is_valid = if err == 0 {
        true
    } else if err == ffi::Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH {
        false
    } else {
        return Err(Error::new(ErrorKind::Bug).add_context(format!(
            "Unhandled error from C code: {}. This should be unreachable. Verifier: {:?}",
            err, verifier,
        )));
    };
    Ok(is_valid)
}

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(parse_variant<&str, Variant>, do_parse!(
    take_until_and_consume!("$") >>
    variant: map_res!(take_until!("$"), |x: &str| x.parse::<Variant>()) >>
    (variant)
));
