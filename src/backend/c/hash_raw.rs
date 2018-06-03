use std::ffi::CStr;

use data::{Data, DataPrivate};
use output::HashRaw;
use {ffi, Error, ErrorKind, Hasher};

pub(crate) fn hash_raw_c(hasher: &mut Hasher) -> Result<HashRaw, Error> {
    let mut buffer = vec![0u8; hasher.config().hash_length() as usize];
    let mut context = ffi::Argon2_Context {
        out: buffer.as_mut_ptr(),
        outlen: buffer.len() as u32,
        pwd: hasher.password_mut().as_mut_ptr(),
        pwdlen: hasher.password().len() as u32,
        salt: hasher.salt_mut().as_mut_ptr(),
        saltlen: hasher.salt().len() as u32,
        secret: hasher.secret_key_mut().as_mut_ptr(),
        secretlen: hasher.secret_key().len() as u32,
        ad: hasher.additional_data_mut().as_mut_ptr(),
        adlen: hasher.additional_data().len() as u32,
        t_cost: hasher.config().iterations(),
        m_cost: hasher.config().memory_size(),
        lanes: hasher.config().lanes(),
        threads: hasher.config().threads(),
        version: hasher.config().version() as u32,
        allocate_cbk: None,
        free_cbk: None,
        flags: hasher.config().flags().bits(),
    };
    let context_ptr = &mut context as *mut ffi::Argon2_Context;
    let variant = hasher.config().variant() as ffi::argon2_type;
    let err = unsafe { ffi::argon2_ctx(context_ptr, variant) };
    check_error(err)?;
    Ok(HashRaw::new(
        /* iterations: */ hasher.config().iterations(),
        /* lanes: */ hasher.config().lanes(),
        /* memory_size: */ hasher.config().memory_size(),
        /* raw_hash_bytes: */ buffer,
        /* raw_salt_bytes: */ hasher.salt().as_bytes().to_vec(),
        /* variant: */ hasher.config().variant(),
        /* version: */ hasher.config().version(),
    ))
}

fn check_error(err: ffi::Argon2_ErrorCodes) -> Result<(), Error> {
    match err {
        ffi::Argon2_ErrorCodes_ARGON2_OK => Ok(()),
        ffi::Argon2_ErrorCodes_ARGON2_MEMORY_ALLOCATION_ERROR => {
            Err(Error::new(ErrorKind::MemoryAllocationError))
        }
        ffi::Argon2_ErrorCodes_ARGON2_THREAD_FAIL => Err(Error::new(ErrorKind::ThreadError)),
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
