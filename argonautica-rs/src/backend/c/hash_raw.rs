use std::ffi::CStr;

use output::HashRaw;
use {ffi, Error, ErrorKind, Hasher};

impl<'a> Hasher<'a> {
    pub(crate) fn hash_raw_c(&mut self) -> Result<HashRaw, Error> {
        let (ad, adlen) = match self.additional_data {
            Some(ref additional_data) => (
                additional_data.as_bytes().as_ptr() as *mut u8,
                additional_data.len() as u32,
            ),
            None => (::std::ptr::null_mut(), 0),
        };
        let (pwd, pwdlen) = match self.password {
            Some(ref mut password) => (
                password.as_bytes().as_ptr() as *mut u8,
                password.len() as u32,
            ),
            None => return Err(Error::new(ErrorKind::PasswordMissingError)),
        };
        let (secret, secretlen) = match self.secret_key {
            Some(ref mut secret_key) => (
                secret_key.as_bytes().as_ptr() as *mut u8,
                secret_key.len() as u32,
            ),
            None => (::std::ptr::null_mut(), 0),
        };
        let mut buffer = vec![0u8; self.config.hash_len() as usize];
        let mut context = ffi::Argon2_Context {
            out: buffer.as_mut_ptr(),
            outlen: buffer.len() as u32,
            pwd,
            pwdlen,
            salt: self.salt.as_bytes().as_ptr() as *mut u8,
            saltlen: self.salt.len() as u32,
            secret,
            secretlen,
            ad,
            adlen,
            t_cost: self.config.iterations(),
            m_cost: self.config.memory_size(),
            lanes: self.config.lanes(),
            threads: self.config.threads(),
            version: self.config.version() as u32,
            allocate_cbk: None,
            free_cbk: None,
            flags: 0,
        };
        let context_ptr = &mut context as *mut ffi::Argon2_Context;
        let variant = self.config.variant() as ffi::argon2_type;
        let err = unsafe { ffi::argon2_ctx(context_ptr, variant) };
        check_error(err)?;
        Ok(HashRaw {
            iterations: self.config.iterations(),
            lanes: self.config.lanes(),
            memory_size: self.config.memory_size(),
            raw_hash_bytes: buffer,
            raw_salt_bytes: self.salt.as_bytes().to_vec(),
            variant: self.config.variant(),
            version: self.config.version(),
        })
    }
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
            if err_msg_ptr.is_null() {
                return Err(Error::new(ErrorKind::Bug)
                    .add_context(format!("Unhandled error from C. Error code: {}", err,)));
            }
            let err_msg_cstr = unsafe { CStr::from_ptr(err_msg_ptr) };
            let err_msg = err_msg_cstr.to_str().unwrap(); // Safe; see argon2_error_message
            Err(Error::new(ErrorKind::Bug).add_context(format!(
                "Unhandled error from C. Error code: {}. Error {}",
                err, err_msg,
            )))
        }
    }
}
