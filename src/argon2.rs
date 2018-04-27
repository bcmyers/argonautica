use std::ptr;

use failure;

use configuration::config::Config;
use ffi;
use parameters::salt::Salt;
use parameters::secret_key::SecretKey;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Argon2 {
    config: Config,
    additional_data: Option<Vec<u8>>,
    salt: Salt,
    secret_key: SecretKey,
}

impl Argon2 {
    pub(crate) fn new(
        config: Config,
        additional_data: Option<Vec<u8>>,
        salt: Salt,
        secret_key: SecretKey
    ) -> Argon2 {
        Argon2 {
            config,
            additional_data,
            salt,
            secret_key,
        }
    }
    pub fn hash(&self, password: &str) -> Result<Vec<u8>, failure::Error> {
        // output
        let output_length = self.config.hash_length();
        let output_bytes = vec![0u8; output_length as usize];
        let output_ptr = output_bytes.as_ptr() as *mut u8;

        // password
        let password_bytes = password.as_bytes();
        let password_ptr = password_bytes.as_ptr() as *mut u8;
        let password_length = password_bytes.len() as u32;

        // salt
        let salt_bytes = self.salt.to_bytes()?;
        let salt_ptr = match self.salt {
            Salt::None => ptr::null_mut(),
            _ => salt_bytes.as_ptr() as *mut u8,
        };
        let salt_length = salt_bytes.len() as u32;

        // secret_key
        let secret_key_bytes = self.secret_key.clone().into_bytes()?;
        let secret_key_ptr = match self.secret_key {
            SecretKey::None => ptr::null_mut(),
            _ => secret_key_bytes.as_ptr() as *mut u8,
        };
        let secret_key_length = secret_key_bytes.len() as u32;

        // additional_data
        let additional_data_bytes = match self.additional_data {
            Some(ref additional_data) => additional_data.as_slice(),
            None => &[],
        };
        let additional_data_ptr = match self.additional_data {
            Some(_) => additional_data_bytes.as_ptr() as *mut u8,
            None => ptr::null_mut(),
        };
        let additional_data_length = additional_data_bytes.len() as u32;

        // other
        let t_cost = self.config.iterations();
        let m_cost = self.config.memory_size();
        let lanes = self.config.lanes();
        let threads = self.config.threads();
        let version = self.config.version() as u32;
        let allocate_cbk = None;
        let free_cbk = None;
        let flags = self.config.flags().bits() as u32;

        let mut argon2_context = ffi::Argon2_Context {
            out: output_ptr,
            outlen: output_length,
            pwd: password_ptr,
            pwdlen: password_length,
            salt: salt_ptr,
            saltlen: salt_length,
            secret: secret_key_ptr,
            secretlen: secret_key_length,
            ad: additional_data_ptr,
            adlen: additional_data_length,
            t_cost,
            m_cost,
            lanes,
            threads,
            version,
            allocate_cbk,
            free_cbk,
            flags,
        };

        let argon2_context_ptr = &mut argon2_context as *mut ffi::Argon2_Context;

        let err = unsafe { ffi::argon2_ctx(argon2_context_ptr, self.config.variant() as u32) };
        match err {
            ffi::Argon2_ErrorCodes_ARGON2_OK => (),
            ffi::Argon2_ErrorCodes_ARGON2_OUTPUT_PTR_NULL => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_SHORT => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_LONG => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_PWD_TOO_SHORT => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_PWD_TOO_LONG => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_SALT_TOO_SHORT => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_SALT_TOO_LONG => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_AD_TOO_SHORT => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_AD_TOO_LONG => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_SECRET_TOO_SHORT => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_SECRET_TOO_LONG => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_TIME_TOO_SMALL => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_TIME_TOO_LARGE => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_MEMORY_TOO_LITTLE => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_MEMORY_TOO_MUCH => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_LANES_TOO_FEW => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_LANES_TOO_MANY => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_PWD_PTR_MISMATCH => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_SALT_PTR_MISMATCH => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_SECRET_PTR_MISMATCH => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_AD_PTR_MISMATCH => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_MEMORY_ALLOCATION_ERROR => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_FREE_MEMORY_CBK_NULL => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_ALLOCATE_MEMORY_CBK_NULL => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_INCORRECT_PARAMETER => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_INCORRECT_TYPE => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_OUT_PTR_MISMATCH => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_THREADS_TOO_FEW => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_THREADS_TOO_MANY => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_MISSING_ARGS => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_ENCODING_FAIL => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_DECODING_FAIL => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_THREAD_FAIL => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_DECODING_LENGTH_FAIL => bail!("TODO"),
            ffi::Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH => bail!("TODO"),
            _ => bail!("TODO"),
        }

        Ok(output_bytes)
    }
}

#[cfg(feature = "serde")]
mod serde {
    use serde::ser::{Serialize, Serializer};
    use serde::de::{Deserialize, Deserializer};

    use super::Argon2;

    impl Serialize for Argon2 {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            unimplemented!()
        }
    }

    impl<'de> Deserialize<'de> for Argon2 {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Argon2, D::Error> {
            unimplemented!()
        }
    }
}
