use std::ffi::{CStr, CString};

use base64;

use errors::{DataError, EncodingError};
use input::{Data, DataMut};
use {Error, ErrorKind};

impl From<Vec<u8>> for SecretKey {
    fn from(bytes: Vec<u8>) -> SecretKey {
        SecretKey {
            bytes: bytes,
            is_owned: true,
        }
    }
}

impl From<String> for SecretKey {
    fn from(s: String) -> SecretKey {
        SecretKey {
            bytes: s.into_bytes(),
            is_owned: true,
        }
    }
}

impl From<CString> for SecretKey {
    fn from(s: CString) -> SecretKey {
        SecretKey {
            bytes: s.into_bytes(),
            is_owned: true,
        }
    }
}

impl<'a> From<&'a [u8]> for SecretKey {
    fn from(bytes: &[u8]) -> SecretKey {
        SecretKey {
            bytes: bytes.to_vec(),
            is_owned: false,
        }
    }
}

impl<'a> From<&'a str> for SecretKey {
    fn from(s: &str) -> SecretKey {
        SecretKey {
            bytes: s.as_bytes().to_vec(),
            is_owned: false,
        }
    }
}

impl<'a> From<&'a CStr> for SecretKey {
    fn from(s: &CStr) -> SecretKey {
        SecretKey {
            bytes: s.to_bytes().to_vec(),
            is_owned: false,
        }
    }
}

impl<'a> From<&'a SecretKey> for SecretKey {
    fn from(secret_key: &SecretKey) -> SecretKey {
        SecretKey {
            bytes: secret_key.as_bytes().to_vec(),
            is_owned: false,
        }
    }
}

/// Type-safe struct representing the raw bytes of your secret key (if any)
///
/// <i>Note that is <u>unlikely</u> to apply to you unless you are using advanced features:
///
/// If you construct a [`SecretKey`](struct.SecretKey.html) from a borrowed value (as opposed to
/// an owned value), you will <b>not</b> be able to use it with a [`Hasher`](../struct.Hasher.html)
/// or a [`Verifier`](../struct.Verifier.html) whose "secret key clearing" configuration is set to
/// `true` (this configuration is set to `false` by default; see
/// [here](../index.html#configuration) for more details on the "secret key clearing"
/// configuration). This limitation (again, only when "secret key clearing" is set to `true`)
/// is required because when you construct a [`SecretKey`](struct.SecretKey.html) from a borrowed
/// value, `jasonus` cannot guarantee that all the underlying bytes of the
/// [`SecretKey`](struct.SecretKey.html) will indeed be erased after hashing and/or verifying,
/// which is the whole point of the "secret key clearing" feature.</i>

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SecretKey {
    bytes: Vec<u8>,
    is_owned: bool,
}

impl SecretKey {
    /// Constructs a [`SecretKey`](struct.SecretKey.html) from a borrowed `&str` (or anything
    /// that can be dereferenced into a `&str`) using the
    /// [standard base64 encoding](https://docs.rs/base64/0.9.1/base64/constant.STANDARD.html).
    pub fn from_base64_encoded_str<S: AsRef<str>>(s: S) -> Result<SecretKey, Error> {
        let bytes = base64::decode_config(s.as_ref(), base64::STANDARD).map_err(|_| {
            Error::new(ErrorKind::EncodingError(EncodingError::Base64DecodeError))
                .add_context(format!("&str: {}", s.as_ref()))
        })?;
        Ok(SecretKey {
            bytes,
            is_owned: false,
        })
    }
    /// Same as [`from_base64_encoded_str`](struct.SecretKey.html#method.from_base64_encoded_str)
    /// except you can pass a value that uses a non-standard base64 encoding (e.g. a
    /// [url-safe encoding](https://docs.rs/base64/0.9.1/base64/constant.URL_SAFE.html))
    pub fn from_base64_encoded_str_config<S: AsRef<str>>(
        s: S,
        config: base64::Config,
    ) -> Result<SecretKey, Error> {
        let bytes = base64::decode_config(s.as_ref(), config).map_err(|_| {
            Error::new(ErrorKind::EncodingError(EncodingError::Base64DecodeError))
                .add_context(format!("&str: {}", s.as_ref()))
        })?;
        Ok(SecretKey {
            bytes,
            is_owned: false,
        })
    }
    /// Constructs a [`SecretKey`](struct.SecretKey.html) from an owned `String` using the
    /// [standard base64 encoding](https://docs.rs/base64/0.9.1/base64/constant.STANDARD.html).
    pub fn from_base64_encoded_string(s: String) -> Result<SecretKey, Error> {
        let bytes = base64::decode_config(&s, base64::STANDARD).map_err(|_| {
            Error::new(ErrorKind::EncodingError(EncodingError::Base64DecodeError))
                .add_context(format!("String: {}", &s))
        })?;
        Ok(SecretKey {
            bytes,
            is_owned: true,
        })
    }
    /// Same as
    /// [`from_base64_encoded_string`](struct.SecretKey.html#method.from_base64_encoded_string)
    /// except you can pass a value that uses a non-standard base64 encoding (e.g. a
    /// [url-safe encoding](https://docs.rs/base64/0.9.1/base64/constant.URL_SAFE.html))
    pub fn from_base64_encoded_string_config(
        s: String,
        config: base64::Config,
    ) -> Result<SecretKey, Error> {
        let bytes = base64::decode_config(&s, config).map_err(|_| {
            Error::new(ErrorKind::EncodingError(EncodingError::Base64DecodeError))
                .add_context(format!("String: {}", &s))
        })?;
        Ok(SecretKey {
            bytes,
            is_owned: true,
        })
    }
    /// Read-only access to the underlying byte buffer
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Return `true` if [`SecretKey`](struct.SecretKey.html) was constructed from an owned value;
    /// `false` otherwise
    pub fn is_owned(&self) -> bool {
        self.is_owned
    }
    /// Read-only acccess to the underlying byte buffer's length
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    /// Read-only access to the underlying byte buffer as a base64-encoded `String` using
    /// [standard base64 encoding](https://docs.rs/base64/0.9.1/base64/constant.STANDARD.html)
    pub fn to_base64_encoded_string(&self) -> String {
        base64::encode_config(self.as_bytes(), base64::STANDARD)
    }
    /// Read-only access to the underlying byte buffer as a base64-encoded `String` using
    /// a custom base64 encoding (e.g. a [url-safe encoding](https://docs.rs/base64/0.9.1/base64/constant.URL_SAFE.html))
    pub fn to_base64_encoded_string_config(&self, config: base64::Config) -> String {
        base64::encode_config(self.as_bytes(), config)
    }
    /// Read-only access to the underlying byte buffer as a `&str` if its bytes are valid utf-8
    pub fn to_str(&self) -> Result<&str, Error> {
        let s = ::std::str::from_utf8(self.as_bytes()).map_err(|_| {
            Error::new(ErrorKind::EncodingError(EncodingError::Utf8EncodeError))
                .add_context(format!("Bytes: {:?}", self.as_bytes()))
        })?;
        Ok(s)
    }
}

impl SecretKey {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.len() >= ::std::u32::MAX as usize {
            return Err(
                Error::new(ErrorKind::DataError(DataError::SecretKeyTooLongError))
                    .add_context(format!("Length: {}", self.len())),
            );
        }
        Ok(())
    }
}

impl Data for SecretKey {
    fn c_len(&self) -> u32 {
        self.len() as u32
    }
    fn c_ptr(&self) -> *const u8 {
        self.as_bytes().as_ptr()
    }
}

impl DataMut for SecretKey {
    fn c_mut_ptr(&mut self) -> *mut u8 {
        self.c_ptr() as *mut u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_is_owned() {
        let secret_key: SecretKey = vec![0u8].into();
        assert!(secret_key.is_owned());

        let secret_key: SecretKey = "string".to_string().into();
        assert!(secret_key.is_owned());

        let secret_key: SecretKey = "str".into();
        assert!(!secret_key.is_owned());

        let secret_key: SecretKey = (&[0u8][..]).into();
        assert!(!secret_key.is_owned());

        let secret_key: SecretKey = vec![0u8].into();
        let secret_key: SecretKey = (&secret_key).into();
        assert!(!secret_key.is_owned());
    }

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<SecretKey>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<SecretKey>();
    }
}
