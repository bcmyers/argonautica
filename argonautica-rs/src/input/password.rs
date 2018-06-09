use std::ffi::{CStr, CString};

use errors::{DataError, EncodingError};
use input::{Data, DataMut};
use {Error, ErrorKind};

impl From<Vec<u8>> for Password {
    fn from(bytes: Vec<u8>) -> Password {
        Password {
            bytes: bytes,
            is_owned: true,
        }
    }
}

impl From<String> for Password {
    fn from(s: String) -> Password {
        Password {
            bytes: s.into_bytes(),
            is_owned: true,
        }
    }
}

impl From<CString> for Password {
    fn from(s: CString) -> Password {
        Password {
            bytes: s.into_bytes(),
            is_owned: true,
        }
    }
}

impl<'a> From<&'a [u8]> for Password {
    fn from(bytes: &[u8]) -> Password {
        Password {
            bytes: bytes.to_vec(),
            is_owned: false,
        }
    }
}

impl<'a> From<&'a str> for Password {
    fn from(s: &str) -> Password {
        Password {
            bytes: s.as_bytes().to_vec(),
            is_owned: false,
        }
    }
}

impl<'a> From<&'a CStr> for Password {
    fn from(s: &CStr) -> Password {
        Password {
            bytes: s.to_bytes().to_vec(),
            is_owned: false,
        }
    }
}

impl<'a> From<&'a Vec<u8>> for Password {
    fn from(bytes: &Vec<u8>) -> Password {
        Password {
            bytes: bytes.clone(),
            is_owned: false,
        }
    }
}

impl<'a> From<&'a String> for Password {
    fn from(s: &String) -> Password {
        Password {
            bytes: s.clone().into_bytes(),
            is_owned: false,
        }
    }
}

impl<'a> From<&'a Password> for Password {
    fn from(password: &Password) -> Password {
        Password {
            bytes: password.as_bytes().to_vec(),
            is_owned: false,
        }
    }
}

/// Type-safe struct representing the raw bytes of your password
///
/// <i>Note that is <u>unlikely</u> to apply to you unless you are using advanced features:
///
/// If you construct a [`Password`](struct.Password.html) from a borrowed value (as opposed to
/// an owned value), you will <b>not</b> be able to use it with a [`Hasher`](../struct.Hasher.html)
/// or a [`Verifier`](../struct.Verifier.html) whose "password clearing" configuration is set to
/// `true` (this configuration is set to `false` by default; see
/// [here](../index.html#configuration) for more details on the "password clearing"
/// configuration). This limitation (again, only when "password clearing" is set to `true`)
/// is required because when you construct a [`Password`](struct.Password.html) from a borrowed
/// value, `argonautica` cannot guarantee that all the underlying bytes of the
/// [`Password`](struct.Password.html) will indeed be erased after hashing and/or verifying,
/// which is the whole point of the "password clearing" feature.</i>
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Password {
    bytes: Vec<u8>,
    is_owned: bool,
}

impl Password {
    /// Read-only access to the underlying byte buffer
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Return `true` if [`Password`](struct.Password.html) was constructed from an owned value;
    /// `false` otherwise
    pub fn is_owned(&self) -> bool {
        self.is_owned
    }
    /// Read-only acccess to the underlying byte buffer's length
    pub fn len(&self) -> usize {
        self.bytes.len()
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

impl Password {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.len() == 0 {
            return Err(ErrorKind::DataError(DataError::PasswordTooShortError).into());
        }
        if self.len() >= ::std::u32::MAX as usize {
            return Err(
                Error::new(ErrorKind::DataError(DataError::PasswordTooLongError))
                    .add_context(format!("Length: {}", self.len())),
            );
        }
        Ok(())
    }
}

impl Data for Password {
    fn c_len(&self) -> u32 {
        self.len() as u32
    }
    fn c_ptr(&self) -> *const u8 {
        self.as_bytes().as_ptr()
    }
}

impl DataMut for Password {
    fn c_mut_ptr(&mut self) -> *mut u8 {
        self.c_ptr() as *mut u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_is_owned() {
        let password: Password = vec![0u8].into();
        assert!(password.is_owned());

        let password: Password = "string".to_string().into();
        assert!(password.is_owned());

        let password: Password = "str".into();
        assert!(!password.is_owned());

        let password: Password = (&[0u8][..]).into();
        assert!(!password.is_owned());

        let password: Password = vec![0u8].into();
        let password: Password = (&password).into();
        assert!(!password.is_owned());
    }

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Password>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Password>();
    }
}
