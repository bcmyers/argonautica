#[cfg(feature = "serde")]
use serde;

use data::{Data, DataPrivate};
use errors::DataError;
use {Error, ErrorKind};

impl<'a> From<&'a [u8]> for Password {
    fn from(bytes: &'a [u8]) -> Self {
        Password {
            bytes: bytes.to_vec(),
        }
    }
}

impl<'a> From<&'a str> for Password {
    fn from(s: &'a str) -> Self {
        let bytes = s.as_bytes().to_vec();
        Password { bytes }
    }
}

impl From<Vec<u8>> for Password {
    fn from(bytes: Vec<u8>) -> Self {
        Password { bytes }
    }
}

impl From<String> for Password {
    fn from(s: String) -> Self {
        let bytes = s.into_bytes();
        Password { bytes }
    }
}

impl<'a> From<&'a Vec<u8>> for Password {
    fn from(bytes: &Vec<u8>) -> Self {
        Password {
            bytes: bytes.clone(),
        }
    }
}

impl<'a> From<&'a String> for Password {
    fn from(s: &String) -> Self {
        let bytes = s.as_bytes().to_vec();
        Password { bytes }
    }
}

impl<'a> From<&'a Password> for Password {
    fn from(password: &Password) -> Self {
        password.clone()
    }
}

impl Data for Password {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Password {
    fn deserialize<D>(_deserializer: D) -> Result<Password, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Password::none())
    }
}

/// Type-safe struct representing the raw bytes of your password
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Password {
    bytes: Vec<u8>,
}

impl Password {
    pub(crate) fn none() -> Password {
        Password { bytes: vec![] }
    }
}

impl DataPrivate for Password {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
    fn validate(&self, _extra: Option<bool>) -> Result<(), Error> {
        if self.bytes.is_empty() {
            return Err(ErrorKind::DataError(DataError::PasswordTooShortError).into());
        }
        if self.bytes.len() >= ::std::u32::MAX as usize {
            return Err(ErrorKind::DataError(DataError::PasswordTooLongError).into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
