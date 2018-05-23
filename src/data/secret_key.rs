use base64;
#[cfg(feature = "serde")]
use serde;

use data::{Data, DataPrivate};
use error::{Error, ErrorKind};

impl<'a> From<&'a [u8]> for SecretKey {
    fn from(bytes: &'a [u8]) -> Self {
        SecretKey {
            bytes: bytes.to_vec(),
        }
    }
}

impl<'a> From<&'a str> for SecretKey {
    fn from(s: &'a str) -> Self {
        let bytes = s.as_bytes().to_vec();
        SecretKey { bytes }
    }
}

impl From<Vec<u8>> for SecretKey {
    fn from(bytes: Vec<u8>) -> Self {
        SecretKey { bytes }
    }
}

impl From<String> for SecretKey {
    fn from(s: String) -> Self {
        let bytes = s.into_bytes();
        SecretKey { bytes }
    }
}

impl<'a> From<&'a Vec<u8>> for SecretKey {
    fn from(bytes: &Vec<u8>) -> Self {
        SecretKey {
            bytes: bytes.clone(),
        }
    }
}

impl<'a> From<&'a String> for SecretKey {
    fn from(s: &String) -> Self {
        let bytes = s.as_bytes().to_vec();
        SecretKey { bytes }
    }
}

impl<'a> From<&'a SecretKey> for SecretKey {
    fn from(secret_key: &SecretKey) -> Self {
        secret_key.clone()
    }
}

impl Data for SecretKey {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SecretKey {
    fn deserialize<D>(_deserializer: D) -> Result<SecretKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(SecretKey::none())
    }
}

/// Type-safe struct representing the raw bytes of your secret key (if any)
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SecretKey {
    bytes: Vec<u8>,
}

impl SecretKey {
    /// Constructs a `SecretKey` from a base64-encoded `&str` that uses the
    /// [standard base64 encoding](https://docs.rs/base64/0.9.1/base64/constant.STANDARD.html)
    pub fn from_base64_encoded_str(s: &str) -> Result<SecretKey, Error> {
        let bytes =
            base64::decode_config(s, base64::STANDARD).map_err(|_| ErrorKind::Base64DecodingError)?;
        Ok(SecretKey { bytes })
    }
    /// Constructs a `SecretKey` from a base64-encoded `&str` that uses a non-standard base64 encoding
    /// (e.g. a [url-safe encoding](https://docs.rs/base64/0.9.1/base64/constant.URL_SAFE.html)),
    /// which the user specifies via the `config` parameter
    pub fn from_base64_encoded_str_config(
        s: &str,
        config: base64::Config,
    ) -> Result<SecretKey, Error> {
        let bytes = base64::decode_config(s, config).map_err(|_| ErrorKind::Base64DecodingError)?;
        Ok(SecretKey { bytes })
    }
}

impl SecretKey {
    pub(crate) fn none() -> SecretKey {
        SecretKey { bytes: vec![] }
    }
}

impl DataPrivate for SecretKey {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
    fn validate(&self, extra: Option<bool>) -> Result<(), Error> {
        let opt_out_of_secret_key = extra.unwrap();
        if !(opt_out_of_secret_key) && self.bytes.is_empty() {
            return Err(ErrorKind::SecretKeyMissingError.into());
        }
        if self.bytes.len() >= ::std::u32::MAX as usize {
            return Err(ErrorKind::SecretKeyTooLongError.into());
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
        assert_send::<SecretKey>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<SecretKey>();
    }
}
