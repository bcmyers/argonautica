use base64;

use data::{Data, DataPrivate};
use errors::{DataError, EncodingError};
use {Error, ErrorKind};

impl<'a> From<&'a [u8]> for SecretKey {
    fn from(bytes: &'a [u8]) -> Self {
        SecretKey {
            bytes: bytes.to_vec(),
            constructed_from_borrow: true,
        }
    }
}

impl<'a> From<&'a str> for SecretKey {
    fn from(s: &'a str) -> Self {
        let bytes = s.as_bytes().to_vec();
        SecretKey {
            bytes,
            constructed_from_borrow: true,
        }
    }
}

impl From<Vec<u8>> for SecretKey {
    fn from(bytes: Vec<u8>) -> Self {
        SecretKey {
            bytes,
            constructed_from_borrow: false,
        }
    }
}

impl From<String> for SecretKey {
    fn from(s: String) -> Self {
        let bytes = s.into_bytes();
        SecretKey {
            bytes,
            constructed_from_borrow: false,
        }
    }
}

impl<'a> From<&'a Vec<u8>> for SecretKey {
    fn from(bytes: &Vec<u8>) -> Self {
        SecretKey {
            bytes: bytes.clone(),
            constructed_from_borrow: true,
        }
    }
}

impl<'a> From<&'a String> for SecretKey {
    fn from(s: &String) -> Self {
        let bytes = s.as_bytes().to_vec();
        SecretKey {
            bytes,
            constructed_from_borrow: true,
        }
    }
}

impl<'a> From<&'a SecretKey> for SecretKey {
    fn from(secret_key: &SecretKey) -> Self {
        let mut secret_key = secret_key.clone();
        secret_key.constructed_from_borrow = true;
        secret_key
    }
}

impl Data for SecretKey {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
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
/// value, `a2` cannot guarantee that all the underlying bytes of the
/// [`SecretKey`](struct.SecretKey.html) will indeed be erased after hashing and/or verifying,
/// which is the whole point of the "secret key clearing" feature.
///
/// Stress not, however, as, again, both the default [`Hasher`](../struct.Hasher.html) and the
/// default [`Verifier`](../struct.Verifier.html) have "secret key clearing" set to `false`.
///
/// If you do decide to turn on "secret key clearing", constructing a
/// [`SecretKey`](struct.SecretKey.html) from an owned value is easy, just pass the
/// [`with_secret_key`](../struct.Hasher.html#method.with_secret_key) method on
/// [`Hasher`](../struct.Hasher.html) or [`Verifier`](../struct.Verifier.html) an owned value,
/// such as a `String` or a `Vec<u8>`, or, alternatively, use one of the two constructors below that
/// takes an owned value, i.e.
/// [`from_base64_encoded_string`](struct.SecretKey.html#method.from_base64_encoded_string) and
/// [`from_base64_encoded_string_config`](struct.SecretKey.html#method.from_base64_encoded_string_config)
/// </i>

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SecretKey {
    bytes: Vec<u8>,
    constructed_from_borrow: bool,
}

impl SecretKey {
    /// Constructs a [`SecretKey`](struct.SecretKey.html) from a borrowed `&str` (or anything
    /// that can be dereferenced into a `&str`) using the
    /// [standard base64 encoding](https://docs.rs/base64/0.9.1/base64/constant.STANDARD.html).
    ///
    /// <i>Note: A [`SecretKey`](struct.SecretKey.html) constructed with this method <b>cannot</b>
    /// be used when the "secret key clearing" configuration is set to `true` since it will
    /// have been constructed from a borrowed (as opposed to owned) value. See
    /// [above](struct.SecretKey.html) for a more detailed explanation</i>
    pub fn from_base64_encoded_str<S: AsRef<str>>(s: S) -> Result<SecretKey, Error> {
        let bytes = base64::decode_config(s.as_ref(), base64::STANDARD).map_err(|_| {
            Error::new(ErrorKind::EncodingError(EncodingError::Base64DecodeError))
                .add_context(format!("&str: {}", s.as_ref()))
        })?;
        Ok(SecretKey {
            bytes,
            constructed_from_borrow: true,
        })
    }
    /// Same as [`from_base64_encoded_str`](struct.SecretKey.html#method.from_base64_encoded_str)
    /// except you can pass a value that uses a non-standard base64 encoding (e.g. a
    /// [url-safe encoding](https://docs.rs/base64/0.9.1/base64/constant.URL_SAFE.html))
    ///
    /// <i>Note: A [`SecretKey`](struct.SecretKey.html) constructed with this method <b>cannot</b>
    /// be used when the "secret key clearing" configuration is set to `true` since it will
    /// have been constructed from a borrowed (as opposed to owned) value. See
    /// [above](struct.SecretKey.html) for a more detailed explanation</i>
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
            constructed_from_borrow: true,
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
            constructed_from_borrow: false,
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
            constructed_from_borrow: false,
        })
    }
}

impl SecretKey {
    pub(crate) fn constructed_from_borrow(&self) -> bool {
        self.constructed_from_borrow
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.bytes.len() >= ::std::u32::MAX as usize {
            return Err(
                Error::new(ErrorKind::DataError(DataError::SecretKeyTooLongError))
                    .add_context(format!("Length: {}", self.bytes.len())),
            );
        }
        Ok(())
    }
}

impl DataPrivate for SecretKey {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constructed_from_borrow_secret_key() {
        let secret_key: SecretKey = vec![0u8].into();
        assert!(!secret_key.constructed_from_borrow());

        let secret_key: SecretKey = "string".to_string().into();
        assert!(!secret_key.constructed_from_borrow());

        let secret_key: SecretKey = "str".into();
        assert!(secret_key.constructed_from_borrow());

        let secret_key: SecretKey = (&[0u8][..]).into();
        assert!(secret_key.constructed_from_borrow());

        let secret_key: SecretKey = vec![0u8].into();
        let secret_key: SecretKey = (&secret_key).into();
        assert!(secret_key.constructed_from_borrow());
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
