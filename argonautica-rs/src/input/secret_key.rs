use std::fmt;

use base64;

use input::Container;
use {Error, ErrorKind};

impl<'a> From<&'a str> for SecretKey<'a> {
    fn from(s: &'a str) -> SecretKey<'a> {
        SecretKey {
            inner: Container::Borrowed(s.as_bytes()),
        }
    }
}

impl<'a> From<&'a mut str> for SecretKey<'a> {
    fn from(s: &'a mut str) -> SecretKey<'a> {
        let bytes = unsafe { s.as_bytes_mut() };
        SecretKey {
            inner: Container::BorrowedMut(bytes),
        }
    }
}

impl<'a> From<&'a String> for SecretKey<'a> {
    fn from(s: &'a String) -> SecretKey<'a> {
        SecretKey {
            inner: Container::Borrowed(s.as_bytes()),
        }
    }
}

impl<'a> From<&'a mut String> for SecretKey<'a> {
    fn from(s: &'a mut String) -> SecretKey<'a> {
        let bytes = unsafe { s.as_bytes_mut() };
        SecretKey {
            inner: Container::BorrowedMut(bytes),
        }
    }
}

impl<'a> From<String> for SecretKey<'a> {
    fn from(s: String) -> SecretKey<'static> {
        SecretKey {
            inner: Container::Owned(s.into_bytes()),
        }
    }
}

impl<'a> From<&'a [u8]> for SecretKey<'a> {
    fn from(bytes: &'a [u8]) -> SecretKey<'a> {
        SecretKey {
            inner: Container::Borrowed(bytes),
        }
    }
}

impl<'a> From<&'a mut [u8]> for SecretKey<'a> {
    fn from(bytes: &'a mut [u8]) -> SecretKey<'a> {
        SecretKey {
            inner: Container::BorrowedMut(bytes),
        }
    }
}

impl<'a> From<&'a Vec<u8>> for SecretKey<'a> {
    fn from(bytes: &'a Vec<u8>) -> SecretKey<'a> {
        SecretKey {
            inner: Container::Borrowed(bytes),
        }
    }
}

impl<'a> From<&'a mut Vec<u8>> for SecretKey<'a> {
    fn from(bytes: &'a mut Vec<u8>) -> SecretKey<'a> {
        SecretKey {
            inner: Container::BorrowedMut(bytes),
        }
    }
}

impl<'a> From<Vec<u8>> for SecretKey<'a> {
    fn from(bytes: Vec<u8>) -> SecretKey<'static> {
        SecretKey {
            inner: Container::Owned(bytes),
        }
    }
}

impl<'a> From<&'a SecretKey<'a>> for SecretKey<'a> {
    fn from(sk: &'a SecretKey<'a>) -> SecretKey<'a> {
        let bytes = match sk.inner {
            Container::Borrowed(ref bytes) => &**bytes,
            Container::BorrowedMut(ref bytes) => &**bytes,
            Container::Owned(ref bytes) => bytes,
        };
        SecretKey {
            inner: Container::Borrowed(bytes),
        }
    }
}

impl<'a> From<&'a mut SecretKey<'a>> for SecretKey<'a> {
    fn from(sk: &'a mut SecretKey<'a>) -> SecretKey<'a> {
        match sk.inner {
            Container::Borrowed(ref bytes) => SecretKey {
                inner: Container::Borrowed(&**bytes),
            },
            Container::BorrowedMut(ref mut bytes) => SecretKey {
                inner: Container::BorrowedMut(&mut **bytes),
            },
            Container::Owned(ref mut bytes) => SecretKey {
                inner: Container::BorrowedMut(&mut *bytes),
            },
        }
    }
}

impl<'a> fmt::Debug for SecretKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "****")
    }
}

/// Type-safe struct representing the raw bytes of a secret key
#[derive(Eq, PartialEq, Hash)]
pub struct SecretKey<'a> {
    pub(crate) inner: Container<'a>,
}

impl<'a> SecretKey<'a> {
    /// Constructs a [`SecretKey`](struct.SecretKey.html) from a base64-encoded `&str` (or anything
    /// that can be dereferenced into a base64-encoded `&str`) using the
    /// [standard base64 encoding](https://docs.rs/base64/0.9.1/base64/constant.STANDARD.html).
    pub fn from_base64_encoded<S>(s: S) -> Result<SecretKey<'static>, Error>
    where
        S: AsRef<str>,
    {
        let bytes = base64::decode_config(s.as_ref(), base64::STANDARD).map_err(|_| {
            Error::new(ErrorKind::Base64DecodeError).add_context(format!("&str: {}", s.as_ref()))
        })?;
        Ok(SecretKey {
            inner: Container::Owned(bytes),
        })
    }
    /// Same as [`from_base64_encoded_str`](struct.SecretKey.html#method.from_base64_encoded_str)
    /// except you can pass a value that uses a non-standard base64 encoding (e.g. a
    /// [url-safe encoding](https://docs.rs/base64/0.9.1/base64/constant.URL_SAFE.html))
    pub fn from_base64_encoded_config<S>(
        s: S,
        config: base64::Config,
    ) -> Result<SecretKey<'static>, Error>
    where
        S: AsRef<str>,
    {
        let bytes = base64::decode_config(s.as_ref(), config).map_err(|_| {
            Error::new(ErrorKind::Base64DecodeError).add_context(format!("&str: {}", s.as_ref()))
        })?;
        Ok(SecretKey {
            inner: Container::Owned(bytes),
        })
    }
    /// Read-only access to the underlying byte buffer
    pub fn as_bytes(&self) -> &[u8] {
        match self.inner {
            Container::Borrowed(ref bytes) => bytes,
            Container::BorrowedMut(ref bytes) => bytes,
            Container::Owned(ref bytes) => bytes,
        }
    }
    /// Indicates whether the underlying byte buffer is mutable or not. The underlying byte
    /// buffer is mutable when the [`SecretKey`](struct.SecretKey.html) was constructed
    /// from an owned value (such as a `String` or a `Vec<u8>`) or from a mutable reference
    /// (such as a `&mut str` or a `&mut [u8]`). It is not mutable when the
    /// [`SecretKey`](struct.SecretKey.html) was constructed from an immutable reference
    /// (such as a `&str` or a `&[u8]`). The [`SecretKey`](struct.SecretKey.html) must be mutable
    /// in order to hash or verify with the `secret_key_clearing` configuration set to `true`
    pub fn is_mutable(&self) -> bool {
        match self.inner {
            Container::Borrowed(_) => false,
            _ => true,
        }
    }
    /// Read-only acccess to the underlying byte buffer's length (in number of bytes)
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }
    /// Clones the underlying byte buffer and returns a new
    /// [`SecretKey`](struct.SecretKey.html) with a `static` lifetime. Use this method if you
    /// would like to move a [`SecretKey`](struct.SecretKey.html) to another thread
    pub fn to_owned(&self) -> SecretKey<'static> {
        SecretKey {
            inner: self.inner.to_owned(),
        }
    }
    /// Returns the underlying byte buffer as a base64-encoded `String` using
    /// [standard base64 encoding](https://docs.rs/base64/0.9.1/base64/constant.STANDARD.html)
    pub fn to_base64_encoded(&self) -> String {
        base64::encode_config(self.as_bytes(), base64::STANDARD)
    }
    /// Returns the underlying byte buffer as a base64-encoded `String` using
    /// a custom base64 encoding (e.g. a [url-safe encoding](https://docs.rs/base64/0.9.1/base64/constant.URL_SAFE.html))
    pub fn to_base64_encoded_config(&self, config: base64::Config) -> String {
        base64::encode_config(self.as_bytes(), config)
    }
    /// Read-only access to the underlying byte buffer as a `&str` if its bytes are valid utf-8
    pub fn to_str(&self) -> Result<&str, Error> {
        let s = ::std::str::from_utf8(self.as_bytes())
            .map_err(|_| Error::new(ErrorKind::Utf8EncodeError))?;
        Ok(s)
    }
}

impl<'a> SecretKey<'a> {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.len() >= ::std::u32::MAX as usize {
            return Err(Error::new(ErrorKind::SecretKeyTooLongError)
                .add_context(format!("Length: {}", self.len())));
        }
        Ok(())
    }
}
