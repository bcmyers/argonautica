use std::ffi::{CStr, CString};

use rand::RngCore;

use errors::EncodingError;
use {Error, ErrorKind};

impl<'a> From<&'a [u8]> for SaltNew<'a> {
    fn from(bytes: &'a [u8]) -> SaltNew<'a> {
        SaltNew(Kind::Borrowed(bytes))
    }
}

impl<'a> From<&'a str> for SaltNew<'a> {
    fn from(s: &'a str) -> SaltNew<'a> {
        SaltNew(Kind::Borrowed(s.as_bytes()))
    }
}

impl<'a> From<&'a CStr> for SaltNew<'a> {
    fn from(s: &'a CStr) -> SaltNew<'a> {
        SaltNew(Kind::Borrowed(s.to_bytes()))
    }
}

impl<'a> From<Vec<u8>> for SaltNew<'a> {
    fn from(bytes: Vec<u8>) -> SaltNew<'a> {
        SaltNew(Kind::Owned(bytes))
    }
}

impl<'a> From<String> for SaltNew<'a> {
    fn from(s: String) -> SaltNew<'a> {
        SaltNew(Kind::Owned(s.into_bytes()))
    }
}

impl<'a> From<CString> for SaltNew<'a> {
    fn from(s: CString) -> SaltNew<'a> {
        SaltNew(Kind::Owned(s.into_bytes()))
    }
}

/// Type-safe struct representing raw salt bytes
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SaltNew<'a>(Kind<'a>);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum Kind<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
    Random(Vec<u8>),
}

impl<'a> Default for SaltNew<'a> {
    /// Creates a new <u>random</u> `Salt`. Initially, the random `Salt` has nothing in it, but
    /// every time you call `hash` or `hash_raw` on a `Hasher`, the `Salt` will update with `32`
    /// new random bytes generated using a cryptographically-secure random number generator
    /// (`OsRng`).
    fn default() -> SaltNew<'a> {
        SaltNew::random(32)
    }
}

impl<'a> SaltNew<'a> {
    /// Creates a new <u>random</u> `Salt`. Initially, the random `Salt` has nothing in it, but
    /// every time you call `hash` or `hash_raw` on a `Hasher`, the `Salt` will update with
    /// new random bytes of the length specified generated using a cryptographically-secure
    /// random number generator (`OsRng`).
    pub fn random(len: usize) -> SaltNew<'a> {
        let bytes = vec![0u8; len];
        SaltNew(Kind::Random(bytes))
    }
    /// Read-only access to the `Salt`'s underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        match self.0 {
            Kind::Borrowed(bytes) => bytes,
            Kind::Owned(ref bytes) => bytes.as_slice(),
            Kind::Random(ref bytes) => bytes.as_slice(),
        }
    }
    /// Returns `true` if the `Salt` is <u>random</u> (meaning it was created using
    /// `default` or `random`). Returns `false` otherwise (meaning it was created with one of
    /// the many `From` implementations)
    pub fn is_random(&self) -> bool {
        match self.0 {
            Kind::Borrowed(_) => false,
            Kind::Owned(_) => false,
            Kind::Random(_) => true,
        }
    }
    /// Returns the length of the underlying byte vector
    pub fn len(&self) -> usize {
        match self.0 {
            Kind::Borrowed(bytes) => bytes.len(),
            Kind::Owned(ref bytes) => bytes.len(),
            Kind::Random(ref bytes) => bytes.len(),
        }
    }
    /// Read-only access to the `Salt`'s underlying bytes as a utf8-encoded &str. This method
    /// will return an error if the underyling bytes are not utf8-encoded
    pub fn to_str(&self) -> Result<&str, Error> {
        let s = ::std::str::from_utf8(self.as_bytes()).map_err(|_| {
            Error::new(ErrorKind::EncodingError(EncodingError::Utf8EncodeError))
                .add_context(format!("Bytes: {:?}", self.as_bytes()))
        })?;
        Ok(s)
    }
    /// If you have a <u>random</u> `Salt` (meaning you used the `default` or `random`
    /// constructors), this method will generate new random bytes of the length
    /// of your `Salt`. If you have a <u>deterministic</u> `Salt`, this method does nothing
    pub fn update<R: RngCore>(&mut self, rng: &mut R) {
        match self.0 {
            Kind::Random(ref mut bytes) => rng.fill_bytes(bytes),
            _ => (),
        }
    }
}

impl<'a> SaltNew<'a> {
    fn as_ptr(&self) -> *const u8 {
        match self.0 {
            Kind::Borrowed(bytes) => bytes.as_ptr(),
            Kind::Owned(ref bytes) => bytes.as_slice().as_ptr(),
            Kind::Random(ref bytes) => bytes.as_slice().as_ptr(),
        }
    }
}

