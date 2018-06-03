use base64;

use errors::EncodingError;
use {Error, ErrorKind};

/// Trait implemented by [`AdditionalData`](struct.AdditionalData.html),
/// [`Password`](struct.Password.html), [`Salt`](struct.Salt.html), and
/// [`SecretKey`](struct.Salt.html) that gives you read-only access their underlying bytes
pub trait Data {
    /// Read-only access to the type's underlying byte buffer
    fn as_bytes(&self) -> &[u8];

    /// Returns a raw const pointer to the underlying byte buffer
    fn as_ptr(&self) -> *const u8 {
        let ptr: *const u8 = match self.as_bytes().len() {
            0 => ::std::ptr::null(),
            _ => self.as_bytes().as_ptr(),
        };
        ptr
    }
    /// Returns the length of the underlying byte buffer
    fn len(&self) -> usize {
        self.as_bytes().len()
    }
    /// Read-only access to the type's underlying byte buffer as a `&str` if those bytes are valid utf-8
    fn to_str(&self) -> Result<&str, Error> {
        let bytes = self.as_bytes();
        let s = ::std::str::from_utf8(bytes).map_err(|_| {
            Error::new(ErrorKind::EncodingError(EncodingError::Utf8EncodeError))
                .add_context(format!("Bytes: {:?}", bytes))
        })?;
        Ok(s)
    }

    /// Read-only access to the type's underlying byte buffer as as a base64-encoded string using
    /// [standard base64 encoding](https://docs.rs/base64/0.9.1/base64/constant.STANDARD.html)
    fn to_base64_encoded_string(&self) -> String {
        base64::encode_config(self.as_bytes(), base64::STANDARD)
    }
    /// Read-only access to the type's underlying byte buffer as as a base64-encoded string using
    /// a custom base64 encoding (e.g. a [url-safe encoding](https://docs.rs/base64/0.9.1/base64/constant.URL_SAFE.html))
    fn to_base64_encoded_string_config(&self, config: base64::Config) -> String {
        base64::encode_config(self.as_bytes(), config)
    }
}

impl<'a, T: Data> Data for &'a T {
    fn as_bytes(&self) -> &[u8] {
        (**self).as_bytes()
    }
}

impl<'a, T: Data> Data for &'a mut T {
    fn as_bytes(&self) -> &[u8] {
        (**self).as_bytes()
    }
}

impl<T: Data> Data for Option<T> {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Some(ref v) => v.as_bytes(),
            None => &[],
        }
    }
}

pub(crate) trait DataPrivate: Data {
    fn as_mut_bytes(&mut self) -> &mut [u8];

    fn as_mut_ptr(&mut self) -> *mut u8 {
        let ptr: *mut u8 = match self.len() {
            0 => ::std::ptr::null_mut(),
            _ => self.as_mut_bytes().as_mut_ptr(),
        };
        ptr
    }
}

impl<'a, T: DataPrivate> DataPrivate for &'a mut T {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        (**self).as_mut_bytes()
    }
}

impl<T: DataPrivate> DataPrivate for Option<T> {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        match self {
            Some(ref mut v) => v.as_mut_bytes(),
            None => &mut [],
        }
    }
}
