use base64;

use error::{Error, ErrorKind};

/// Trait implemented by `AdditionalData`, `Password`, `Salt`, and `SecretKey` that gives you
/// read-only access their underlying bytes
pub trait Data {
    /// Read-only access to the struct's underlying bytes
    fn as_bytes(&self) -> &[u8];

    /// Read-only access to the struct's underlying bytes as a `&str` if those bytes are valid utf-8
    fn to_str(&self) -> Result<&str, Error> {
        let bytes = self.as_bytes();
        let s = ::std::str::from_utf8(bytes).map_err(|_| ErrorKind::InvalidUtf8Error)?;
        Ok(s)
    }

    /// Read-only access to the struct's underlying bytes as as a base64-encoded string using
    /// the [standard base64 encoding](https://docs.rs/base64/0.9.1/base64/constant.STANDARD.html)
    fn to_base64_encoded_string(&self) -> String {
        base64::encode_config(self.as_bytes(), base64::STANDARD)
    }
    /// Read-only access to the struct's underlying bytes as as a base64-encoded string using
    /// a custom base64 encoding (e.g. a [url-safe encoding](https://docs.rs/base64/0.9.1/base64/constant.URL_SAFE.html))
    fn to_base64_encoded_string_config(&self, config: base64::Config) -> String {
        base64::encode_config(self.as_bytes(), config)
    }
}

pub(crate) trait DataPrivate: Data {
    fn as_mut_bytes(&mut self) -> &mut [u8];
    fn validate(&self, extra: Option<bool>) -> Result<(), Error>;

    fn as_ptr(&self) -> *const u8 {
        let ptr: *const u8 = match self.as_bytes().len() {
            0 => ::std::ptr::null(),
            _ => self.as_bytes().as_ptr(),
        };
        ptr
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        let ptr: *mut u8 = match self.as_bytes().len() {
            0 => ::std::ptr::null_mut(),
            _ => self.as_mut_bytes().as_mut_ptr(),
        };
        ptr
    }
    fn len(&self) -> u32 {
        self.as_bytes().len() as u32
    }
}
