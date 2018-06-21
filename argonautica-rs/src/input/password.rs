use std::fmt;

use input::Container;
use {Error, ErrorKind};

impl<'a> From<&'a str> for Password<'a> {
    fn from(s: &'a str) -> Password<'a> {
        Password {
            inner: Container::Borrowed(s.as_bytes()),
        }
    }
}

impl<'a> From<&'a mut str> for Password<'a> {
    fn from(s: &'a mut str) -> Password<'a> {
        let bytes = unsafe { s.as_bytes_mut() };
        Password {
            inner: Container::BorrowedMut(bytes),
        }
    }
}

impl<'a> From<&'a String> for Password<'a> {
    fn from(s: &'a String) -> Password<'a> {
        Password {
            inner: Container::Borrowed(s.as_bytes()),
        }
    }
}

impl<'a> From<&'a mut String> for Password<'a> {
    fn from(s: &'a mut String) -> Password<'a> {
        let bytes = unsafe { s.as_bytes_mut() };
        Password {
            inner: Container::BorrowedMut(bytes),
        }
    }
}

impl<'a> From<String> for Password<'a> {
    fn from(s: String) -> Password<'a> {
        Password {
            inner: Container::Owned(s.into_bytes()),
        }
    }
}

impl<'a> From<&'a [u8]> for Password<'a> {
    fn from(bytes: &'a [u8]) -> Password<'a> {
        Password {
            inner: Container::Borrowed(bytes),
        }
    }
}

impl<'a> From<&'a mut [u8]> for Password<'a> {
    fn from(bytes: &'a mut [u8]) -> Password<'a> {
        Password {
            inner: Container::BorrowedMut(bytes),
        }
    }
}

impl<'a> From<&'a Vec<u8>> for Password<'a> {
    fn from(bytes: &'a Vec<u8>) -> Password<'a> {
        Password {
            inner: Container::Borrowed(bytes),
        }
    }
}

impl<'a> From<&'a mut Vec<u8>> for Password<'a> {
    fn from(bytes: &'a mut Vec<u8>) -> Password<'a> {
        Password {
            inner: Container::BorrowedMut(bytes),
        }
    }
}

impl<'a> From<Vec<u8>> for Password<'a> {
    fn from(bytes: Vec<u8>) -> Password<'a> {
        Password {
            inner: Container::Owned(bytes),
        }
    }
}

impl<'a> From<&'a Password<'a>> for Password<'a> {
    fn from(sk: &'a Password<'a>) -> Password<'a> {
        let bytes = match sk.inner {
            Container::Borrowed(ref bytes) => &**bytes,
            Container::BorrowedMut(ref bytes) => &**bytes,
            Container::Owned(ref bytes) => bytes,
        };
        Password {
            inner: Container::Borrowed(bytes),
        }
    }
}

impl<'a> From<&'a mut Password<'a>> for Password<'a> {
    fn from(sk: &'a mut Password<'a>) -> Password<'a> {
        match sk.inner {
            Container::Borrowed(ref bytes) => Password {
                inner: Container::Borrowed(&**bytes),
            },
            Container::BorrowedMut(ref mut bytes) => Password {
                inner: Container::BorrowedMut(&mut **bytes),
            },
            Container::Owned(ref mut bytes) => Password {
                inner: Container::BorrowedMut(&mut *bytes),
            },
        }
    }
}

impl<'a> fmt::Debug for Password<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "****")
    }
}

/// Type-safe struct representing the raw bytes of a password
#[derive(Eq, PartialEq, Hash)]
pub struct Password<'a> {
    pub(crate) inner: Container<'a>,
}

impl<'a> Password<'a> {
    /// Read-only access to the underlying byte buffer
    pub fn as_bytes(&self) -> &[u8] {
        match self.inner {
            Container::Borrowed(ref bytes) => bytes,
            Container::BorrowedMut(ref bytes) => bytes,
            Container::Owned(ref bytes) => bytes,
        }
    }
    /// Indicates whether the underlying byte buffer is mutable or not. The underlying byte
    /// buffer is mutable when the [`Password`](struct.Password.html) was constructed
    /// from an owned value (such as a `String` or a `Vec<u8>`) or from a mutable reference
    /// (such as a `&mut str` or a `&mut [u8]`). It is not mutable when the
    /// [`Password`](struct.Password.html) was constructed from an immutable reference
    /// (such as a `&str` or a `&[u8]`). The [`Password`](struct.Password.html) must be mutable
    /// in order to hash or verify with the `password_clearing` configuration set to `true`
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
    /// [`Password`](struct.Password.html) with a `static` lifetime. Use this method if you
    /// would like to move a [`Password`](struct.Password.html) to another thread
    pub fn to_owned(&self) -> Password<'static> {
        Password {
            inner: self.inner.to_owned(),
        }
    }
    /// Read-only access to the underlying byte buffer as a `&str` if its bytes are valid utf-8
    pub fn to_str(&self) -> Result<&str, Error> {
        let s = ::std::str::from_utf8(self.as_bytes())
            .map_err(|_| Error::new(ErrorKind::Utf8EncodeError))?;
        Ok(s)
    }
}

impl<'a> Password<'a> {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.len() == 0 {
            return Err(Error::new(ErrorKind::PasswordTooShortError));
        }
        if self.len() >= ::std::u32::MAX as usize {
            return Err(Error::new(ErrorKind::PasswordTooLongError)
                .add_context(format!("Length: {}", self.len())));
        }
        Ok(())
    }
}
