use std::fmt;

use failure;

use error::ErrorKind;

impl failure::Fail for Error {
    fn cause(&self) -> Option<&failure::Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&failure::Backtrace> {
        self.inner.backtrace()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error { inner: failure::Context::new(kind) }
    }
}

impl From<failure::Context<ErrorKind>> for Error {
    fn from(inner: failure::Context<ErrorKind>) -> Error {
        Error { inner: inner }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

#[derive(Debug)]
pub struct Error {
    inner: failure::Context<ErrorKind>,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        *self.inner.get_context()
    }
}
