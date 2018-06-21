use std::fmt;

use ErrorKind;

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "argonautica::Error {{ kind: argonautica::ErrorKind::{:?}, display: {:?} }}",
            self.kind, self.display,
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.display)
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error::new(kind)
    }
}

/// Struct representing an error, which implements the
/// [`Fail`](https://docs.rs/failure/0.1.1/failure/trait.Fail.html) trait
/// from [failure](https://github.com/rust-lang-nursery/failure)
#[derive(Fail, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Error {
    kind: ErrorKind,
    display: String,
}

impl Error {
    /// Creates a new [`Error`](struct.Error.html)
    pub fn new(kind: ErrorKind) -> Error {
        let display = format!("{}", &kind);
        Error { display, kind }
    }
    /// Adds additional context to the [`Error`](struct.Error.html). The additional context will be appended to
    /// the end of the [`Error`](struct.Error.html)'s display string
    pub fn add_context<S>(mut self, context: S) -> Error
    where
        S: AsRef<str>
    {
        self.display = format!("{}: {}", self.kind, context.as_ref());
        self
    }
    /// Gets the [`ErrorKind`](enum.ErrorKind.html) associated with the [`Error`](struct.Error.html)
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Error>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Error>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<Error>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<Error>();
    }
}
