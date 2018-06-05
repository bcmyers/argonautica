// TODO: Tests

use errors::{ConfigurationError, DataError, EncodingError};

/// Enum representing the various kinds of errors
#[derive(Fail, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum ErrorKind {
    /// This is a bug in the jasonus crate and should not occur. Please file an issue
    #[fail(
        display = "This is a bug in the jasonus crate and should not occur. Please file an issue"
    )]
    Bug,

    /// Wrapper for a [`ConfigurationError`](errors/enum.ConfigurationError.html)
    #[fail(display = "{}", _0)]
    ConfigurationError(ConfigurationError),

    /// Wrapper for a [`DataError`](errors/enum.DataError.html)
    #[fail(display = "{}", _0)]
    DataError(DataError),

    /// Wrapper for a [`EncodingError`](errors/enum.EncodingError.html)
    #[fail(display = "{}", _0)]
    EncodingError(EncodingError),

    /// C code attempted to allocate memory (using malloc) and failed
    #[fail(display = "C code attempted to allocate memory (using malloc) and failed")]
    MemoryAllocationError,

    /// Failed to access OS random number generator
    #[fail(display = "Failed to access OS random number generator")]
    OsRngError,

    /// C code reported a "Threading failure" error
    #[fail(display = "C code reported a \"Threading failure\" error")]
    ThreadError,

    #[doc(hidden)]
    #[fail(display = "__Nonexaustive variant")]
    __Nonexhaustive,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ErrorKind>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<ErrorKind>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<ErrorKind>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<ErrorKind>();
    }
}
