use errors::{ConfigurationError, DataError, ParseError};

/// Enum representing the various kinds of errors
#[derive(Fail, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum ErrorKind {
    /// This is a bug in the a2 crate and should not occur. Please file an issue
    #[fail(display = "This is a bug in the a2 crate and should not occur. Please file an issue")]
    Bug,

    /// Wrapper for a [`ConfigurationError`](errors/enum.ConfigurationError.html)
    #[fail(display = "{}", _0)]
    ConfigurationError(ConfigurationError),

    /// Wrapper for a [`DataError`](errors/enum.DataError.html)
    #[fail(display = "{}", _0)]
    DataError(DataError),

    /// Failed to access OS random number generator
    #[fail(display = "Failed to access OS random number generator")]
    OsRngError,

    /// Wrapper for a [`ParseError`](errors/enum.ParseError.html)
    #[fail(display = "{}", _0)]
    ParseError(ParseError),

    #[doc(hidden)]
    #[fail(display = "__Nonexaustive ErrorKind variant")]
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
}
