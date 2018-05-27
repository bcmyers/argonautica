/// Enum representing parsing errors
#[derive(Fail, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum ParseError {
    /// Backend parse error. Failed to parse u32 into Backend
    #[fail(display = "Backend parse error. Failed to parse u32 into Backend")]
    BackendParseError,

    /// Base64 decode error. Invalid base64 encoding
    #[fail(display = "Base64 decode error. Invalid base64 encoding")]
    Base64DecodeError,

    /// Utf-8 error. Failed to parse bytes into a utf-8 encoded String
    #[fail(display = "Utf-8 error. Failed to parse bytes into a utf-8 encoded String")]
    Utf8Error,

    /// Variant parse error. Failed to parse &str into Variant
    #[fail(display = "Variant parse error. Failed to parse &str into Variant")]
    VariantParseError,

    /// Version parse error. Failed to parse &str or u32 into Version
    #[fail(display = "Version parse error. Failed to parse &str or u32 into Version")]
    VersionParseError,

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
        assert_send::<ParseError>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<ParseError>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<ParseError>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<ParseError>();
    }
}
