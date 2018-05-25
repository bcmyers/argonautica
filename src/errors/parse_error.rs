/// Enum representing parsing errors
#[derive(Fail, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum ParseError {
    /// Base64 parse error. Failed to parse &str into bytes
    #[fail(display = "Base64 parse error. Failed to parse &str into bytes")]
    Base64ParseError,

    /// Hash parse error. Invalid hash
    #[fail(display = "Hash parse error. Invalid hash")]
    HashParseError,

    /// Utf8 parse error. Failed to parse bytes into utf8 String
    #[fail(display = "Utf8 parse error. Failed to parse bytes into utf8 String")]
    Utf8ParseError,

    /// Variant parse error. Failed to parse &str into Variant
    #[fail(display = "Variant parse error. Failed to parse &str into Variant")]
    VariantParseError,

    /// Version parse error. Failed to parse &str or u32 into Version
    #[fail(display = "Version parse error. Failed to parse &str or u32 into Version")]
    VersionParseError,

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
        assert_send::<ParseError>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<ParseError>();
    }
}
