// TODO: Tests

/// Enum representing encoding / decoding errors
#[derive(Fail, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum EncodingError {
    /// Backend encode error. u32 provided could not be encoded into a Backend
    #[fail(display = "Backend encode error. u32 provided could not be encoded into a Backend")]
    BackendEncodeError,

    /// Base64 decode error. Bytes provided were invalid base64
    #[fail(display = "Base64 decode error. Bytes provided were invalid base64")]
    Base64DecodeError,

    #[cfg(test)]
    /// Hash encode error. HashRaw provided could not be encoded into a hash
    #[fail(display = "Hash encode error. HashRaw provided could not be encoded into a hash")]
    HashEncodeError,

    /// Hash decode error. Hash provided was invalid
    #[fail(display = "Hash decode error. Hash provided was invalid")]
    HashDecodeError,

    /// Utf-8 encode error. Bytes provided could not be encoded into utf-8
    #[fail(display = "Utf-8 encode error. Bytes provided could not be encoded into utf-8")]
    Utf8EncodeError,

    /// Variant encode error. &str provided could not be encoded into a Variant
    #[fail(display = "Variant encode error. &str provided could not be encoded into a Variant")]
    VariantEncodeError,

    /// Version encode error. &str or u32 provided could not be encoded into a Version
    #[fail(
        display = "Version encode error. &str or u32 provided could not be encoded into a Version"
    )]
    VersionEncodeError,

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
        assert_send::<EncodingError>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<EncodingError>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<EncodingError>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<EncodingError>();
    }
}
