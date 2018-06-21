/// Enum representing the various kinds of errors
#[derive(Fail, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum ErrorKind {
    /// Additional data too long. Length in bytes must be less than 2^32
    #[fail(display = "Additional data too long. Length in bytes must be less than 2^32")]
    AdditionalDataTooLongError,

    /// Backend encode error. u32 provided could not be encoded into a Backend
    #[fail(display = "Backend encode error. u32 provided could not be encoded into a Backend")]
    BackendEncodeError,

    /// Rust backend not yet supported. Please use the C backend
    #[fail(display = "Rust backend not yet supported. Please use the C backend")]
    BackendUnsupportedError,

    /// Base64 decode error. Bytes provided were invalid base64
    #[fail(display = "Base64 decode error. Bytes provided were invalid base64")]
    Base64DecodeError,

    /// This is a bug in the argonautica crate and should be unreachable. Please file an issue
    #[fail(
        display = "This is a bug in the argonautica crate and should be unreachable. Please file an issue"
    )]
    Bug,

    /// Hash decode error. Hash provided was invalid
    #[fail(display = "Hash decode error. Hash provided was invalid")]
    HashDecodeError,

    #[cfg(test)]
    /// Hash encode error. HashRaw provided could not be encoded into a hash
    #[fail(display = "Hash encode error. HashRaw provided could not be encoded into a hash")]
    HashEncodeError,

    /// Hash length too short. Hash length must be at least 4
    #[fail(display = "Hash length too short. Hash length must be at least 4")]
    HashLenTooShortError,

    /// Hash missing. Attempted to verify without first having provided a hash
    #[fail(display = "Hash missing. Attempted to verify without first having provided a hash")]
    HashMissingError,

    /// Iterations too few. Iterations must be greater than 0
    #[fail(display = "Iterations must be greater than 0")]
    IterationsTooFewError,

    /// Lanes too few. Lanes must be greater than 0
    #[fail(display = "Lanes must be greater than 0")]
    LanesTooFewError,

    /// Lanes too many. Lanes must be less than 2^24
    #[fail(display = "Lanes must be less than 2^24")]
    LanesTooManyError,

    /// C code attempted to allocate memory (using malloc) and failed
    #[fail(display = "C code attempted to allocate memory (using malloc) and failed")]
    MemoryAllocationError,

    /// Memory size invalid. Memory size must be a power of two
    #[fail(display = "Memory size invalid. Memory size must be a power of two")]
    MemorySizeInvalidError,

    /// Memory size too small. Memory size must be at least 8 times the number of lanes
    #[fail(
        display = "Memory size too small. Memory size must be at least 8 times the number of lanes"
    )]
    MemorySizeTooSmallError,

    /// Failed to access OS random number generator
    #[fail(display = "Failed to access OS random number generator")]
    OsRngError,

    /// Password immutable error. You attempted to hash or verify with an immutable password and password_clearing set to true, which is not possible because with an immutable password argonautica cannot zero out the password bytes. To prevent this error, either pass Hasher or Verifier a mutable password or set password_clearing to false
    #[fail(
        display = "Password immutable error. You attempted to hash or verify with an immutable password and password_clearing set to true, which is not possible because with an immutable password argonautica cannot zero out the password bytes. To prevent this error, either pass Hasher or Verifier a mutable password or set password_clearing to false"
    )]
    PasswordImmutableError,

    /// Password missing. Attempted to verify without first having provided a password
    #[fail(
        display = "Password missing. Attempted to verify without first having provided a password"
    )]
    PasswordMissingError,

    /// Password too long. Length in bytes must be less than 2^32
    #[fail(display = "Password too long. Length in bytes must be less than 2^32")]
    PasswordTooLongError,

    /// Password too short. Length in bytes must be greater than 0
    #[fail(display = "Password too short. Length in bytes must be greater than 0")]
    PasswordTooShortError,

    /// Salt too long. Length in bytes must be less than 2^32
    #[fail(display = "Salt too long. Length in bytes must be less than 2^32")]
    SaltTooLongError,

    /// Salt too short. Length in bytes must be at least 8
    #[fail(display = "Salt too short. Length in bytes must be at least 8")]
    SaltTooShortError,

    /// Secret key immutable error. You attempted to hash or verify with an immutable secret key and secret_key_clearing set to true, which is not possible because with an immutable secret key argonautica cannot zero out the secret key bytes. To prevent this error, either pass Hasher or Verifier a mutable secret key or set secret_key_clearing to false
    #[fail(
        display = "Secret key immutable error. You attempted to hash or verify with an immutable secret key and secret_key_clearing set to true, which is not possible because with an immutable secret key argonautica cannot zero out the secret key bytes. To prevent this error, either pass Hasher or Verifier a mutable secret key or set secret_key_clearing to false"
    )]
    SecretKeyImmutableError,

    /// Secret key missing. Attempted to hash without a secret key without having first opted out of using a secret key
    #[fail(
        display = "Secret key missing. Attempted to hash without a secret key without having first opted out of using a secret key"
    )]
    SecretKeyMissingError,

    /// Secret key too long. Length in bytes must be less than 2^32
    #[fail(display = "Secret key too long. Length in bytes must be less than 2^32")]
    SecretKeyTooLongError,

    /// C code reported a "Threading failure" error
    #[fail(display = "C code reported a \"Threading failure\" error")]
    ThreadError,

    /// Threads too few. Threads must be greater than 0
    #[fail(display = "Threads too few. Threads must be greater than 0")]
    ThreadsTooFewError,

    /// Threads too many. Threads must be less than 2^24
    #[fail(display = "Threads too many. Threads must be less than 2^24")]
    ThreadsTooManyError,

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
