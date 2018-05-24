/// Enum representing the various kinds of errors
#[derive(Fail, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum ErrorKind {
    /// Additional data too long. Length in bytes must be less than 2^32
    #[fail(display = "Additional data too long. Length in bytes must be less than 2^32")]
    AdditionalDataTooLongError,

    /// Rust backend not yet supported. Please use the C backend
    #[fail(display = "Rust backend not yet supported. Please use the C backend")]
    BackendUnsupportedError,

    /// This is a bug in the a2 crate and should not occur. Please file an issue
    #[fail(display = "This is a bug in the a2 crate and should not occur. Please file an issue")]
    Bug,

    /// Failed to decode hash. Hash invalid
    #[fail(display = "Failed to decode hash. Hash invalid")]
    HashDecodingError,

    /// Failed to encode [`HashRaw`](output/struct.HashRaw.html) into hash
    #[fail(display = "Failed to encode HashRaw into hash. HashRaw invalid")]
    HashEncodingError,

    /// Called [`verify`](struct.Verifier.html#method.verify) or
    /// [`verify_non_blocking`](struct.Verifier.html#method.verify_non_blocking) on a
    /// [`Verifier`](struct.Verifier.html) withough first providing a hash or [`HashRaw`](output/struct.HashRaw.html)
    #[fail(display = "Called verify or verify_non_blocking on a Verifier withough first providing a hash or HashRaw")]
    HashNoneError,

    /// Hash length too short. Hash length must be at least 4
    #[fail(display = "Hash length too short. Hash length must be at least 4")]
    HashLengthTooShortError,

    /// Failed to decode base64. Invalid base64
    #[fail(display = "Failed to decode base64. Invalid base64")]
    Base64DecodingError,

    /// Invalid utf-8
    #[fail(display = "Invalid utf-8")]
    InvalidUtf8Error,

    /// Too few iterations. Iterations must be greater than 0
    #[fail(display = "Too few iterations. Iterations must be greater than 0")]
    IterationsTooFewError,

    /// Too few lanes. Lanes must be greater than 0
    #[fail(display = "Too few lanes. Lanes must be greater than 0")]
    LanesTooFewError,

    /// Too many lanes. Lanes must be less than 2^24
    #[fail(display = "Too many lanes. Lanes must be less than 2^24")]
    LanesTooManyError,

    /// Invalid memory size. Memory size must be a power of two
    #[fail(display = "Invalid memory size. Memory size must be a power of two")]
    MemorySizeInvalidError,

    /// Memory size too small. Memory size must be at least 8 times the number of lanes
    #[fail(display = "Memory size too small. Memory size must be at least 8 times the number of lanes")]
    MemorySizeTooSmallError,

    /// Failed to access OS random number generator
    #[fail(display = "Failed to access OS random number generator")]
    OsRngError,

    /// Failed to parse into [`Variant`](config/enum.Variant.html)
    #[fail(display = "Failed to parse into Variant")]
    VariantParseError,

    /// Failed to parse into [`Version`](config/enum.Version.html)
    #[fail(display = "Failed to parse into Version")]
    VersionParseError,

    /// Password too short. Length in bytes must be greater than 0
    #[fail(display = "Password too short. Length in bytes must be greater than 0")]
    PasswordTooShortError,

    /// Password too long. Length in bytes must be less than 2^32
    #[fail(display = "Password too long. Length in bytes must be less than 2^32")]
    PasswordTooLongError,

    /// Attempted to use a non-random salt without having opted out of random salt
    #[fail(display = "Attempted to use a non-random salt without having opted out of random salt")]
    SaltNonRandomError,

    /// Salt too short. Length in bytes must be at least 8
    #[fail(display = "Salt too short. Length in bytes must be at least 8")]
    SaltTooShortError,

    /// Salt too long. Length in bytes must be less than 2^32
    #[fail(display = "Salt too long. Length in bytes must be less than 2^32")]
    SaltTooLongError,

    /// Trying to hash without a secret key when you have not explicitly opted out of using a secret key
    #[fail(display = "Trying to hash without a secret key when you have not explicitly opted out of using a secret key")]
    SecretKeyMissingError,

    /// Secret key too long. Length in bytes must be less than 2^32
    #[fail(display = "Secret key too long. Length in bytes must be less than 2^32")]
    SecretKeyTooLongError,

    /// Too many threads. Threads must be less than 2^24
    #[fail(display = "Too many threads. Threads must be less than 2^24")]
    ThreadsTooManyError,

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
