use base64::DecodeError;
use rand::Error as RandError;
use std::str::Utf8Error;
use thiserror::Error;

/// Enum representing the various kinds of errors
#[derive(Error, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum Error {
    /// Additional data too long. Length in bytes must be less than 2^32
    #[error("Additional data too long. Length in bytes must be less than 2^32, Length: {0}")]
    AdditionalDataTooLongError(usize),

    /// Backend encode error. u32 provided could not be encoded into a Backend
    #[error("Backend encode error. u32 provided could not be encoded into a Backend")]
    BackendEncodeError,

    /// Rust backend not yet supported. Please use the C backend
    #[error("Rust backend not yet supported. Please use the C backend")]
    BackendUnsupportedError,

    /// Base64 decode error. Bytes provided were invalid base64
    #[error("Base64 decode error. Bytes provided were invalid base64")]
    Base64DecodeError(#[source] DecodeError),

    /// This is a bug in the argonautica crate and should be unreachable. Please file an issue
    #[error("This is a bug in the argonautica crate and should be unreachable. Please file an issue. Message: {0}")]
    Bug(String),

    /// Hash decode error. Hash provided was invalid
    #[error("Hash decode error. Hash provided was invalid")]
    HashDecodeError(#[source] DecodeError),

    #[cfg(test)]
    /// Hash encode error. HashRaw provided could not be encoded into a hash
    #[error("Hash encode error. HashRaw provided could not be encoded into a hash")]
    HashEncodeError,

    /// Hash length too short. Hash length must be at least 4
    #[error("Hash length too short. Hash length must be at least 4, Length: {0}")]
    HashLenTooShortError(u32),

    /// Hash missing. Attempted to verify without first having provided a hash
    #[error("Hash missing. Attempted to verify without first having provided a hash")]
    HashMissingError,

    /// Iterations too few. Iterations must be greater than 0
    #[error("Iterations must be greater than 0, Length: {0}")]
    IterationsTooFewError(u32),

    /// Lanes too few. Lanes must be greater than 0
    #[error("Lanes must be greater than 0, Lanes: {0}")]
    LanesTooFewError(u32),

    /// Lanes too many. Lanes must be less than 2^24
    #[error("Lanes must be less than 2^24, Lanes: {0}")]
    LanesTooManyError(u32),

    /// C code attempted to allocate memory (using malloc) and failed
    #[error("C code attempted to allocate memory (using malloc) and failed")]
    MemoryAllocationError,

    /// Memory size invalid. Memory size must be a power of two
    #[error("Memory size invalid. Memory size must be a power of two, Memory size: {0}")]
    MemorySizeInvalidError(u32),

    /// Memory size too small. Memory size must be at least 8 times the number of lanes
    #[error("Memory size too small. Memory size must be at least 8 times the number of lanes. Lanes: {lanes}. Memory size: {memory_size}")]
    MemorySizeTooSmallError { lanes: u32, memory_size: u32 },

    /// Failed to access OS random number generator
    #[error("Failed to access OS random number generator")]
    OsRngError(#[source] RandError),

    /// Password immutable error. You attempted to hash or verify with an immutable password and password_clearing set to true, which is not possible because with an immutable password argonautica cannot zero out the password bytes. To prevent this error, either pass Hasher or Verifier a mutable password or set password_clearing to false
    #[error("Password immutable error. You attempted to hash or verify with an immutable password and password_clearing set to true, which is not possible because with an immutable password argonautica cannot zero out the password bytes. To prevent this error, either pass Hasher or Verifier a mutable password or set password_clearing to false")]
    PasswordImmutableError,

    /// Password missing. Attempted to verify without first having provided a password
    #[error("Password missing. Attempted to verify without first having provided a password")]
    PasswordMissingError,

    /// Password too long. Length in bytes must be less than 2^32
    #[error("Password too long. Length in bytes must be less than 2^32, Length: {0}")]
    PasswordTooLongError(usize),

    /// Password too short. Length in bytes must be greater than 0
    #[error("Password too short. Length in bytes must be greater than 0")]
    PasswordTooShortError,

    /// Salt too long. Length in bytes must be less than 2^32
    #[error("Salt too long. Length in bytes must be less than 2^32, Length: {0}")]
    SaltTooLongError(usize),

    /// Salt too short. Length in bytes must be at least 8
    #[error("Salt too short. Length in bytes must be at least 8, Length: {0}")]
    SaltTooShortError(usize),

    /// Secret key immutable error. You attempted to hash or verify with an immutable secret key and secret_key_clearing set to true, which is not possible because with an immutable secret key argonautica cannot zero out the secret key bytes. To prevent this error, either pass Hasher or Verifier a mutable secret key or set secret_key_clearing to false
    #[error("Secret key immutable error. You attempted to hash or verify with an immutable secret key and secret_key_clearing set to true, which is not possible because with an immutable secret key argonautica cannot zero out the secret key bytes. To prevent this error, either pass Hasher or Verifier a mutable secret key or set secret_key_clearing to false")]
    SecretKeyImmutableError,

    /// Secret key missing. Attempted to hash without a secret key without having first opted out of using a secret key
    #[error("Secret key missing. Attempted to hash without a secret key without having first opted out of using a secret key")]
    SecretKeyMissingError,

    /// Secret key too long. Length in bytes must be less than 2^32
    #[error("Secret key too long. Length in bytes must be less than 2^32, Length: {0}")]
    SecretKeyTooLongError(usize),

    /// C code reported a "Threading failure" error
    #[error("C code reported a \"Threading failure\" error")]
    ThreadError,

    /// Threads too few. Threads must be greater than 0
    #[error("Threads too few. Threads must be greater than 0, Threads: {0}")]
    ThreadsTooFewError(u32),

    /// Threads too many. Threads must be less than 2^24
    #[error("Threads too many. Threads must be less than 2^24, Threads: {0}")]
    ThreadsTooManyError(u32),

    /// Utf-8 encode error. Bytes provided could not be encoded into utf-8
    #[error("Utf-8 encode error. Bytes provided could not be encoded into utf-8")]
    Utf8EncodeError(#[source] Utf8Error),

    /// Variant encode error. &str provided could not be encoded into a Variant
    #[error(
        "Variant encode error. &str provided could not be encoded into a Variant, String: {0}"
    )]
    VariantEncodeError(String),

    /// Version encode error. &str or u32 provided could not be encoded into a Version
    #[error("Version encode error. &str or u32 provided could not be encoded into a Version, {0}")]
    VersionEncodeError(String),

    #[doc(hidden)]
    #[error("__Nonexaustive variant")]
    __Nonexhaustive,
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
