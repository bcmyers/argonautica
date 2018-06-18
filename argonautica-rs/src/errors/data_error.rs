// TODO: Tests

/// Enum representing data or input errors
#[derive(Fail, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum DataError {
    /// Additional data too long. Length in bytes must be less than 2^32
    #[fail(display = "Additional data too long. Length in bytes must be less than 2^32")]
    AdditionalDataTooLongError,

    /// Hash missing. Attempted to verify without first having provided a hash
    #[fail(display = "Hash missing. Attempted to verify without first having provided a hash")]
    HashMissingError,

    /// Password missing. Attempted to verify without first having provided a password
    #[fail(
        display = "Password missing. Attempted to verify without first having provided a password"
    )]
    PasswordMissingError,

    /// Password too short. Length in bytes must be greater than 0
    #[fail(display = "Password too short. Length in bytes must be greater than 0")]
    PasswordTooShortError,

    /// Password too long. Length in bytes must be less than 2^32
    #[fail(display = "Password too long. Length in bytes must be less than 2^32")]
    PasswordTooLongError,

    /// Password unowned error. You attempted to hash or verify with a borrowed password and 'password clearing' set to true, which is not possible because with a borrowed value argonautica cannot zero out the password bytes. To prevent this error, either pass Hasher or Verifier an owned password or set 'password clearing' to false
    #[fail(
        display = "Password unowned error. You attempted to hash or verify with a borrowed password and 'password clearing' set to true, which is not possible because with a borrowed value argonautica cannot zero out the password bytes. To prevent this error, either pass Hasher or Verifier an owned password or set 'password clearing' to false"
    )]
    PasswordUnownedError,

    /// Salt too short. Length in bytes must be at least 8
    #[fail(display = "Salt too short. Length in bytes must be at least 8")]
    SaltTooShortError,

    /// Salt too long. Length in bytes must be less than 2^32
    #[fail(display = "Salt too long. Length in bytes must be less than 2^32")]
    SaltTooLongError,

    /// Secret key missing. Attempted to hash without a secret key without having first opted out of using a secret key
    #[fail(
        display = "Secret key missing. Attempted to hash without a secret key without having first opted out of using a secret key"
    )]
    SecretKeyMissingError,

    /// Secret key too long. Length in bytes must be less than 2^32
    #[fail(display = "Secret key too long. Length in bytes must be less than 2^32")]
    SecretKeyTooLongError,

    /// Secret key unowned error. You attempted to hash or verify with a borrowed secret key and 'secret key clearing' set to true, which is not possible because with a borrowed value argonautica cannot zero out the secret key bytes. To prevent this error, either pass Hasher or Verifier an owned secret key or set 'secret key clearing' to false
    #[fail(
        display = "Secret key unowned error. You attempted to hash or verify with a borrowed secret key and 'secret key clearing' set to true, which is not possible because with a borrowed value argonautica cannot zero out the secret key bytes. To prevent this error, either pass Hasher or Verifier an owned secret key or set 'secret key clearing' to false"
    )]
    SecretKeyUnownedError,

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
        assert_send::<DataError>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<DataError>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<DataError>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<DataError>();
    }
}
