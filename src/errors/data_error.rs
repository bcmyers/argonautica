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

    /// Hash invalid
    #[fail(display = "Hash invalid")]
    HashInvalidError,

    /// Password missing. Attempted to verify without first having provided a password
    #[fail(display = "Password missing. Attempted to verify without first having provided a password")]
    PasswordMissingError,

    /// Password too short. Length in bytes must be greater than 0
    #[fail(display = "Password too short. Length in bytes must be greater than 0")]
    PasswordTooShortError,

    /// Password too long. Length in bytes must be less than 2^32
    #[fail(display = "Password too long. Length in bytes must be less than 2^32")]
    PasswordTooLongError,

    /// Attempted to use a non-random salt without first having opted out of random salt
    #[fail(display = "Attempted to use a non-random salt without first having opted out of random salt")]
    SaltNonRandomError,

    /// Salt too short. Length in bytes must be at least 8
    #[fail(display = "Salt too short. Length in bytes must be at least 8")]
    SaltTooShortError,

    /// Salt too long. Length in bytes must be less than 2^32
    #[fail(display = "Salt too long. Length in bytes must be less than 2^32")]
    SaltTooLongError,

    /// Secret key missing. Attempted to hash without a secret key without having first opted out of using a secret key
    #[fail(display = "Secret key missing. Attempted to hash without a secret key without having first opted out of using a secret key")]
    SecretKeyMissingError,

    /// Secret key too long. Length in bytes must be less than 2^32
    #[fail(display = "Secret key too long. Length in bytes must be less than 2^32")]
    SecretKeyTooLongError,

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
}
