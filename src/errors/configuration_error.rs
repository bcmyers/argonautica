/// Enum representing configuration errors
#[derive(Fail, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum ConfigurationError {
    /// Rust backend not yet supported. Please use the C backend
    #[fail(display = "Rust backend not yet supported. Please use the C backend")]
    BackendUnsupportedError,

    /// Hash length too short. Hash length must be at least 4
    #[fail(display = "Hash length too short. Hash length must be at least 4")]
    HashLengthTooShortError,

    /// Iterations too few. Iterations must be greater than 0
    #[fail(display = "Iterations must be greater than 0")]
    IterationsTooFewError,

    /// Lanes too few. Lanes must be greater than 0
    #[fail(display = "Lanes must be greater than 0")]
    LanesTooFewError,

    /// Iterations too many. Lanes must be less than 2^24
    #[fail(display = "Lanes must be less than 2^24")]
    LanesTooManyError,

    /// Memory size invalid. Memory size must be a power of two
    #[fail(display = "Memory size invalid. Memory size must be a power of two")]
    MemorySizeInvalidError,

    /// Memory size too small. Memory size must be at least 8 times the number of lanes
    #[fail(display = "Memory size too small. Memory size must be at least 8 times the number of lanes")]
    MemorySizeTooSmallError,

    /// Threads too few. Threads must be greater than 0
    #[fail(display = "Threads too few. Threads must be greater than 0")]
    ThreadsTooFewError,

    /// Threads too many. Threads must be less than 2^24
    #[fail(display = "Threads too many. Threads must be less than 2^24")]
    ThreadsTooManyError,

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
        assert_send::<ConfigurationError>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<ConfigurationError>();
    }
}
