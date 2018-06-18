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
    HashLenTooShortError,

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
    #[fail(
        display = "Memory size too small. Memory size must be at least 8 times the number of lanes"
    )]
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
    use config::Backend;
    use {ErrorKind, Hasher, Verifier};

    fn hasher() -> Hasher {
        let mut hasher = Hasher::default();
        hasher
            .configure_password_clearing(false)
            .configure_secret_key_clearing(false)
            .with_password("P@ssw0rd");
        hasher
    }

    fn verifier() -> Verifier {
        let mut verifier = Verifier::default();
        verifier
            .configure_password_clearing(false)
            .configure_secret_key_clearing(false)
            .with_hash("$argon2i$v=19$m=32,t=32,p=4$Tk9NRmV3WUE$IAvmo59b12w")
            .with_password("P@ssw0rd");
        verifier
    }

    #[test]
    fn test_error_backend_unsupported() {
        let mut hasher = hasher();
        let result = hasher.configure_backend(Backend::Rust).hash();
        match result {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(
                e.kind(),
                ErrorKind::ConfigurationError(ConfigurationError::BackendUnsupportedError)
            ),
        }

        let mut verifier = verifier();
        let result = verifier.configure_backend(Backend::Rust).verify();
        match result {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(
                e.kind(),
                ErrorKind::ConfigurationError(ConfigurationError::BackendUnsupportedError)
            ),
        }
    }

    #[test]
    fn test_error_hash_len_too_short() {
        let mut hasher = hasher();
        let result = hasher.configure_hash_len(3).hash();
        match result {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(
                e.kind(),
                ErrorKind::ConfigurationError(ConfigurationError::HashLenTooShortError)
            ),
        }
    }

    #[test]
    fn test_error_iterations_too_few() {
        let mut hasher = hasher();
        let result = hasher.configure_iterations(0).hash();
        match result {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(
                e.kind(),
                ErrorKind::ConfigurationError(ConfigurationError::IterationsTooFewError)
            ),
        }
    }

    #[test]
    fn test_error_lanes_too_few() {
        let mut hasher = hasher();
        let result = hasher.configure_lanes(0).hash();
        match result {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(
                e.kind(),
                ErrorKind::ConfigurationError(ConfigurationError::LanesTooFewError)
            ),
        }
    }

    #[test]
    fn test_error_lanes_too_many() {
        let mut hasher = hasher();
        let result = hasher.configure_lanes(2u32.pow(24)).hash();
        match result {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(
                e.kind(),
                ErrorKind::ConfigurationError(ConfigurationError::LanesTooManyError)
            ),
        }
    }

    #[test]
    fn test_error_memory_size_invalid() {
        for i in 4..10 {
            let mut hasher = hasher();
            let result = hasher
                .configure_lanes(1)
                .configure_memory_size(2u32.pow(i) + 1)
                .hash();
            match result {
                Ok(_) => panic!(),
                Err(e) => assert_eq!(
                    e.kind(),
                    ErrorKind::ConfigurationError(ConfigurationError::MemorySizeInvalidError)
                ),
            }
        }
    }

    #[test]
    fn test_error_memory_size_too_small() {
        let memory_pow = |lanes: u32| -> u32 {
            let mut i = 1;
            loop {
                let memory_size = 2u32.pow(i);
                if memory_size < 8 * lanes {
                    i += 1;
                    continue;
                }
                return i;
            }
        };
        for lanes in 1..10 {
            let mut hasher = hasher();
            let result = hasher
                .configure_lanes(lanes)
                .configure_memory_size(2u32.pow(memory_pow(lanes) - 1))
                .hash();
            match result {
                Ok(_) => panic!(),
                Err(e) => assert_eq!(
                    e.kind(),
                    ErrorKind::ConfigurationError(ConfigurationError::MemorySizeTooSmallError)
                ),
            }
        }
    }

    #[test]
    fn test_error_threads_too_few() {
        let mut hasher = hasher();
        let result = hasher.configure_threads(0).hash();
        match result {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(
                e.kind(),
                ErrorKind::ConfigurationError(ConfigurationError::ThreadsTooFewError)
            ),
        }
    }

    #[test]
    fn test_error_threads_too_many() {
        let mut hasher = hasher();
        let result = hasher.configure_threads(2u32.pow(24)).hash();
        match result {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(
                e.kind(),
                ErrorKind::ConfigurationError(ConfigurationError::ThreadsTooManyError)
            ),
        }
    }

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

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<ConfigurationError>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<ConfigurationError>();
    }
}
