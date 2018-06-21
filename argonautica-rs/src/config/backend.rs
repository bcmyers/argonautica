use config::defaults::DEFAULT_BACKEND;
use {Error, ErrorKind};

impl Default for Backend {
    /// Returns [`Backend::C`](enum.Backend.html#variant.C)
    fn default() -> Backend {
        DEFAULT_BACKEND
    }
}

/// Enum representing the choice between a
/// [C implementation](https://github.com/P-H-C/phc-winner-argon2/tree/20171227)
/// of the Argon2 algorithm or a Rust implementation. *Currently only a C
/// implemenation is supported. You will get an error if you choose the Rust backend.
/// The intention is to write a Rust implementation in the future.*
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum Backend {
    /// Backend using a
    /// [C implementation](https://github.com/P-H-C/phc-winner-argon2/tree/20171227)
    /// of the Argon2 algorithm
    C = 1,
    /// Placeholder for a currently-unavailable but planned-for-the-future Rust backend.
    /// *You will get an error if you use this backend now.*
    Rust = 2,
}

impl Backend {
    /// Performs the following mapping:
    /// * `1_u32` => `Ok(Backend::C)`<br/>
    /// * `2_u32` => `Ok(Backend::Rust)`<br/>
    /// * anything else => an error
    pub fn from_u32(x: u32) -> Result<Backend, Error> {
        match x {
            1 => Ok(Backend::C),
            2 => Ok(Backend::Rust),
            _ => Err(Error::new(ErrorKind::BackendEncodeError).add_context(format!("Int: {}", x))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Backend>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Backend>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<Backend>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<Backend>();
    }
}
