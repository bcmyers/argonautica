use config::defaults::DEFAULT_BACKEND;

/// Enum representing the choice between a [C implementation](https://github.com/P-H-C/phc-winner-argon2/tree/20171227)
/// of the Argon2 algorithm or a `Rust implementation` of the Argon2 algorithm. *Currently only a C
/// implemenation is supported. You will get a runtime error if you choose the Rust backend.
/// The intention is to write a Rust implementation in the future.*
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Backend {
    /// Backend using a [C implementation](https://github.com/P-H-C/phc-winner-argon2/tree/20171227)
    /// of the Argon2 algorithm
    C,
    /// Placeholder for a currently-unavailable but planned-for-the-future Rust backend.
    /// *You will get a runtime error if you use this backend now.*
    Rust,
}

impl Default for Backend {
    fn default() -> Backend {
        DEFAULT_BACKEND
    }
}
