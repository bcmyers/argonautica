//! Enums and constants representing Argon2 configuration options, e.g. hash length, Argon2
//! version, etc.
//!
//! [RFC](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03)
//! * "If you do not know the difference between them or you consider side-channel attacks as viable threat, choose Argon2id"
//! * Backend server authentication that takes 0.5 seconds on a 2 GHz CPU using 4 cores: Argon2id with 8 lanes and 4 GB of RAM
//! * Key derivation for hard-drive encryption, that takes 3 seconds on a 2 GHz CPU using 2 cores: Argon2id with 4 lanes and 6 GB of RAM.
//! * Frontend server authentication, that takes 0.5 seconds on a 2 GHz CPU using 2 cores: Argon2id with 4 lanes and 1 GB of RAM.
//!
//! Salt: 16 bytes is sufficient for all applications, but can be reduced to 8 bytes in the case of space constraints

pub(crate) mod backend;
pub(crate) mod config;
pub(crate) mod defaults;
pub(crate) mod flags;
pub(crate) mod variant;
pub(crate) mod version;

pub use self::backend::Backend;
pub use self::config::Config;
pub use self::defaults::*;
pub use self::variant::Variant;
pub use self::version::Version;
