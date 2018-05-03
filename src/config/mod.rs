//! Enums and constants representing Argon2 configuration options, e.g. hash length, Argon2
//! version, etc.

pub(crate) mod config;
pub(crate) mod defaults;
pub(crate) mod flags;
pub(crate) mod variant;
pub(crate) mod version;

pub use self::config::Config;
pub use self::defaults::*;
pub use self::variant::Variant;
pub use self::version::Version;
