//! Enums and defaults for Argon2 configuration options (e.g. `hash_len`,
//! [`Variant`](config/enum.Variant.html), [`Version`](config/enum.Version.html), etc.)
mod backend;
pub(crate) mod defaults;
mod flags;
mod hasher_config;
mod variant;
mod verifier_config;
mod version;

pub use self::backend::Backend;
pub use self::defaults::*;
pub(crate) use self::flags::Flags;
pub use self::hasher_config::HasherConfig;
pub use self::variant::Variant;
pub use self::verifier_config::VerifierConfig;
pub use self::version::Version;
