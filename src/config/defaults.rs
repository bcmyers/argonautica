use num_cpus;

use config::{Backend, Variant, Version};

lazy_static! {
    pub(crate) static ref DEFAULT_LANES: u32 = num_cpus::get_physical() as u32;
    pub(crate) static ref DEFAULT_THREADS: u32 = num_cpus::get_physical() as u32;
}

/// [`Backend::C`](enum.Backend.html#variant.C)
pub const DEFAULT_BACKEND: Backend = Backend::C;

/// `32_u32`
pub const DEFAULT_HASH_LENGTH: u32 = 32;

/// `192_u32`
pub const DEFAULT_ITERATIONS: u32 = 192;

/// `4096_u32`
pub const DEFAULT_MEMORY_SIZE: u32 = 4_096;

/// `32_u32`
pub const DEFAULT_SALT_LENGTH: u32 = 32;

/// `false`
pub const DEFAULT_OPT_OUT_OF_RANDOM_SALT: bool = false;

/// `false`
pub const DEFAULT_OPT_OUT_OF_SECRET_KEY: bool = false;

/// `true`
pub const DEFAULT_PASSWORD_CLEARING: bool = true;

/// `false`
pub const DEFAULT_SECRET_KEY_CLEARING: bool = false;

/// [`Variant::Argon2id`](enum.Variant.html#variant.Argon2id)
pub const DEFAULT_VARIANT: Variant = Variant::Argon2id;

/// [`Version::_0x13`](enum.Version.html#variant._0x13)
pub const DEFAULT_VERSION: Version = Version::_0x13;
