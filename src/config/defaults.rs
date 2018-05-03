use config::variant::Variant;
use config::version::Version;

pub const DEFAULT_HASH_LENGTH: u32 = 32;
pub const DEFAULT_ITERATIONS: u32 = 10;
pub const DEFAULT_LANES: u32 = 1;
pub const DEFAULT_MEMORY_SIZE: u32 = 4096;
pub const DEFAULT_SALT_LENGTH: u32 = 32;
pub const DEFAULT_OPT_OUT_OF_RANDOM_SALT: bool = false;
pub const DEFAULT_OPT_OUT_OF_SECRET_KEY: bool = false;
pub const DEFAULT_PASSWORD_CLEARING: bool = true;
pub const DEFAULT_SECRET_KEY_CLEARING: bool = false;
pub const DEFAULT_THREADS: u32 = 1;
pub const DEFAULT_VARIANT: Variant = Variant::Argon2i;
pub const DEFAULT_VERSION: Version = Version::_0x13;
