use num_cpus;

use config::backend::Backend;
use config::variant::Variant;
use config::version::Version;

lazy_static! {
    pub static ref DEFAULT_LANES: u32 = num_cpus::get_physical() as u32;
    pub static ref DEFAULT_THREADS: u32 = num_cpus::get_physical() as u32;
}

pub const DEFAULT_BACKEND: Backend = Backend::C;
pub const DEFAULT_HASH_LENGTH: u32 = 32;
pub const DEFAULT_ITERATIONS: u32 = 128;
pub const DEFAULT_MEMORY_SIZE: u32 = 4_096;
pub const DEFAULT_SALT_LENGTH: u32 = 32;
pub const DEFAULT_OPT_OUT_OF_RANDOM_SALT: bool = false;
pub const DEFAULT_OPT_OUT_OF_SECRET_KEY: bool = false;
pub const DEFAULT_PASSWORD_CLEARING: bool = true;
pub const DEFAULT_SECRET_KEY_CLEARING: bool = false;
pub const DEFAULT_VARIANT: Variant = Variant::Argon2id;
pub const DEFAULT_VERSION: Version = Version::_0x13;
