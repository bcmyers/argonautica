use failure;

use config::defaults::*;
use config::flags::Flags;
use config::variant::Variant;
use config::version::Version;

const PANIC_WARNING: &str = "Your program will panic at runtime if you call hash or hash_raw on a Hasher with this configuration";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Config {
    hash_length: u32,
    iterations: u32,
    lanes: u32,
    memory_size: u32,
    opt_out_of_random_salt: bool,
    opt_out_of_secret_key: bool,
    password_clearing: bool,
    secret_key_clearing: bool,
    threads: u32,
    variant: Variant,
    version: Version,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            hash_length: DEFAULT_HASH_LENGTH,
            iterations: DEFAULT_ITERATIONS,
            lanes: DEFAULT_LANES,
            memory_size: DEFAULT_MEMORY_SIZE,
            opt_out_of_random_salt: DEFAULT_OPT_OUT_OF_RANDOM_SALT,
            opt_out_of_secret_key: DEFAULT_OPT_OUT_OF_SECRET_KEY,
            password_clearing: DEFAULT_PASSWORD_CLEARING,
            secret_key_clearing: DEFAULT_SECRET_KEY_CLEARING,
            threads: DEFAULT_THREADS,
            variant: DEFAULT_VARIANT,
            version: DEFAULT_VERSION,
        }
    }
}

impl Config {
    pub fn hash_length(&self) -> u32 {
        self.hash_length
    }
    pub fn iterations(&self) -> u32 {
        self.iterations
    }
    pub fn lanes(&self) -> u32 {
        self.lanes
    }
    pub fn memory_size(&self) -> u32 {
        self.memory_size
    }
    pub fn opt_out_of_random_salt(&self) -> bool {
        self.opt_out_of_random_salt
    }
    pub fn opt_out_of_secret_key(&self) -> bool {
        self.opt_out_of_secret_key
    }
    pub fn password_clearing(&self) -> bool {
        self.password_clearing
    }
    pub fn secret_key_clearing(&self) -> bool {
        self.secret_key_clearing
    }
    pub fn threads(&self) -> u32 {
        self.threads
    }
    pub fn variant(&self) -> Variant {
        self.variant
    }
    pub fn version(&self) -> Version {
        self.version
    }
    pub(crate) fn flags(&self) -> Flags {
        let mut flags = Flags::default();
        if self.password_clearing() {
            flags = flags | Flags::CLEAR_PASSWORD;
        }
        if self.secret_key_clearing() {
            flags = flags | Flags::CLEAR_SECRET_KEY;
        }
        flags
    }

    pub fn set_hash_length(&mut self, hash_length: u32) {
        validate_hash_length(hash_length).unwrap_or_else(|e| {
            warn!("{}. {}.", e, PANIC_WARNING);
        });
        self.hash_length = hash_length;
    }
    pub fn set_iterations(&mut self, iterations: u32) {
        validate_iterations(iterations).unwrap_or_else(|e| {
            warn!("{}. {}.", e, PANIC_WARNING);
        });
        self.iterations = iterations;
    }
    pub fn set_lanes(&mut self, lanes: u32) {
        validate_lanes(lanes).unwrap_or_else(|e| {
            warn!("{}. {}.", e, PANIC_WARNING);
        });
        self.lanes = lanes;
    }
    pub fn set_memory_size(&mut self, memory_size: u32) {
        validate_memory_size(memory_size).unwrap_or_else(|e| {
            warn!("{}. {}.", e, PANIC_WARNING);
        });
        self.memory_size = memory_size;
    }
    pub fn set_opt_out_of_random_salt(&mut self, boolean: bool) {
        self.opt_out_of_random_salt = boolean;
    }
    pub fn set_opt_out_of_secret_key(&mut self, boolean: bool) {
        self.opt_out_of_secret_key = boolean;
    }
    pub fn set_password_clearing(&mut self, boolean: bool) {
        self.password_clearing = boolean;
    }
    pub fn set_secret_key_clearing(&mut self, boolean: bool) {
        self.secret_key_clearing = boolean;
    }
    pub fn set_threads(&mut self, threads: u32) {
        validate_threads(threads).unwrap_or_else(|e| {
            warn!("{}. {}.", e, PANIC_WARNING);
        });
        self.threads = threads;
    }
    pub fn set_variant(&mut self, variant: Variant) {
        self.variant = variant;
    }
    pub fn set_version(&mut self, version: Version) {
        if version != DEFAULT_VERSION {
            warn!(
                "Version configuration set to {:?}, whereas the lastest version is {:?}. \
                 Are you sure you want to use an old version of the Argon2 algorithm?",
                version, DEFAULT_VERSION,
            );
        }
        self.version = version;
    }

    pub fn validate(&self) -> Result<(), failure::Error> {
        validate_hash_length(self.hash_length)?;
        validate_lanes(self.lanes)?;
        validate_iterations(self.iterations)?;
        validate_memory_size(self.memory_size)?;
        validate_threads(self.threads)?;
        Ok(())
    }
}

fn validate_hash_length(hash_length: u32) -> Result<(), failure::Error> {
    if hash_length < 4 {
        bail!("Hash length configuration is too short. It must be greater than 4")
    }
    Ok(())
}

fn validate_iterations(iterations: u32) -> Result<(), failure::Error> {
    if iterations == 0 {
        bail!("Iterations configuration cannot be zero")
    }
    Ok(())
}

fn validate_lanes(_lanes: u32) -> Result<(), failure::Error> {
    // TODO
    Ok(())
}

fn validate_memory_size(memory_size: u32) -> Result<(), failure::Error> {
    if memory_size < 8 {
        bail!("Memory size configuration is too short. It must be greater than 8")
    }
    if !(memory_size.is_power_of_two()) {
        bail!("Memory size configuration is invalid. It must be a power of two")
    }
    Ok(())
}

fn validate_threads(_threads: u32) -> Result<(), failure::Error> {
    // TODO
    Ok(())
}
