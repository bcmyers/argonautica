use config::defaults::{DEFAULT_HASH_LENGTH, DEFAULT_ITERATIONS, DEFAULT_LANES,
                       DEFAULT_MEMORY_SIZE, DEFAULT_OPT_OUT_OF_RANDOM_SALT,
                       DEFAULT_OPT_OUT_OF_SECRET_KEY, DEFAULT_PASSWORD_CLEARING,
                       DEFAULT_SECRET_KEY_CLEARING, DEFAULT_THREADS, DEFAULT_VERSION};
use config::{Backend, Flags, Variant, Version};
use errors::ConfigurationError;
use {Error, ErrorKind};

const PANIC_WARNING: &str = "Your program will panic at runtime if you use this configuration";

/// Read-only configuration for [`Hasher`](../struct.Hasher.html). Can be obtained by calling
/// the [`config`](../struct.Hasher.html#method.config) method on an instance of [`Hasher`](../struct.Hasher.html)
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct HasherConfig {
    backend: Backend,
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

impl HasherConfig {
    pub fn backend(&self) -> Backend {
        self.backend
    }
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
}

impl HasherConfig {
    pub(crate) fn default() -> HasherConfig {
        HasherConfig {
            backend: Backend::default(),
            hash_length: DEFAULT_HASH_LENGTH,
            iterations: DEFAULT_ITERATIONS,
            lanes: *DEFAULT_LANES,
            memory_size: DEFAULT_MEMORY_SIZE,
            opt_out_of_random_salt: DEFAULT_OPT_OUT_OF_RANDOM_SALT,
            opt_out_of_secret_key: DEFAULT_OPT_OUT_OF_SECRET_KEY,
            password_clearing: DEFAULT_PASSWORD_CLEARING,
            secret_key_clearing: DEFAULT_SECRET_KEY_CLEARING,
            threads: *DEFAULT_THREADS,
            variant: Variant::default(),
            version: Version::default(),
        }
    }
    pub(crate) fn flags(&self) -> Flags {
        let mut flags = Flags::default();
        if self.password_clearing() {
            flags |= Flags::CLEAR_PASSWORD;
        }
        if self.secret_key_clearing() {
            flags |= Flags::CLEAR_SECRET_KEY;
        }
        flags
    }
    pub(crate) fn set_backend(&mut self, backend: Backend) {
        validate_backend(backend).unwrap_or_else(|e| {
            warn!("{}. {}.", e, PANIC_WARNING);
        });
        self.backend = backend;
    }
    pub(crate) fn set_hash_length(&mut self, hash_length: u32) {
        validate_hash_length(hash_length).unwrap_or_else(|e| {
            warn!("{}. {}.", e, PANIC_WARNING);
        });
        self.hash_length = hash_length;
    }
    pub(crate) fn set_iterations(&mut self, iterations: u32) {
        validate_iterations(iterations).unwrap_or_else(|e| {
            warn!("{}. {}.", e, PANIC_WARNING);
        });
        self.iterations = iterations;
    }
    pub(crate) fn set_lanes(&mut self, lanes: u32) {
        validate_lanes(lanes).unwrap_or_else(|e| {
            warn!("{}. {}.", e, PANIC_WARNING);
        });
        self.lanes = lanes;
    }
    pub(crate) fn set_memory_size(&mut self, memory_size: u32) {
        validate_memory_size(self.lanes, memory_size).unwrap_or_else(|e| {
            warn!("{}. {}.", e, PANIC_WARNING);
        });
        self.memory_size = memory_size;
    }
    pub(crate) fn set_opt_out_of_random_salt(&mut self, boolean: bool) {
        self.opt_out_of_random_salt = boolean;
    }
    pub(crate) fn set_opt_out_of_secret_key(&mut self, boolean: bool) {
        self.opt_out_of_secret_key = boolean;
    }
    pub(crate) fn set_password_clearing(&mut self, boolean: bool) {
        self.password_clearing = boolean;
    }
    pub(crate) fn set_secret_key_clearing(&mut self, boolean: bool) {
        self.secret_key_clearing = boolean;
    }
    pub(crate) fn set_threads(&mut self, threads: u32) {
        validate_threads(threads).unwrap_or_else(|e| {
            warn!("{}. {}.", e, PANIC_WARNING);
        });
        self.threads = threads;
    }
    pub(crate) fn set_variant(&mut self, variant: Variant) {
        self.variant = variant;
    }
    pub(crate) fn set_version(&mut self, version: Version) {
        if version != DEFAULT_VERSION {
            warn!(
                "Version configuration set to {:?}, whereas the lastest version is {:?}. \
                 Are you sure you want to use an old version of the Argon2 algorithm?",
                version, DEFAULT_VERSION,
            );
        }
        self.version = version;
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        validate_backend(self.backend)?;
        validate_hash_length(self.hash_length)?;
        validate_iterations(self.iterations)?;
        validate_lanes(self.lanes)?;
        validate_memory_size(self.lanes, self.memory_size)?;
        validate_threads(self.threads)?;
        Ok(())
    }
}

fn validate_backend(backend: Backend) -> Result<(), Error> {
    match backend {
        Backend::C => (),
        Backend::Rust => {
            return Err(
                ErrorKind::ConfigurationError(ConfigurationError::BackendUnsupportedError).into(),
            )
        }
    }
    Ok(())
}

fn validate_hash_length(hash_length: u32) -> Result<(), Error> {
    if hash_length < 4 {
        return Err(
            ErrorKind::ConfigurationError(ConfigurationError::HashLengthTooShortError).into(),
        );
    }
    Ok(())
}

fn validate_iterations(iterations: u32) -> Result<(), Error> {
    if iterations == 0 {
        return Err(
            ErrorKind::ConfigurationError(ConfigurationError::HashLengthTooShortError).into(),
        );
    }
    Ok(())
}

fn validate_lanes(lanes: u32) -> Result<(), Error> {
    if lanes == 0 {
        return Err(ErrorKind::ConfigurationError(ConfigurationError::LanesTooFewError).into());
    }
    if lanes > 0x00ffffff {
        return Err(ErrorKind::ConfigurationError(ConfigurationError::LanesTooManyError).into());
    }
    Ok(())
}

fn validate_memory_size(lanes: u32, memory_size: u32) -> Result<(), Error> {
    if memory_size < 8 * lanes {
        return Err(
            ErrorKind::ConfigurationError(ConfigurationError::MemorySizeTooSmallError).into(),
        );
    }
    if !(memory_size.is_power_of_two()) {
        return Err(
            ErrorKind::ConfigurationError(ConfigurationError::MemorySizeInvalidError).into(),
        );
    }
    Ok(())
}

fn validate_threads(threads: u32) -> Result<(), Error> {
    if threads == 0 {
        return Err(ErrorKind::ConfigurationError(ConfigurationError::ThreadsTooFewError).into());
    }
    if threads > 0x00ffffff {
        return Err(ErrorKind::ConfigurationError(ConfigurationError::ThreadsTooManyError).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<HasherConfig>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<HasherConfig>();
    }
}
