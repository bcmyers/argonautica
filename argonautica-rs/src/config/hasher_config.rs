use futures_cpupool::CpuPool;

use config::defaults::*;
use config::{Backend, Flags, Variant, Version};
use {Error, ErrorKind};

const PANIC_WARNING: &str = "Your program will error if you use this configuration";

/// Read-only configuration for [`Hasher`](../struct.Hasher.html). Can be obtained by calling
/// the [`config`](../struct.Hasher.html#method.config) method on an instance of
/// [`Hasher`](../struct.Hasher.html)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct HasherConfig {
    backend: Backend,
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing, skip_deserializing, default = "default_cpu_pool_serde")
    )]
    cpu_pool: Option<CpuPool>,
    hash_len: u32,
    iterations: u32,
    lanes: u32,
    memory_size: u32,
    opt_out_of_secret_key: bool,
    password_clearing: bool,
    secret_key_clearing: bool,
    threads: u32,
    variant: Variant,
    version: Version,
}

impl HasherConfig {
    #[allow(missing_docs)]
    pub fn backend(&self) -> Backend {
        self.backend
    }
    #[allow(missing_docs)]
    pub fn cpu_pool(&self) -> Option<CpuPool> {
        match self.cpu_pool {
            Some(ref cpu_pool) => Some(cpu_pool.clone()),
            None => None,
        }
    }
    #[allow(missing_docs)]
    pub fn hash_len(&self) -> u32 {
        self.hash_len
    }
    #[allow(missing_docs)]
    pub fn iterations(&self) -> u32 {
        self.iterations
    }
    #[allow(missing_docs)]
    pub fn lanes(&self) -> u32 {
        self.lanes
    }
    #[allow(missing_docs)]
    pub fn memory_size(&self) -> u32 {
        self.memory_size
    }
    #[allow(missing_docs)]
    pub fn opt_out_of_secret_key(&self) -> bool {
        self.opt_out_of_secret_key
    }
    #[allow(missing_docs)]
    pub fn password_clearing(&self) -> bool {
        self.password_clearing
    }
    #[allow(missing_docs)]
    pub fn secret_key_clearing(&self) -> bool {
        self.secret_key_clearing
    }
    #[allow(missing_docs)]
    pub fn threads(&self) -> u32 {
        self.threads
    }
    #[allow(missing_docs)]
    pub fn variant(&self) -> Variant {
        self.variant
    }
    #[allow(missing_docs)]
    pub fn version(&self) -> Version {
        self.version
    }
}

impl HasherConfig {
    pub(crate) fn default() -> HasherConfig {
        HasherConfig {
            backend: Backend::default(),
            cpu_pool: None,
            hash_len: DEFAULT_HASH_LEN,
            iterations: DEFAULT_ITERATIONS,
            lanes: default_lanes(),
            memory_size: DEFAULT_MEMORY_SIZE,
            opt_out_of_secret_key: DEFAULT_OPT_OUT_OF_SECRET_KEY,
            password_clearing: DEFAULT_PASSWORD_CLEARING,
            secret_key_clearing: DEFAULT_SECRET_KEY_CLEARING,
            threads: default_threads(),
            variant: Variant::default(),
            version: Version::default(),
        }
    }
    #[allow(dead_code)]
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
    pub(crate) fn set_cpu_pool(&mut self, cpu_pool: CpuPool) {
        self.cpu_pool = Some(cpu_pool);
    }
    pub(crate) fn set_hash_len(&mut self, hash_len: u32) {
        validate_hash_len(hash_len).unwrap_or_else(|e| {
            warn!("{}. {}.", e, PANIC_WARNING);
        });
        self.hash_len = hash_len;
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
        validate_hash_len(self.hash_len)?;
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
        Backend::Rust => return Err(Error::new(ErrorKind::BackendUnsupportedError)),
    }
    Ok(())
}

fn validate_hash_len(hash_len: u32) -> Result<(), Error> {
    if hash_len < 4 {
        return Err(Error::new(ErrorKind::HashLenTooShortError)
            .add_context(format!("Hash len: {}", hash_len)));
    }
    Ok(())
}

fn validate_iterations(iterations: u32) -> Result<(), Error> {
    if iterations == 0 {
        return Err(Error::new(ErrorKind::IterationsTooFewError)
            .add_context(format!("Iterations: {}", iterations)));
    }
    Ok(())
}

fn validate_lanes(lanes: u32) -> Result<(), Error> {
    if lanes == 0 {
        return Err(Error::new(ErrorKind::LanesTooFewError).add_context(format!("Lanes: {}", lanes)));
    }
    if lanes > 0x00ff_ffff {
        return Err(
            Error::new(ErrorKind::LanesTooManyError).add_context(format!("Lanes: {}", lanes))
        );
    }
    Ok(())
}

fn validate_memory_size(lanes: u32, memory_size: u32) -> Result<(), Error> {
    if memory_size < 8 * lanes {
        return Err(Error::new(ErrorKind::MemorySizeTooSmallError)
            .add_context(format!("Lanes: {}. Memory size: {}", lanes, memory_size)));
    }
    if !(memory_size.is_power_of_two()) {
        return Err(Error::new(ErrorKind::MemorySizeInvalidError)
            .add_context(format!("Memory size: {}", memory_size)));
    }
    Ok(())
}

fn validate_threads(threads: u32) -> Result<(), Error> {
    if threads == 0 {
        return Err(
            Error::new(ErrorKind::ThreadsTooFewError).add_context(format!("Threads: {}", threads))
        );
    }
    if threads > 0x00ff_ffff {
        return Err(
            Error::new(ErrorKind::ThreadsTooManyError).add_context(format!("Threads: {}", threads))
        );
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

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<HasherConfig>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<HasherConfig>();
    }
}
