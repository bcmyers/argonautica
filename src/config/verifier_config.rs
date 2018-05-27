use futures_cpupool::CpuPool;

use config::Backend;
#[cfg(feature = "serde")]
use config::default_cpu_pool_serde;
use config::defaults::{DEFAULT_BACKEND, DEFAULT_PASSWORD_CLEARING, DEFAULT_SECRET_KEY_CLEARING};

/// Read-only configuration for [`Verifier`](../struct.Verifier.html). Can be obtained by calling
/// the [`config`](../struct.Verifier.html#method.config) method on an instance of
/// [`Verifier`](../struct.Verifier.html)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct VerifierConfig {
    backend: Backend,
    #[cfg_attr(feature = "serde",
               serde(skip_serializing, skip_deserializing, default = "default_cpu_pool_serde"))]
    cpu_pool: Option<CpuPool>,
    password_clearing: bool,
    secret_key_clearing: bool,
}

impl VerifierConfig {
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
    pub fn password_clearing(&self) -> bool {
        self.password_clearing
    }
    #[allow(missing_docs)]
    pub fn secret_key_clearing(&self) -> bool {
        self.secret_key_clearing
    }
}

impl VerifierConfig {
    pub(crate) fn default() -> VerifierConfig {
        VerifierConfig {
            backend: DEFAULT_BACKEND,
            cpu_pool: None,
            password_clearing: DEFAULT_PASSWORD_CLEARING,
            secret_key_clearing: DEFAULT_SECRET_KEY_CLEARING,
        }
    }
    pub(crate) fn set_backend(&mut self, backend: Backend) {
        self.backend = backend;
    }
    pub(crate) fn set_cpu_pool(&mut self, cpu_pool: CpuPool) {
        self.cpu_pool = Some(cpu_pool);
    }
    pub(crate) fn set_password_clearing(&mut self, boolean: bool) {
        self.password_clearing = boolean;
    }
    pub(crate) fn set_secret_key_clearing(&mut self, boolean: bool) {
        self.secret_key_clearing = boolean;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<VerifierConfig>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<VerifierConfig>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<VerifierConfig>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<VerifierConfig>();
    }
}
