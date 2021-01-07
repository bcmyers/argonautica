use futures::executor::ThreadPool;

#[cfg(feature = "serde")]
use crate::config::defaults::default_thread_pool_serde;
use crate::config::Backend;

/// Read-only configuration for [`Verifier`](../struct.Verifier.html). Can be obtained by calling
/// the [`config`](../struct.Verifier.html#method.config) method on an instance of
/// [`Verifier`](../struct.Verifier.html)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct VerifierConfig {
    pub(crate) backend: Backend,
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing,
            skip_deserializing,
            default = "default_thread_pool_serde"
        )
    )]
    pub(crate) cpu_pool: Option<ThreadPool>,
    pub(crate) password_clearing: bool,
    pub(crate) secret_key_clearing: bool,
    pub(crate) threads: u32,
}

impl VerifierConfig {
    #[allow(missing_docs)]
    pub fn backend(&self) -> Backend {
        self.backend
    }
    #[allow(missing_docs)]
    pub fn cpu_pool(&self) -> Option<ThreadPool> {
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
    #[allow(missing_docs)]
    pub fn threads(&self) -> u32 {
        self.threads
    }
}

impl VerifierConfig {
    pub(crate) fn new(
        backend: Backend,
        cpu_pool: Option<ThreadPool>,
        password_clearing: bool,
        secret_key_clearing: bool,
        threads: u32,
    ) -> VerifierConfig {
        VerifierConfig {
            backend,
            cpu_pool,
            password_clearing,
            secret_key_clearing,
            threads,
        }
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
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<VerifierConfig>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<VerifierConfig>();
    }
}
