use config::Backend;
use config::defaults::{DEFAULT_BACKEND, DEFAULT_PASSWORD_CLEARING, DEFAULT_SECRET_KEY_CLEARING};

/// Read-only configuration for [`Verifier`](../struct.Verifier.html). Can be obtained by calling
/// the [`config`](../struct.Verifier.html#method.config) method on an instance of [`Verifier`](../struct.Verifier.html)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct VerifierConfig {
    backend: Backend,
    password_clearing: bool,
    secret_key_clearing: bool,
}

impl VerifierConfig {
    #[allow(missing_docs)]
    pub fn backend(&self) -> Backend {
        self.backend
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
            password_clearing: DEFAULT_PASSWORD_CLEARING,
            secret_key_clearing: DEFAULT_SECRET_KEY_CLEARING,
        }
    }
    pub(crate) fn set_backend(&mut self, backend: Backend) {
        self.backend = backend;
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
}
