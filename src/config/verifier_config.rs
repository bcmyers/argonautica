use config::defaults::{DEFAULT_BACKEND, DEFAULT_PASSWORD_CLEARING, DEFAULT_SECRET_KEY_CLEARING};
use config::Backend;

/// Read-only `Verifier` configuration. Can be obtained by calling `config()` on an instance of `Verifier`
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct VerifierConfig {
    backend: Backend,
    password_clearing: bool,
    secret_key_clearing: bool,
}

impl VerifierConfig {
    pub fn backend(&self) -> Backend {
        self.backend
    }
    pub fn password_clearing(&self) -> bool {
        self.password_clearing
    }
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
