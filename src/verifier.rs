use failure;
use scopeguard;

use backend::{verify_c, verify_rust};
use config::{Backend, VerifierConfig};
use data::{AdditionalData, Password, SecretKey};
use output::HashRaw;

impl Default for Verifier {
    /// Same as the `new` method
    fn default() -> Verifier {
        Verifier {
            additional_data: AdditionalData::none(),
            config: VerifierConfig::default(),
            hash_enum: HashEnum::none(),
            password: Password::none(),
            secret_key: SecretKey::none(),
        }
    }
}

/// One of the two main structs. Use it to verify passwords against hashes
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verifier {
    additional_data: AdditionalData,
    config: VerifierConfig,
    hash_enum: HashEnum,
    #[serde(skip_serializing)]
    password: Password,
    #[serde(skip_serializing)]
    secret_key: SecretKey,
}

// TODO: Getters
impl Verifier {
    /// Creates a new `Verifier` with sensible defaults:
    /// * `backend`: `Backend::C`
    /// * `password_clearing`: true
    /// * `secret_key_clearing`: false
    pub fn new() -> Verifier {
        Verifier::default()
    }
    /// Allows you to configure `Verifier` to use a custom backend implementation. The default
    /// is `Backend::C`. <i>Note: Currently the only backend implementation supported is </i> `Backend::C` <i>.
    /// A Rust backend is planned, but is not currently available. If you configure</i>
    /// `Hasher` <i>with</i> `Backend::Rust`<i>, it will panic at runtime</i>
    pub fn configure_backend(&mut self, backend: Backend) -> &mut Verifier {
        self.config.set_backend(backend);
        self
    }
    /// Allows you to configure `Verifier` to erase the password bytes after each call to `verify`.
    /// The default is to clear out the password bytes (i.e. `true`).
    pub fn configure_password_clearing(&mut self, boolean: bool) -> &mut Verifier {
        self.config.set_password_clearing(boolean);
        self
    }
    /// Allows you to configure `Verifier` to erase the secret key bytes after each call to `verify`.
    /// The default is to <b>not</b> clear out the secret key bytes (i.e. `false`).
    /// This default was chosen to make it easier to keep using the same `Verifier` for multiple passwords.
    pub fn configure_secret_key_clearing(&mut self, boolean: bool) -> &mut Verifier {
        self.config.set_secret_key_clearing(boolean);
        self
    }
    /// <b>The primary method.</b> After you have configured `Verifier` to your liking and provided
    /// it will all the data it needs to verify a password (e.g. a string-encoded hash or `HashRaw`,
    /// a `Password` and a `SecretKey`), call this method in order to determine whether the
    /// provided password matches the provided hash
    pub fn verify(&mut self) -> Result<bool, failure::Error> {
        // TODO: validate?
        let mut verifier = scopeguard::guard(self, |verifier| {
            if verifier.config.password_clearing() {
                verifier.password = Password::none();
            }
            if verifier.config.secret_key_clearing() {
                verifier.secret_key = SecretKey::none();
            }
        });

        let is_valid = match verifier.config.backend() {
            Backend::C => verify_c(&mut verifier)?,
            Backend::Rust => verify_rust(&mut verifier)?,
        };

        Ok(is_valid)
    }
    /// Allows you to provide `Verifier` with the additional data, if any, that was
    /// originally used to create the hash. Normally hashes are not created with
    /// additional data; so you are not likely to need this method
    pub fn with_additional_data<AD>(&mut self, additional_data: AD) -> &mut Verifier
    where
        AD: Into<AdditionalData>,
    {
        self.additional_data = additional_data.into();
        self
    }
    /// Provides `Verifier` with the hash to verify against (in the form of an encode `&str`
    /// like those produced by the `hash` method on `Hasher`)
    pub fn with_hash(&mut self, hash: &str) -> &mut Verifier {
        self.hash_enum = HashEnum::Encoded(hash.to_string());
        self
    }
    /// Provides `Verifier` with the hash to verify against (in the form of a `RawHash`
    /// like those produced by the `hash_raw` method on `Hasher`)
    pub fn with_hash_raw(&mut self, hash_raw: &HashRaw) -> &mut Verifier {
        self.hash_enum = HashEnum::Raw(hash_raw.clone());
        self
    }
    /// Provides `Verifier` with the password to verify against
    pub fn with_password<P>(&mut self, password: P) -> &mut Verifier
    where
        P: Into<Password>,
    {
        self.password = password.into();
        self
    }
    /// Provides `Verifier` with the secret key that was initially used to create the hash
    pub fn with_secret_key<SK>(&mut self, secret_key: SK) -> &mut Verifier
    where
        SK: Into<SecretKey>,
    {
        self.secret_key = secret_key.into();
        self
    }
    /// Read-only access to the `Verifier`'s `AdditionalData`. If you never provided `AdditionalData`,
    /// this will return a reference to an empty `AdditionalData` (i.e. one whose underlying
    /// vector of bytes has zero length)
    pub fn additional_data(&self) -> &AdditionalData {
        &self.additional_data
    }
    /// Read-only access to the `Verifier`'s `VerifierConfig`
    pub fn config(&self) -> &VerifierConfig {
        &self.config
    }
    /// Read-only access to the `Verifier`'s string-encoded hash, if any. If you never provided a
    /// string-encoded hash or a `RawHash`, this will return `Some("")`. If you provided a `RawHash`
    /// but not a string-encoded hash, this will return `None`.
    pub fn hash(&self) -> Option<&str> {
        match self.hash_enum {
            HashEnum::Encoded(ref s) => Some(s),
            HashEnum::Raw(_) => None,
        }
    }
    /// Read-only access to the `Verifier`'s `RawHash`, if any. If you never provided a
    /// `RawHash`, this will return `None`.
    pub fn hash_raw(&self) -> Option<&HashRaw> {
        match self.hash_enum {
            HashEnum::Encoded(_) => None,
            HashEnum::Raw(ref hash_raw) => Some(hash_raw),
        }
    }
    /// Read-only access to the `Verifier`'s `Password`. If you never provided a `Password`,
    /// this will return a reference to an empty `Password` (i.e. one whose underlying
    /// vector of bytes has zero length)
    pub fn password(&self) -> &Password {
        &self.password
    }
    /// Read-only access to the `Verifier`'s `SecretKey`. If you never provided a `SecretKey`,
    /// this will return a reference to an empty `SecretKey` (i.e. one whose underlying
    /// vector of bytes has zero length)
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

impl Verifier {
    pub(crate) fn hash_enum(&self) -> &HashEnum {
        &self.hash_enum
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum HashEnum {
    Raw(HashRaw),
    Encoded(String),
}

impl HashEnum {
    fn none() -> HashEnum {
        HashEnum::Encoded("".to_string())
    }
}
