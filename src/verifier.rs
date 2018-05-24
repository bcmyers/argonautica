use futures::Future;
use futures_cpupool::CpuPool;
use num_cpus;
use scopeguard;

use backend::verify_c;
use config::{Backend, VerifierConfig};
use data::{AdditionalData, DataPrivate, Password, SecretKey};
use error::{Error, ErrorKind};
use output::HashRaw;

impl Default for Verifier {
    /// Same as the [`new`](struct.Verifier.html#method.new) method
    fn default() -> Verifier {
        Verifier {
            additional_data: AdditionalData::none(),
            config: VerifierConfig::default(),
            cpu_pool: CpuPool::new(num_cpus::get_physical()), // TODO: move to Config?
            hash_enum: HashEnum::default(),
            password: Password::none(),
            secret_key: SecretKey::none(),
        }
    }
}

/// <b><u>One of the two main structs.</u></b> Use it to verify passwords against hashes
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Verifier {
    additional_data: AdditionalData,
    config: VerifierConfig,
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    cpu_pool: CpuPool,
    hash_enum: HashEnum,
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    password: Password,
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    secret_key: SecretKey,
}

// TODO: Getters
impl Verifier {
    /// Creates a new [`Verifier`](struct.Verifier.html) with sensible defaults:
    /// * `backend`: [`Backend::C`](config/enum.Backend.html#variant.C)
    /// * `cpu_pool`: `CpuPool::new(num_cpus::get_physical())`
    /// * `password_clearing`: `true`
    /// * `secret_key_clearing`: `false`
    pub fn new() -> Verifier {
        Verifier::default()
    }
    /// Allows you to configure [`Verifier`](struct.Verifier.html) to use a custom backend implementation. The default
    /// is [`Backend::C`](config/enum.Backend.html#variant.C). <i>Note: Currently the only backend implementation supported is </i> [`Backend::C`](config/enum.Backend.html#variant.C) <i>.
    /// A Rust backend is planned, but is not currently available. If you configure</i>
    /// [`Verifier`](struct.Verifier.html) <i>with</i> [`Backend::Rust`](config/enum.Backend.html#variant.Rust)<i>, it will panic at runtime</i>
    pub fn configure_backend(&mut self, backend: Backend) -> &mut Verifier {
        self.config.set_backend(backend);
        self
    }
    /// The non-blocking method on [`Verifier`](struct.Verifier.html)
    /// ([`verify_non_blocking`](struct.Verifier.html#method.verify_non_blocking))
    /// uses a [`CpuPool`](https://docs.rs/futures-cpupool/0.1.8/futures_cpupool/struct.CpuPool.html)
    /// in order to push work off onto another thread. This method
    /// allows you to provide your own [`CpuPool`](https://docs.rs/futures-cpupool/0.1.8/futures_cpupool/struct.CpuPool.html)
    /// instead of using the default, which is `CpuPool::new(num_cpus::get_physical())`. Note:
    /// The cpu pool is only used for the non-blocking method mentioned above.
    pub fn configure_cpu_pool(&mut self, cpu_pool: CpuPool) -> &mut Verifier {
        self.cpu_pool = cpu_pool;
        self
    }
    /// Allows you to configure [`Verifier`](struct.Verifier.html) to erase the password bytes after each call to [`verify`](struct.Verifier.html#method.verify).
    /// The default is to clear out the password bytes (i.e. `true`).
    pub fn configure_password_clearing(&mut self, boolean: bool) -> &mut Verifier {
        self.config.set_password_clearing(boolean);
        self
    }
    /// Allows you to configure [`Verifier`](struct.Verifier.html) to erase the secret key bytes after each call to [`verify`](struct.Verifier.html#method.verify).
    /// The default is to <b>not</b> clear out the secret key bytes (i.e. `false`).
    /// This default was chosen to make it easier to keep using the same [`Verifier`](struct.Verifier.html) for multiple passwords.
    pub fn configure_secret_key_clearing(&mut self, boolean: bool) -> &mut Verifier {
        self.config.set_secret_key_clearing(boolean);
        self
    }
    /// <b>The primary method (blocking version).</b> After you have configured [`Verifier`](struct.Verifier.html) to your liking and provided
    /// it will all the data it needs to verify a password (e.g. a string-encoded hash or [`HashRaw`](output/struct.HashRaw.html),
    /// a [`Password`](data/struct.Password.html) and a [`SecretKey`](data/struct.SecretKey.html)), call this method in order to determine whether the
    /// provided password matches the provided hash
    pub fn verify(&mut self) -> Result<bool, Error> {
        // ensure password and/or secret_key clearing code will run
        let mut verifier = scopeguard::guard(self, |verifier| {
            if verifier.config.password_clearing() {
                verifier.password = Password::none();
            }
            if verifier.config.secret_key_clearing() {
                verifier.secret_key = SecretKey::none();
            }
        });

        // validate inputs
        verifier.validate()?;

        // calculate is_valid
        let is_valid = match verifier.config.backend() {
            Backend::C => verify_c(&mut verifier)?,
            Backend::Rust => return Err(ErrorKind::BackendUnsupportedError.into()),
        };

        Ok(is_valid)
    }
    /// <b>The primary method (non-blocking version).</b> Same as [`verify`](struct.Verifier.html#method.verify) except it returns a [`Future`](https://docs.rs/futures/0.1.21/futures/future/trait.Future.html) instead of a [`Result`](https://doc.rust-lang.org/std/result/enum.Result.html)
    pub fn verify_non_blocking(&mut self) -> impl Future<Item = bool, Error = Error> {
        let mut verifier = self.clone();
        self.cpu_pool.spawn_fn(move || {
            let is_valid = verifier.verify()?;
            Ok::<_, Error>(is_valid)
        })
    }
    /// Allows you to provide [`Verifier`](struct.Verifier.html) with the additional data, if any, that was
    /// originally used to create the hash. Normally hashes are not created with
    /// additional data; so you are not likely to need this method
    pub fn with_additional_data<AD>(&mut self, additional_data: AD) -> &mut Verifier
    where
        AD: Into<AdditionalData>,
    {
        self.additional_data = additional_data.into();
        self
    }
    /// Provides [`Verifier`](struct.Verifier.html) with the hash to verify against (in the form of an encode `&str`
    /// like those produced by the [`hash`](struct.Hasher.html#method.hash) method on [`Hasher`](struct.Hasher.html))
    pub fn with_hash(&mut self, hash: &str) -> &mut Verifier {
        self.hash_enum = HashEnum::Encoded(hash.to_string());
        self
    }
    /// Provides [`Verifier`](struct.Verifier.html) with the hash to verify against (in the form of a [`RawHash`](output/struct.HashRaw.html)
    /// like those produced by the [`hash_raw`](struct.Hasher.html#method.hash_raw) method on [`Hasher`](struct.Hasher.html))
    pub fn with_hash_raw(&mut self, hash_raw: &HashRaw) -> &mut Verifier {
        self.hash_enum = HashEnum::Raw(hash_raw.clone());
        self
    }
    /// Provides [`Verifier`](struct.Verifier.html) with the password to verify against
    pub fn with_password<P>(&mut self, password: P) -> &mut Verifier
    where
        P: Into<Password>,
    {
        self.password = password.into();
        self
    }
    /// Provides [`Verifier`](struct.Verifier.html) with the secret key that was initially used to create the hash
    pub fn with_secret_key<SK>(&mut self, secret_key: SK) -> &mut Verifier
    where
        SK: Into<SecretKey>,
    {
        self.secret_key = secret_key.into();
        self
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s [`AdditionalData`](data/struct.AdditionalData.html). If you never provided [`AdditionalData`](data/struct.AdditionalData.html),
    /// this will return a reference to an empty [`AdditionalData`](data/struct.AdditionalData.html) (i.e. one whose underlying
    /// vector of bytes has zero length)
    pub fn additional_data(&self) -> &AdditionalData {
        &self.additional_data
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s [`VerifierConfig`](config/struct.VerifierConfig.html)
    pub fn config(&self) -> &VerifierConfig {
        &self.config
    }
    /// Access to the [`Verifier`](struct.Verifier.html)'s [`CpuPool`](https://docs.rs/futures-cpupool/0.1.8/futures_cpupool/struct.CpuPool.html)
    pub fn cpu_pool(&self) -> CpuPool {
        self.cpu_pool.clone()
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s string-encoded hash, if any. If you never provided a
    /// string-encoded hash, this will return `None`.
    pub fn hash(&self) -> Option<&str> {
        match self.hash_enum {
            HashEnum::Encoded(ref s) => Some(s),
            HashEnum::Raw(_) => None,
            HashEnum::None => None,
        }
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s [`RawHash`](output/struct.HashRaw.html), if any. If you never provided a
    /// [`RawHash`](output/struct.HashRaw.html), this will return `None`.
    pub fn hash_raw(&self) -> Option<&HashRaw> {
        match self.hash_enum {
            HashEnum::Encoded(_) => None,
            HashEnum::Raw(ref hash_raw) => Some(hash_raw),
            HashEnum::None => None,
        }
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s [`Password`](data/struct.Password.html). If you never provided a [`Password`](data/struct.Password.html),
    /// this will return a reference to an empty [`Password`](data/struct.Password.html) (i.e. one whose underlying
    /// vector of bytes has zero length)
    pub fn password(&self) -> &Password {
        &self.password
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s [`SecretKey`](data/struct.SecretKey.html). If you never provided a [`SecretKey`](data/struct.SecretKey.html),
    /// this will return a reference to an empty [`SecretKey`](data/struct.SecretKey.html) (i.e. one whose underlying
    /// vector of bytes has zero length)
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

impl Verifier {
    pub(crate) fn hash_enum(&self) -> &HashEnum {
        &self.hash_enum
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        match self.hash_enum {
            HashEnum::None => return Err(ErrorKind::HashNoneError.into()),
            _ => (),
        }
        self.password.validate(None)?;
        self.secret_key.validate(Some(true))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub(crate) enum HashEnum {
    Raw(HashRaw),
    Encoded(String),
    None,
}

impl Default for HashEnum {
    fn default() -> HashEnum {
        HashEnum::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{Variant, Version};
    use hasher::Hasher;

    pub const PASSWORDS: [&str; 2] = ["P@ssw0rd", "😊"];
    pub const VARIANTS: [Variant; 3] = [Variant::Argon2d, Variant::Argon2i, Variant::Argon2id];
    pub const VERSIONS: [Version; 2] = [Version::_0x10, Version::_0x13];

    struct Test {
        password: String,
        variant: Variant,
        version: Version,
    }

    impl Test {
        fn run(self) {
            let additional_data = vec![4u8; 12];
            let secret_key = vec![3u8; 8];
            let mut hasher = Hasher::default();
            hasher
                .configure_hash_length(32)
                .configure_iterations(3)
                .configure_lanes(4)
                .configure_memory_size(32)
                .configure_threads(4)
                .configure_variant(self.variant)
                .configure_version(self.version)
                .opt_out_of_random_salt()
                .with_salt(vec![2; 16])
                .opt_out_of_secret_key();
            let hash = hasher.with_password(self.password.as_str()).hash().unwrap();

            hasher.with_secret_key(secret_key.as_slice());
            let hash2 = hasher.with_password(self.password.as_str()).hash().unwrap();

            hasher.with_additional_data(additional_data.as_slice());
            let hash3 = hasher.with_password(self.password.as_str()).hash().unwrap();

            let mut verifier = Verifier::new();
            verifier
                .with_hash(&hash)
                .with_password(self.password.as_str());
            let is_valid = verifier.verify().unwrap();
            assert!(is_valid);

            verifier
                .with_hash(&hash2)
                .with_password(self.password.as_str())
                .with_secret_key(secret_key.as_slice());
            let is_valid = verifier.verify().unwrap();
            assert!(is_valid);

            verifier
                .with_additional_data(additional_data.as_slice())
                .with_hash(&hash3)
                .with_password(self.password.as_str());
            let is_valid = verifier.verify().unwrap();
            assert!(is_valid);
        }
    }

    #[test]
    fn test_verifier() {
        for password in &PASSWORDS {
            for variant in &VARIANTS {
                for version in &VERSIONS {
                    Test {
                        password: password.to_string(),
                        variant: *variant,
                        version: *version,
                    }.run();
                }
            }
        }
    }

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Verifier>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Verifier>();
    }
}
