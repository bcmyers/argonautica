use futures::Future;
use futures_cpupool::CpuPool;
use scopeguard;

use config::{default_cpu_pool, default_lanes, Backend, HasherConfig, Variant, Version};
use data::{AdditionalData, Data, Password, Salt, SecretKey};
use errors::{ConfigurationError, DataError};
use output::HashRaw;
use {Error, ErrorKind};

impl Default for Hasher {
    /// Same as the [`new`](struct.Hasher.html#method.new) method
    fn default() -> Hasher {
        Hasher {
            additional_data: None,
            config: HasherConfig::default(),
            password: None,
            salt: Salt::default(),
            secret_key: None,
        }
    }
}

/// <b><u>One of the two main structs.</u></b> Use it to turn passwords into hashes that
/// are safe to store in a database
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Hasher {
    additional_data: Option<AdditionalData>,
    config: HasherConfig,
    #[cfg_attr(feature = "serde", serde(skip_serializing, skip_deserializing))]
    password: Option<Password>,
    salt: Salt,
    #[cfg_attr(feature = "serde", serde(skip_serializing, skip_deserializing))]
    secret_key: Option<SecretKey>,
}

impl Hasher {
    /// Creates a new [`Hasher`](struct.Hasher.html) with a sensible default configuration
    /// for the average machine (e.g. an early-2014 MacBook Air).
    ///
    /// <b>Note: If you are using this library to hash user passwords for storage in a database,
    /// it is recommended that you adjust these settings for your machine (primarily `iterations`,
    /// and `memory_size`) until the time it takes to hash a password is approximately 500
    /// milliseconds</b>.
    ///
    /// There is a script in the examples directory that will show you the various configuration
    /// options for your machine that produce hashing times between 375 and 625 milliseconds
    /// (Don't forget to run it with the `--release` flag). Alternatively, you can clone the
    /// repository and run the benchmark suite with
    /// `cargo bench --features benches -- bench_inputs`, which will take longer but which runs
    /// many iterations for each configuration scenario; so it provides information about
    /// distributions of running time (e.g. mean, 95% confidence intervals, etc.) as opposed
    /// to just point estimates.
    ///
    /// Here are the default configuration options:
    /// * `backend`: [`Backend::C`](config/enum.Backend.html#variant.C)
    /// * `cpu_pool`: A [`CpuPool`](https://docs.rs/futures-cpupool/0.1.8/futures_cpupool/struct.CpuPool.html) ...
    ///     * with threads equal to the number of logical cores on your machine
    ///     * that is lazily created, i.e. created only if / when you call the methods
    ///       that need it ([`hash_non_blocking`](struct.Hasher.html#method.hash_non_blocking) or
    ///       [`hash_raw_non_blocking`](struct.Hasher.html#method.hash_raw_non_blocking))
    /// * `hash_length`: `32` bytes
    /// * `iterations`: `128`
    /// * `lanes`: The number of physical cores on your machine
    /// * `memory_size`: `4096` kibibytes
    /// * `opt_out_of_random_salt`: `false`
    /// * `opt_out_of_secret_key`: `false`
    /// * `password_clearing`: `true`
    /// * `salt`: random [`Salt`](data/struct.Salt.html) of length 32 bytes that renews with every hash
    /// * `secret_key_clearing`: `false`
    /// * `threads`: The number of physical cores on your machine
    /// * `variant`: [`Variant::Argon2id`](config/enum.Variant.html#variant.Argon2id)
    /// * `version`: [`Version::_0x13`](config/enum.Verion.html#variant._0x13)
    pub fn new() -> Hasher {
        Hasher::default()
    }
    /// Creates a new [`Hasher`](struct.Hasher.html) that is fast <b><u>but highly insecure</u></b>.
    /// If for some reason you'd like to use Argon2 for hashing where security is not an issue,
    /// you can use this configuration. It sets hash length to 32 bytes (256 bits), uses only
    /// 1 iteration, sets memory size to the minimum of 8 * the number of lanes, uses a
    /// deterministic salt of the minimum length of 8 bytes, opts out of a secret key, and
    /// sets password clearing to false. All other configuration options are the same as the
    /// defaults. On the developer's early-2014 Macbook Air, this configuration hashes
    /// "some document" in approximately 250 microseconds (on average)
    pub fn fast_but_insecure() -> Hasher {
        fn memory_size(lanes: u32) -> u32 {
            let mut counter = 1;
            let memory_size = loop {
                if 2u32.pow(counter) < 8 * lanes {
                    counter += 1;
                    continue;
                } else {
                    break 2u32.pow(counter);
                }
            };
            memory_size
        }
        let lanes = default_lanes();
        let mut hasher = Hasher::default();
        hasher
            .configure_hash_length(32)
            .configure_iterations(1)
            .configure_lanes(lanes)
            .configure_memory_size(memory_size(lanes))
            .configure_password_clearing(false)
            .configure_secret_key_clearing(false)
            .configure_threads(lanes)
            .opt_out_of_random_salt(true)
            .opt_out_of_secret_key(true)
            .with_salt("somesalt");
        hasher
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) with a custom backend. The
    /// default backend is [`Backend::C`](config/enum.Backend.html#variant.C), <i>which is
    /// currently the only backend supported. A Rust backend is planned, but is not currently
    /// available. If you configure a [`Hasher`](struct.Hasher.html) with
    /// [`Backend::Rust`](config/enum.Backend.html#variant.Rust) it will error</i>
    pub fn configure_backend(&mut self, backend: Backend) -> &mut Hasher {
        self.config.set_backend(backend);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) with a custom
    /// [`CpuPool`](https://docs.rs/futures-cpupool/0.1.8/futures_cpupool/struct.CpuPool.html).
    /// The default [`Hasher`](struct.Hasher.html) does not have a cpu pool, which is
    /// only needed for the [`hash_non_blocking`](struct.Hasher.html#method.hash_non_blocking)
    /// and [`hash_raw_non_blocking`](struct.Hasher.html#method.hash_raw_non_blocking) methods.
    /// If you call either of these methods without a cpu pool, a default cpu pool will be created
    /// for you on the fly; so even if you never configure [`Hasher`](struct.Hasher.html) with
    /// this method you can still use the non-blocking hashing methods.
    /// The default cpu pool has as many threads as the number of logical cores on your machine
    pub fn configure_cpu_pool(&mut self, cpu_pool: CpuPool) -> &mut Hasher {
        self.config.set_cpu_pool(cpu_pool);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom hash length
    /// (in bytes). The default is `32`.
    ///
    /// See [configuration example](index.html#configuration) for a more detailed discussion
    /// of this parameter
    pub fn configure_hash_length(&mut self, hash_length: u32) -> &mut Hasher {
        self.config.set_hash_length(hash_length);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom number of
    /// iterations. The default is `128`.
    ///
    /// See [configuration example](index.html#configuration) for a more detailed discussion
    /// of this parameter
    pub fn configure_iterations(&mut self, iterations: u32) -> &mut Hasher {
        self.config.set_iterations(iterations);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom number of
    /// lanes. The default is the number of physical cores on your machine.
    ///
    /// See [configuration example](index.html#configuration) for a more detailed discussion
    /// of this parameter
    pub fn configure_lanes(&mut self, lanes: u32) -> &mut Hasher {
        self.config.set_lanes(lanes);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom memory size
    /// (in kibibytes). The default is `4096`.
    ///
    /// See [configuration example](index.html#configuration) for a more detailed discussion
    /// of this parameter
    pub fn configure_memory_size(&mut self, memory_size: u32) -> &mut Hasher {
        self.config.set_memory_size(memory_size);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to erase the password bytes
    /// after each call to [`hash`](struct.Hasher.html#method.hash)
    /// or [`hash_raw`](struct.Hasher.html#method.hash_raw) (or their non-blocking versions).
    /// The default is to clear out the password bytes (i.e. `true`).
    ///
    /// See [configuration example](index.html#configuration) for a more detailed discussion
    /// of this parameter
    pub fn configure_password_clearing(&mut self, boolean: bool) -> &mut Hasher {
        self.config.set_password_clearing(boolean);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to erase the secret key bytes
    /// after each call to [`hash`](struct.Hasher.html#method.hash)
    /// or [`hash_raw`](struct.Hasher.html#method.hash_raw) (or their non-blocking version).
    /// The default is to <b>not</b> clear out the secret key bytes (i.e. `false`).
    /// This default was chosen to make it easier to keep using the same
    /// [`Hasher`](struct.Hasher.html) for multiple passwords.
    ///
    /// See [configuration example](index.html#configuration) for a more detailed discussion
    /// of this parameter
    pub fn configure_secret_key_clearing(&mut self, boolean: bool) -> &mut Hasher {
        self.config.set_secret_key_clearing(boolean);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom number of
    /// threads. The default is the number of physical cores on your machine. If you choose
    /// a number of threads that is greater than the lanes configuration,
    /// [`Hasher`](struct.Hasher.html) will use the minimum of the two.
    ///
    /// See [configuration example](index.html#configuration) for a more detailed discussion
    /// of this parameter
    pub fn configure_threads(&mut self, threads: u32) -> &mut Hasher {
        self.config.set_threads(threads);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom Argon2
    /// variant. The default is [`Variant::Argon2id`](config/enum.Variant.html#variant.Argon2id).
    /// Do <b>not</b> use a different variant unless you have a specific reason to do so.
    ///
    /// See [configuration example](index.html#configuration) for a more detailed discussion
    /// of this parameter
    pub fn configure_variant(&mut self, variant: Variant) -> &mut Hasher {
        self.config.set_variant(variant);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom Argon2 version.
    /// The default and latest (as of 5/18) is
    /// [`Version::_0x13`](config/enum.Version.html#variant._0x13).
    /// Do <b>not</b> use a different version unless you have a specific reason to do so.
    ///
    /// See [configuration example](index.html#configuration) for a more detailed discussion
    /// of this parameter
    pub fn configure_version(&mut self, version: Version) -> &mut Hasher {
        self.config.set_version(version);
        self
    }
    /// <b><u>The primary method (blocking version).</u></b>
    ///
    /// After you have configured a [`Hasher`](struct.Hasher.html) to your liking and provided
    /// it will all the data you would like to hash, e.g.
    /// * a [`Password`](data/struct.Password.html),
    /// * a [`Salt`](data/struct.Password.html) (note: it is recommened you use the default random salt),
    /// * a [`SecretKey`](data/struct.SecretKey.html),
    /// * [`AdditionalData`](data/struct.AdditionalData.html) (optional),
    ///
    /// call this method in order to produce a string-encoded hash, which is safe to store in a
    /// database and against which you can verify passwords later
    pub fn hash(&mut self) -> Result<String, Error> {
        use backend::encode_rust;
        let hash_raw = self.hash_raw()?;
        let hash = encode_rust(&hash_raw);
        Ok(hash)
    }
    /// <b><u>The primary method (non-blocking version).</u></b>
    ///
    /// Same as [`hash`](struct.Hasher.html#method.hash) except it returns a
    /// [`Future`](https://docs.rs/futures/0.1.21/futures/future/trait.Future.html)
    /// instead of a [`Result`](https://doc.rust-lang.org/std/result/enum.Result.html)
    pub fn hash_non_blocking(&mut self) -> impl Future<Item = String, Error = Error> {
        use backend::encode_rust;
        self.hash_raw_non_blocking().and_then(|hash_raw| {
            let hash = encode_rust(&hash_raw);
            Ok::<_, Error>(hash)
        })
    }
    /// Like the [`hash`](struct.Hasher.html#method.hash) method, but instead of producing
    /// an string-encoded hash, it produces a [`HashRaw`](output/struct.HashRaw.html) struct
    /// that contains all the components of the string-encoded version, including the raw
    /// hash bytes and the raw salt bytes. In general, you should prefer to use the
    /// [`hash`](struct.Hasher.html#method.hash) method instead of this method
    pub fn hash_raw(&mut self) -> Result<HashRaw, Error> {
        use backend::hash_raw_c;
        // ensure password and/or secret_key clearing code will run
        let mut hasher = scopeguard::guard(self, |hasher| {
            if hasher.config().password_clearing() {
                hasher.set_password(None);
            }
            if hasher.config().secret_key_clearing() {
                hasher.set_secret_key(None);
            }
        });
        // reset salt if it is random
        if hasher.salt().is_random() {
            let len = hasher.salt().len();
            hasher.set_salt(Salt::random(len as u32)?);
        }
        // validate inputs
        hasher.validate()?;
        // calculate hash_raw
        let hash_raw = match hasher.config().backend() {
            Backend::C => hash_raw_c(&mut hasher)?,
            Backend::Rust => {
                return Err(ErrorKind::ConfigurationError(
                    ConfigurationError::BackendUnsupportedError,
                ).into())
            }
        };
        Ok(hash_raw)
    }
    /// Same as [`hash_raw`](struct.Hasher.html#method.hash) except it returns a
    /// [`Future`](https://docs.rs/futures/0.1.21/futures/future/trait.Future.html)
    /// instead of a [`Result`](https://doc.rust-lang.org/std/result/enum.Result.html)
    pub fn hash_raw_non_blocking(&mut self) -> impl Future<Item = HashRaw, Error = Error> {
        let mut hasher = self.clone();
        match self.config.cpu_pool() {
            Some(cpu_pool) => cpu_pool.spawn_fn(move || {
                let hash_raw = hasher.hash_raw()?;
                Ok::<_, Error>(hash_raw)
            }),
            None => {
                let cpu_pool = default_cpu_pool();
                self.config.set_cpu_pool(cpu_pool.clone());
                cpu_pool.spawn_fn(move || {
                    let hash_raw = hasher.hash_raw()?;
                    Ok::<_, Error>(hash_raw)
                })
            }
        }
    }
    /// For safety reasons, if you would like to produce a hash that does not include a random
    /// salt, you must explicitly opt out of using a random salt by passing this method `true`.
    /// It is not recommended that you do this
    pub fn opt_out_of_random_salt(&mut self, boolean: bool) -> &mut Hasher {
        self.config.set_opt_out_of_random_salt(boolean);
        self
    }
    /// For safety reasons, if you would like to produce a hash that does not include a secret
    /// key, you must explicitly opt out of using a secret key by passing this method `true`.
    /// It is not recommended that you do this
    pub fn opt_out_of_secret_key(&mut self, boolean: bool) -> &mut Hasher {
        self.config.set_opt_out_of_secret_key(boolean);
        self
    }
    /// Allows you to add some additional data to the [`Hasher`](struct.Hasher.html)
    /// that will be hashed alongside the [`Password`](data/struct.Password.html) and
    /// other pieces of data you would like to hash (i.e. the [`Salt`](data/struct.Salt.html) and
    /// an optional [`SecretKey`](data/struct.SecretKey.html)).
    ///
    /// Including additional data in your hash is not very common; so it is unlikely you will
    /// need to use this method. If, however, you do add additional data, note that it is like
    /// a secret key in that it will be required later in order to verify passwords, and
    /// it is not stored in the string-encoded version of the hash, meaning you will have to
    /// provide it manually to a [`Verifier`](struct.Verifier.html)
    pub fn with_additional_data<AD>(&mut self, additional_data: AD) -> &mut Hasher
    where
        AD: Into<AdditionalData>,
    {
        self.additional_data = Some(additional_data.into());
        self
    }
    /// Allows you to provide a [`Hasher`](struct.Hasher.html) with the password you would like
    /// to hash. Hashing requires a password; so you must call this method before calling
    /// [`hash`](struct.Hasher.html#method.hash), [`hash_raw`](struct.Hasher.html#method.hash_raw),
    /// or their non-blocking version
    pub fn with_password<P>(&mut self, password: P) -> &mut Hasher
    where
        P: Into<Password>,
    {
        self.password = Some(password.into());
        self
    }
    /// Allows you to provide [`Hasher`](struct.Hasher.html) with a custom
    /// [`Salt`](data/struct.Salt.html) to include in the hash. The default
    /// [`Hasher`](struct.Hasher.html) is configured to use a random
    /// [`Salt`](data/struct.Salt.html) of 32 bytes; so there is no need
    /// to call this method. If you would like to use a random
    /// [`Salt`](data/struct.Salt.html) of different length, you can call this method with
    /// `Salt::random(your_custom_length_in_bytes)`. Using a deterministic
    /// [`Salt`](data/struct.Salt.html) is possible, but discouraged. If you choose to use
    /// a deterministic [`Salt`](data/struct.Salt.html), you will have to explicitly opt out of
    /// using a random salt with the
    /// [`opt_out_of_random_salt`](struct.Hasher.html#method.opt_out_of_random_salt) method
    pub fn with_salt<S>(&mut self, salt: S) -> &mut Hasher
    where
        S: Into<Salt>,
    {
        self.salt = salt.into();
        self
    }
    /// Allows you to provide [`Hasher`](struct.Hasher.html) with a secret key that will be used
    /// to create the hash. The secret key will not be included in the hash output, meaning you
    /// must save it somewhere (ideally outside your code) to use later, as the only way to
    /// verify passwords against the hash later is to know the secret key. This library
    /// encourages the use of a secret key; so if you do not want to provide one, you will have
    /// to explicitly opt out of using a secret key with the
    /// [`opt_out_of_secret_key`](struct.Hasher.html#method.opt_out_of_secret_key) method
    /// before calling [`hash`](struct.Hasher.html#method.hash),
    /// [`hash_raw`](struct.Hasher.html#method.hash_raw), or their non-blocking version
    pub fn with_secret_key<SK>(&mut self, secret_key: SK) -> &mut Hasher
    where
        SK: Into<SecretKey>,
    {
        self.secret_key = Some(secret_key.into());
        self
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s
    /// [`AdditionalData`](data/struct.AdditionalData.html), if any
    pub fn additional_data(&self) -> Option<&AdditionalData> {
        self.additional_data.as_ref()
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s
    /// [`HasherConfig`](config/struct.HasherConfig.html)
    pub fn config(&self) -> &HasherConfig {
        &self.config
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s
    /// [`Password`](data/struct.Password.html), if any
    pub fn password(&self) -> Option<&Password> {
        self.password.as_ref()
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s [`Salt`](data/struct.Salt.html)
    pub fn salt(&self) -> &Salt {
        &self.salt
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s
    /// [`SecretKey`](data/struct.SecretKey.html), if any
    pub fn secret_key(&self) -> Option<&SecretKey> {
        self.secret_key.as_ref()
    }
}

impl Hasher {
    pub(crate) fn additional_data_mut(&mut self) -> Option<&mut AdditionalData> {
        self.additional_data.as_mut()
    }
    pub(crate) fn password_mut(&mut self) -> Option<&mut Password> {
        self.password.as_mut()
    }
    pub(crate) fn salt_mut(&mut self) -> &mut Salt {
        &mut self.salt
    }
    pub(crate) fn secret_key_mut(&mut self) -> Option<&mut SecretKey> {
        self.secret_key.as_mut()
    }
    pub(crate) fn set_password(&mut self, password: Option<Password>) {
        self.password = password;
    }
    pub(crate) fn set_salt(&mut self, salt: Salt) {
        self.salt = salt;
    }
    pub(crate) fn set_secret_key(&mut self, secret_key: Option<SecretKey>) {
        self.secret_key = secret_key;
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.config.validate()?;
        if let Some(ref additional_data) = self.additional_data {
            additional_data.validate()?;
        }
        match self.password {
            Some(ref password) => {
                password.validate()?;
                if self.config.password_clearing() && password.constructed_from_borrow() {
                    return Err(Error::new(ErrorKind::DataError(
                        DataError::PasswordUnownedError,
                    )));
                }
            }
            None => {
                return Err(Error::new(ErrorKind::DataError(
                    DataError::PasswordMissingError,
                )))
            }
        }
        self.salt.validate()?;
        if !self.config.opt_out_of_random_salt() & !self.salt.is_random() {
            return Err(Error::new(ErrorKind::DataError(
                DataError::SaltNonRandomError,
            )));
        }
        match self.secret_key {
            Some(ref secret_key) => {
                secret_key.validate()?;
                if self.config.secret_key_clearing() && secret_key.constructed_from_borrow() {
                    return Err(Error::new(ErrorKind::DataError(
                        DataError::SecretKeyUnownedError,
                    )));
                }
            }
            None => {
                if !self.config.opt_out_of_secret_key() {
                    return Err(Error::new(ErrorKind::DataError(
                        DataError::SecretKeyMissingError,
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{Variant, Version};

    struct Test {
        variant: Variant,
        version: Version,
        expected: Vec<u8>,
    }

    impl Test {
        fn run(&self) {
            let mut hasher = Hasher::default();
            let raw_hash = hasher
                .configure_hash_length(32)
                .configure_iterations(3)
                .configure_lanes(4)
                .configure_memory_size(32)
                .configure_threads(4)
                .configure_variant(self.variant)
                .configure_version(self.version)
                .opt_out_of_random_salt(true)
                .with_additional_data(vec![4; 12])
                .with_password(vec![1; 32])
                .with_salt(vec![2; 16])
                .with_secret_key(vec![3; 8])
                .hash_raw()
                .unwrap();
            assert_eq!(raw_hash.raw_hash_bytes(), self.expected.as_slice());
        }
    }

    #[test]
    fn test_hasher_0x10_2d() {
        Test {
            variant: Variant::Argon2d,
            version: Version::_0x10,
            expected: vec![
                0x96, 0xa9, 0xd4, 0xe5, 0xa1, 0x73, 0x40, 0x92, 0xc8, 0x5e, 0x29, 0xf4, 0x10, 0xa4,
                0x59, 0x14, 0xa5, 0xdd, 0x1f, 0x5c, 0xbf, 0x08, 0xb2, 0x67, 0x0d, 0xa6, 0x8a, 0x02,
                0x85, 0xab, 0xf3, 0x2b,
            ],
        }.run();
    }

    #[test]
    fn test_hasher_0x10_2i() {
        Test {
            variant: Variant::Argon2i,
            version: Version::_0x10,
            expected: vec![
                0x87, 0xae, 0xed, 0xd6, 0x51, 0x7a, 0xb8, 0x30, 0xcd, 0x97, 0x65, 0xcd, 0x82, 0x31,
                0xab, 0xb2, 0xe6, 0x47, 0xa5, 0xde, 0xe0, 0x8f, 0x7c, 0x05, 0xe0, 0x2f, 0xcb, 0x76,
                0x33, 0x35, 0xd0, 0xfd,
            ],
        }.run();
    }

    #[test]
    fn test_hasher_0x10_2id() {
        Test {
            variant: Variant::Argon2id,
            version: Version::_0x10,
            expected: vec![
                0xb6, 0x46, 0x15, 0xf0, 0x77, 0x89, 0xb6, 0x6b, 0x64, 0x5b, 0x67, 0xee, 0x9e, 0xd3,
                0xb3, 0x77, 0xae, 0x35, 0x0b, 0x6b, 0xfc, 0xbb, 0x0f, 0xc9, 0x51, 0x41, 0xea, 0x8f,
                0x32, 0x26, 0x13, 0xc0,
            ],
        }.run();
    }

    #[test]
    fn test_hasher_0x13_2d() {
        Test {
            variant: Variant::Argon2d,
            version: Version::_0x13,
            expected: vec![
                0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97, 0x53, 0x71, 0xd3, 0x09, 0x19, 0x73,
                0x42, 0x94, 0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1, 0xa1, 0x3a, 0x4d, 0xb9,
                0xfa, 0xbe, 0x4a, 0xcb,
            ],
        }.run();
    }

    #[test]
    fn test_hasher_0x13_2i() {
        Test {
            variant: Variant::Argon2i,
            version: Version::_0x13,
            expected: vec![
                0xc8, 0x14, 0xd9, 0xd1, 0xdc, 0x7f, 0x37, 0xaa, 0x13, 0xf0, 0xd7, 0x7f, 0x24, 0x94,
                0xbd, 0xa1, 0xc8, 0xde, 0x6b, 0x01, 0x6d, 0xd3, 0x88, 0xd2, 0x99, 0x52, 0xa4, 0xc4,
                0x67, 0x2b, 0x6c, 0xe8,
            ],
        }.run();
    }

    #[test]
    fn test_hasher_0x13_2id() {
        Test {
            variant: Variant::Argon2id,
            version: Version::_0x13,
            expected: vec![
                0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
                0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
                0x6b, 0x01, 0xe6, 0x59,
            ],
        }.run();
    }

    #[test]
    fn test_hasher_clearing() {
        // Password is cleared and secret key remains
        let mut hasher = Hasher::default();
        let hash = hasher
            .configure_password_clearing(true)
            .configure_secret_key_clearing(false)
            .opt_out_of_random_salt(true)
            .opt_out_of_secret_key(true)
            .with_password("password")
            .with_secret_key("secret")
            .hash();
        match hash {
            Ok(_) => panic!("Should return an error"),
            Err(e) => assert_eq!(
                e,
                Error::new(ErrorKind::DataError(DataError::PasswordUnownedError))
            ),
        }
        assert!(hasher.password().is_none());
        assert!(hasher.secret_key().is_some());

        // Secret key is cleared and password remains
        let mut hasher = Hasher::default();
        let hash = hasher
            .configure_password_clearing(false)
            .configure_secret_key_clearing(true)
            .opt_out_of_random_salt(true)
            .opt_out_of_secret_key(true)
            .with_password("password")
            .with_secret_key("secret")
            .hash();
        match hash {
            Ok(_) => panic!("Should return an error"),
            Err(e) => assert_eq!(
                e,
                Error::new(ErrorKind::DataError(DataError::SecretKeyUnownedError))
            ),
        }
        assert!(hasher.password().is_some());
        assert!(hasher.secret_key().is_none());
    }

    #[test]
    fn test_hasher_fast_but_insecure() {
        let mut hasher = Hasher::fast_but_insecure();
        let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_hasher_serialization() {
        use serde_json;

        let password = "P@ssw0rd";
        let secret_key = "secret";

        let mut hasher1 = Hasher::default();
        hasher1
            .configure_password_clearing(false)
            .opt_out_of_random_salt(true)
            .with_additional_data("additional data")
            .with_password(password)
            .with_secret_key(secret_key)
            .with_salt("somesalt");
        let hash1 = hasher1.hash().expect("failed to hash");
        let hash_raw1 = hasher1.hash_raw().expect("failed to hash_raw");

        // Serialize Hasher
        let j = serde_json::to_string_pretty(&hasher1).expect("failed to serialize hasher");
        // Deserialize Hasher
        let mut hasher2: Hasher = serde_json::from_str(&j).expect("failed to deserialize hasher");
        // Assert that password and secret key have been erased
        assert_eq!(hasher2.password(), None);
        assert_eq!(hasher2.secret_key(), None);
        // Assert that calling hash or hash_raw produces an error
        assert!(hasher2.hash().is_err());
        assert!(hasher2.hash_raw().is_err());
        // Add a password and secret key and ensure hash and hash_raw now work
        hasher2.with_password(password).with_secret_key(secret_key);
        let hash2 = hasher2.hash().expect("failed to hash");
        let hash_raw2 = hasher2.hash_raw().expect("failed to hash_raw");
        // Assert hashes match originals
        assert_eq!(hash1, hash2);
        assert_eq!(hash_raw1, hash_raw2);
    }

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Hasher>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Hasher>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<Hasher>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<Hasher>();
    }
}
