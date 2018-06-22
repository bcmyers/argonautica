use futures::Future;
use futures_cpupool::CpuPool;
use scopeguard;

use config::defaults::{default_cpu_pool, default_lanes};
use config::{Backend, HasherConfig, Variant, Version};
use input::{AdditionalData, Container, Password, Salt, SecretKey};
use output::HashRaw;
use {Error, ErrorKind};

impl<'a> Default for Hasher<'a> {
    /// Same as the [`new`](struct.Hasher.html#method.new) method
    fn default() -> Hasher<'static> {
        Hasher {
            additional_data: None,
            config: HasherConfig::default(),
            password: None,
            salt: Salt::default(),
            secret_key: None,
        }
    }
}

/// <b><u>One of the two main structs.</u></b> Use it to turn passwords into hashes
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Hasher<'a> {
    pub(crate) additional_data: Option<AdditionalData>,
    pub(crate) config: HasherConfig,
    #[cfg_attr(feature = "serde", serde(skip_serializing, skip_deserializing))]
    pub(crate) password: Option<Password<'a>>,
    pub(crate) salt: Salt,
    #[cfg_attr(feature = "serde", serde(skip_serializing, skip_deserializing))]
    pub(crate) secret_key: Option<SecretKey<'a>>,
}

impl<'a> Hasher<'a> {
    /// Creates a new [`Hasher`](struct.Hasher.html) with a sensible default configuration
    /// for the average machine (e.g. an early-2014 MacBook Air).
    ///
    /// <b>Note: If you are using this library to hash user passwords for storage in a database,
    /// it is recommended that you adjust these settings for your machine (primarily `iterations`,
    /// and `memory_size`) until the time it takes to hash a password is approximately 300-500
    /// milliseconds</b>.
    ///
    /// There is a script in the examples directory that will show you the various configuration
    /// options for your machine that produce hashing times between 300 and 500 milliseconds
    /// (Don't forget to run it with the `--release` and `--features="simd"` flags). Alternatively,
    /// you can clone the repository and run the benchmark suite with
    /// `cargo bench --features="benches simd" -- inputs`, which will take longer but which runs
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
    /// * `hash_len`: `32` bytes
    /// * `iterations`: `192`
    /// * `lanes`: The number of logical cores on your machine
    /// * `memory_size`: `4096` kibibytes
    /// * `opt_out_of_secret_key`: `false`
    /// * `password_clearing`: `false`
    /// * `salt`: random [`Salt`](input/struct.Salt.html) of length 32 bytes that renews with every hash
    /// * `secret_key_clearing`: `false`
    /// * `threads`: The number of logical cores on your machine
    /// * `variant`: [`Variant::Argon2id`](config/enum.Variant.html#variant.Argon2id)
    /// * `version`: [`Version::_0x13`](config/enum.Verion.html#variant._0x13)
    pub fn new() -> Hasher<'static> {
        Hasher::default()
    }
    /// Creates a new [`Hasher`](struct.Hasher.html) that is <b>fast but <u>highly</u> insecure</b>.
    /// If for some reason you'd like to use Argon2 for hashing where security is not an issue,
    /// you can use this configuration. It sets hash length to 32 bytes (256 bits), uses only
    /// 1 iteration, sets memory size to the minimum of 8 * the number of lanes, uses a
    /// deterministic salt of the minimum length of 8 bytes, and opts out of a secret key.
    /// All other configuration options are the same as the defaults. On the developer's
    /// early-2014 Macbook Air, this configuration hashes the full text of Shakespear's Hamlet
    /// in approximately 1 millisecond (on average). [MD5](https://github.com/stainless-steel/md5)
    /// does it in about half the time and [sha2](https://github.com/RustCrypto/hashes) with the
    /// SHA-256 algorithm performs about the same as `argonautica`
    pub fn fast_but_insecure() -> Hasher<'a> {
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
            .configure_hash_len(32)
            .configure_iterations(1)
            .configure_lanes(lanes)
            .configure_memory_size(memory_size(lanes))
            .configure_password_clearing(false)
            .configure_secret_key_clearing(false)
            .configure_threads(lanes)
            .opt_out_of_secret_key(true)
            .with_salt(&[0u8; 8][..]);
        hasher
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) with a custom backend. The
    /// default backend is [`Backend::C`](config/enum.Backend.html#variant.C), <i>which is
    /// currently the only backend supported. A Rust backend is planned, but is not currently
    /// available. If you configure a [`Hasher`](struct.Hasher.html) with
    /// [`Backend::Rust`](config/enum.Backend.html#variant.Rust) it will error when you
    /// call [`hash`](struct.Hasher.html#method.hash),
    /// [`hash_raw`](struct.Hasher.html#method.hash_raw) or their non-blocking equivalents</i>
    pub fn configure_backend(&mut self, backend: Backend) -> &mut Hasher<'a> {
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
    pub fn configure_cpu_pool(&mut self, cpu_pool: CpuPool) -> &mut Hasher<'a> {
        self.config.set_cpu_pool(cpu_pool);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom hash length
    /// (in number of bytes). The default is `32`.
    ///
    /// See [configuration example](index.html#configuration) for a more detailed discussion
    /// of this parameter
    pub fn configure_hash_len(&mut self, hash_len: u32) -> &mut Hasher<'a> {
        self.config.set_hash_len(hash_len);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom number of
    /// iterations. The default is `192`.
    ///
    /// See [configuration example](index.html#configuration) for a more details on this parameter
    pub fn configure_iterations(&mut self, iterations: u32) -> &mut Hasher<'a> {
        self.config.set_iterations(iterations);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom number of
    /// lanes. The default is the number of physical cores on your machine.
    ///
    /// See [configuration example](index.html#configuration) for a more details on this parameter
    pub fn configure_lanes(&mut self, lanes: u32) -> &mut Hasher<'a> {
        self.config.set_lanes(lanes);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom memory size
    /// (in kibibytes). The default is `4096`.
    ///
    /// See [configuration example](index.html#configuration) for a more details on this parameter
    pub fn configure_memory_size(&mut self, memory_size: u32) -> &mut Hasher<'a> {
        self.config.set_memory_size(memory_size);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to erase the password bytes
    /// after each call to [`hash`](struct.Hasher.html#method.hash),
    /// [`hash_raw`](struct.Hasher#method.hash_raw), or their non-blocking equivalents.
    /// The default is to <b>not</b> clear out the password
    /// bytes (i.e. `false`). If you set this option to `true`, you must provide
    /// [`Hasher`](struct.Hasher.html) with a mutable password, e.g. a password
    /// constructed from a `String`, `Vec<u8>`, `&mut str`, `&mut [u8]`, etc. as opposed to
    /// one constructed from a `&str`, `&[u8]`, etc., or else hashing will return an
    /// [`Error`](struct.Error.html).
    ///
    /// See [configuration example](index.html#configuration) for a more details on this parameter
    pub fn configure_password_clearing(&mut self, boolean: bool) -> &mut Hasher<'a> {
        self.config.set_password_clearing(boolean);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to erase the secret key bytes
    /// after each call to [`hash`](struct.Hasher.html#method.hash),
    /// [`hash_raw`](struct.Hasher#method.hash_raw), or their non-blocking equivalents.
    /// The default is to <b>not</b> clear out the secret key
    /// bytes (i.e. `false`). If you set this option to `true`, you must provide
    /// [`Hasher`](struct.Hasher.html) with a mutable secret key, e.g. a secret key
    /// constructed from a `String`, `Vec<u8>`, `&mut str`, `&mut [u8]`, etc. as opposed to
    /// one constructed from a `&str`, `&[u8]`, etc., or else hashing will return an
    /// [`Error`](struct.Error.html).
    ///
    /// See [configuration example](index.html#configuration) for a more details on this parameter
    pub fn configure_secret_key_clearing(&mut self, boolean: bool) -> &mut Hasher<'a> {
        self.config.set_secret_key_clearing(boolean);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom number of
    /// threads. The default is the number of physical cores on your machine. If you choose
    /// a number of threads that is greater than the lanes configuration,
    /// [`Hasher`](struct.Hasher.html) will use the minimum of the two.
    ///
    /// See [configuration example](index.html#configuration) for a more details on this parameter
    pub fn configure_threads(&mut self, threads: u32) -> &mut Hasher<'a> {
        self.config.set_threads(threads);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom Argon2
    /// variant. The default is [`Variant::Argon2id`](config/enum.Variant.html#variant.Argon2id).
    /// Do <b>not</b> use a different variant unless you have a specific reason to do so.
    ///
    /// See [configuration example](index.html#configuration) for a more details on this parameter
    pub fn configure_variant(&mut self, variant: Variant) -> &mut Hasher<'a> {
        self.config.set_variant(variant);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom Argon2 version.
    /// The default and latest (as of 5/18) is
    /// [`Version::_0x13`](config/enum.Version.html#variant._0x13).
    /// Do <b>not</b> use a different version unless you have a specific reason to do so.
    ///
    /// See [configuration example](index.html#configuration) for a more details on this parameter
    pub fn configure_version(&mut self, version: Version) -> &mut Hasher<'a> {
        self.config.set_version(version);
        self
    }
    /// <b><u>The primary method (blocking version).</u></b>
    ///
    /// After you have configured a [`Hasher`](struct.Hasher.html) to your liking and provided
    /// it will all the data you would like to hash, e.g.
    /// * a [`Password`](input/struct.Password.html),
    /// * a [`Salt`](input/struct.Password.html) (note: it is recommened you use the default random salt),
    /// * a [`SecretKey`](input/struct.SecretKey.html),
    /// * [`AdditionalData`](input/struct.AdditionalData.html) (optional),
    ///
    /// call this method in order to produce a string-encoded hash, which is safe to store in a
    /// database and against which you can verify passwords later
    pub fn hash(&mut self) -> Result<String, Error> {
        let hash_raw = self.hash_raw()?;
        let hash = hash_raw.encode_rust();
        Ok(hash)
    }
    /// <b><u>The primary method (non-blocking version).</u></b>
    ///
    /// Same as [`hash`](struct.Hasher.html#method.hash) except it returns a
    /// [`Future`](https://docs.rs/futures/0.1.21/futures/future/trait.Future.html)
    /// instead of a [`Result`](https://doc.rust-lang.org/std/result/enum.Result.html)
    pub fn hash_non_blocking(&mut self) -> impl Future<Item = String, Error = Error> {
        self.hash_raw_non_blocking().and_then(|hash_raw| {
            let hash = hash_raw.encode_rust();
            Ok::<_, Error>(hash)
        })
    }
    /// Like the [`hash`](struct.Hasher.html#method.hash) method, but instead of producing
    /// an string-encoded hash, it produces a [`HashRaw`](output/struct.HashRaw.html) struct
    /// that contains all the components of the string-encoded version, including the raw
    /// hash bytes and the raw salt bytes. In general, you should prefer to use the
    /// [`hash`](struct.Hasher.html#method.hash) method instead of this method
    pub fn hash_raw(&mut self) -> Result<HashRaw, Error> {
        let mut hasher = scopeguard::guard(self, |hasher| {
            hasher.clear();
        });
        hasher.validate()?;
        hasher.salt.update()?;
        let hash_raw = match hasher.config.backend() {
            Backend::C => hasher.hash_raw_c()?,
            Backend::Rust => return Err(Error::new(ErrorKind::BackendUnsupportedError)),
        };
        Ok(hash_raw)
    }
    /// Same as [`hash_raw`](struct.Hasher.html#method.hash) except it returns a
    /// [`Future`](https://docs.rs/futures/0.1.21/futures/future/trait.Future.html)
    /// instead of a [`Result`](https://doc.rust-lang.org/std/result/enum.Result.html)
    pub fn hash_raw_non_blocking(&mut self) -> impl Future<Item = HashRaw, Error = Error> {
        let hasher = scopeguard::guard(self, |hasher| {
            hasher.clear();
        });
        let mut hasher = hasher.to_owned();
        match hasher.config.cpu_pool() {
            Some(cpu_pool) => cpu_pool.spawn_fn(move || hasher.hash_raw()),
            None => {
                let cpu_pool = default_cpu_pool();
                hasher.config.set_cpu_pool(cpu_pool.clone());
                cpu_pool.spawn_fn(move || hasher.hash_raw())
            }
        }
    }
    /// As an extra security measure, if you want to hash without a secret key, which
    /// is not recommended, you must explicitly declare that this is your intention
    /// by calling this method and setting the `opt_out_of_secret_key` configuration to
    /// `true` (by default, it is set to `false`); otherwise hashing will return an error
    /// when you fail to provide a secret key
    pub fn opt_out_of_secret_key(&mut self, boolean: bool) -> &mut Hasher<'a> {
        self.config.set_opt_out_of_secret_key(boolean);
        self
    }
    /// Clones the [`Hasher`](struct.Hasher.html), returning a new
    /// [`Hasher`](struct.Hasher.html) with a `static` lifetime. Use this method if you
    /// would like to move a [`Hasher`](struct.Hasher.html) to another thread
    pub fn to_owned(&self) -> Hasher<'static> {
        let password = self.password.as_ref().map(|password| password.to_owned());
        let secret_key = self
            .secret_key
            .as_ref()
            .map(|secret_key| secret_key.to_owned());
        Hasher {
            additional_data: self.additional_data.clone(),
            config: self.config.clone(),
            password,
            salt: self.salt.clone(),
            secret_key,
        }
    }
    /// Allows you to add some additional data to the [`Hasher`](struct.Hasher.html)
    /// that will be hashed alongside the [`Password`](input/struct.Password.html) and
    /// other pieces of data you would like to hash (i.e. the [`Salt`](input/struct.Salt.html) and
    /// an optional [`SecretKey`](input/struct.SecretKey.html)).
    ///
    /// Including additional data in your hash is not very common; so it is unlikely you will
    /// need to use this method. If, however, you do add additional data, note that it is like
    /// a secret key in that it will be required later in order to verify passwords, and
    /// it is not stored in the string-encoded version of the hash, meaning you will have to
    /// provide it manually to a [`Verifier`](struct.Verifier.html)
    pub fn with_additional_data<AD>(&mut self, additional_data: AD) -> &mut Hasher<'a>
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
    pub fn with_password<P>(&mut self, password: P) -> &mut Hasher<'a>
    where
        P: Into<Password<'a>>,
    {
        self.password = Some(password.into());
        self
    }
    /// Allows you to provide [`Hasher`](struct.Hasher.html) with a custom
    /// [`Salt`](input/struct.Salt.html) to include in the hash. The default
    /// [`Hasher`](struct.Hasher.html) is configured to use a random
    /// [`Salt`](input/struct.Salt.html) of 32 bytes; so there is no need
    /// to call this method. If you would like to use a random
    /// [`Salt`](input/struct.Salt.html) of different length, you can call this method with
    /// `Salt::random(your_custom_length_in_bytes)`. Using a deterministic
    /// [`Salt`](input/struct.Salt.html) is possible, but discouraged
    pub fn with_salt<S>(&mut self, salt: S) -> &mut Hasher<'a>
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
    /// encourages the use of a secret key
    pub fn with_secret_key<SK>(&mut self, secret_key: SK) -> &mut Hasher<'a>
    where
        SK: Into<SecretKey<'a>>,
    {
        self.secret_key = Some(secret_key.into());
        self
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s
    /// [`AdditionalData`](input/struct.AdditionalData.html), if any
    pub fn additional_data(&self) -> Option<&AdditionalData> {
        self.additional_data.as_ref()
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s
    /// [`HasherConfig`](config/struct.HasherConfig.html)
    pub fn config(&self) -> &HasherConfig {
        &self.config
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s
    /// [`Password`](input/struct.Password.html), if any
    pub fn password(&self) -> Option<&Password<'a>> {
        self.password.as_ref()
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s [`Salt`](input/struct.Salt.html)
    pub fn salt(&self) -> &Salt {
        &self.salt
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s
    /// [`SecretKey`](input/struct.SecretKey.html), if any
    pub fn secret_key(&self) -> Option<&SecretKey<'a>> {
        self.secret_key.as_ref()
    }
}

impl<'a> Hasher<'a> {
    pub(crate) fn clear(&mut self) {
        if self.password.is_some() && self.config.password_clearing() {
            {
                let password_mut_ref = self.password.as_mut().unwrap();
                match password_mut_ref.inner {
                    Container::Borrowed(_) => (),
                    Container::BorrowedMut(ref mut bytes) => {
                        unsafe { ::std::ptr::write_bytes(bytes.as_mut_ptr(), 0, bytes.len()) };
                    }
                    Container::Owned(ref mut bytes) => {
                        unsafe { ::std::ptr::write_bytes(bytes.as_mut_ptr(), 0, bytes.len()) };
                    }
                }
            }
            self.password = None;
        }
        if self.secret_key.is_some() && self.config.secret_key_clearing() {
            {
                let secret_key_mut_ref = self.secret_key.as_mut().unwrap();
                match secret_key_mut_ref.inner {
                    Container::Borrowed(_) => (),
                    Container::BorrowedMut(ref mut bytes) => {
                        unsafe { ::std::ptr::write_bytes(bytes.as_mut_ptr(), 0, bytes.len()) };
                    }
                    Container::Owned(ref mut bytes) => {
                        unsafe { ::std::ptr::write_bytes(bytes.as_mut_ptr(), 0, bytes.len()) };
                    }
                }
            }
            self.secret_key = None;
        }
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.config.validate()?;
        if let Some(ref additional_data) = self.additional_data {
            additional_data.validate()?;
        }
        match self.password {
            Some(ref password) => {
                password.validate()?;
                if self.config.password_clearing() && !password.is_mutable() {
                    return Err(Error::new(ErrorKind::PasswordImmutableError));
                }
            }
            None => return Err(Error::new(ErrorKind::PasswordMissingError)),
        }
        self.salt.validate()?;
        match self.secret_key {
            Some(ref secret_key) => {
                secret_key.validate()?;
                if self.config.secret_key_clearing() && !secret_key.is_mutable() {
                    return Err(Error::new(ErrorKind::SecretKeyImmutableError));
                }
            }
            None => {
                if !self.config.opt_out_of_secret_key() {
                    return Err(Error::new(ErrorKind::SecretKeyMissingError));
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
                .configure_hash_len(32)
                .configure_iterations(3)
                .configure_lanes(4)
                .configure_memory_size(32)
                .configure_threads(4)
                .configure_variant(self.variant)
                .configure_version(self.version)
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
            .with_password("password")
            .with_secret_key("secret")
            .hash();
        match hash {
            Ok(_) => panic!("Should return an error"),
            Err(e) => assert_eq!(e, Error::new(ErrorKind::PasswordImmutableError)),
        }
        assert!(hasher.password().is_none());
        assert!(hasher.secret_key().is_some());

        // Secret key is cleared and password remains
        let mut hasher = Hasher::default();
        let hash = hasher
            .configure_password_clearing(false)
            .configure_secret_key_clearing(true)
            .with_password("password")
            .with_secret_key("secret")
            .hash();
        match hash {
            Ok(_) => panic!("Should return an error"),
            Err(e) => assert_eq!(e, Error::new(ErrorKind::SecretKeyImmutableError)),
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
