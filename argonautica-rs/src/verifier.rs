use futures::Future;
use futures_cpupool::CpuPool;

use backend::decode_rust;
use config::{default_cpu_pool, Backend, VerifierConfig};
use input::{AdditionalData, Password, SecretKey};
use output::HashRaw;
use {Error, ErrorKind, Hasher};

impl Default for Hash {
    fn default() -> Hash {
        Hash::None
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum Hash {
    Encoded(String),
    Raw(HashRaw),
    None,
}

impl<'a> Default for Verifier<'a> {
    /// Same as the [`new`](struct.Verifier.html#method.new) method
    fn default() -> Verifier<'a> {
        Verifier {
            hash: Hash::default(),
            hasher: Hasher::default(),
        }
    }
}

/// <b><u>One of the two main structs.</u></b> Use it to verify passwords against hashes
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Verifier<'a> {
    hash: Hash,
    hasher: Hasher<'a>,
}

impl<'a> Verifier<'a> {
    /// Creates a new [`Verifier`](struct.Verifier.html) with the following configuration:
    /// * `backend`: [`Backend::C`](config/enum.Backend.html#variant.C)
    /// * `cpu_pool`: A [`CpuPool`](https://docs.rs/futures-cpupool/0.1.8/futures_cpupool/struct.CpuPool.html) ...
    ///     * with threads equal to the number of logical cores on your machine
    ///     * that is lazily created, i.e. created only if / when you call the method that
    ///       needs it ([`verify_non_blocking`](struct.Verifier.html#method.verify_non_blocking))
    /// * `password_clearing`: `false`
    /// * `secret_key_clearing`: `false`
    /// * `threads`: The number of logical cores on your machine
    pub fn new() -> Verifier<'a> {
        Verifier::default()
    }
    /// Allows you to configure [`Verifier`](struct.Verifier.html) with a custom backend. The
    /// default backend is [`Backend::C`](config/enum.Backend.html#variant.C), <i>which is
    /// currently the only backend supported. A Rust backend is planned, but is not currently
    /// available. If you configure a [`Verifier`](struct.Verifier.html) with
    /// [`Backend::Rust`](config/enum.Backend.html#variant.Rust) it will error</i>
    pub fn configure_backend(&mut self, backend: Backend) -> &mut Verifier<'a> {
        self.hasher.config.set_backend(backend);
        self
    }
    /// Allows you to configure [`Verifier`](struct.Verifier.html) with a custom
    /// [`CpuPool`](https://docs.rs/futures-cpupool/0.1.8/futures_cpupool/struct.CpuPool.html).
    /// The default [`Verifier`](struct.Verifier.html) does not have a cpu pool, which is
    /// only needed for the [`verify_non_blocking`](struct.Verifier.html#method.verify_non_blocking)
    /// method. If you call [`verify_non_blocking`](struct.Verifier.html#method.verify_non_blocking)
    /// without a cpu pool, a default cpu pool will be created for you on the fly; so even
    /// if you never configure [`Verifier`](struct.Verifier.html) with this method you can still
    /// use the [`verify_non_blocking`](struct.Verifier.html#method.verify_non_blocking) method.
    /// The default cpu pool has as many threads as the number of logical cores on your machine
    pub fn configure_cpu_pool(&mut self, cpu_pool: CpuPool) -> &mut Verifier<'a> {
        self.hasher.config.set_cpu_pool(cpu_pool);
        self
    }
    /// Allows you to configure [`Verifier`](struct.Verifier.html) to erase the password bytes
    /// after each call to [`verify`](struct.Verifier.html#method.verify)
    /// or its non-blocking equivalent. The default is to <b>not</b> clear out the password
    /// bytes (i.e. `false`). If you set this option to `true`, you must provide
    /// [`Verifier`](struct.Verifier.html) with a mutable password, e.g. a password
    /// constructed from a `String`, `Vec<u8>`, `&mut str`, `&mut [u8]`, etc. as opposed to
    /// one constructed from a `&str`, `&[u8]`, etc., or else verifying will return an
    /// [`Error`](struct.Error.html).
    pub fn configure_password_clearing(&mut self, boolean: bool) -> &mut Verifier<'a> {
        self.hasher.config.set_password_clearing(boolean);
        self
    }
    /// Allows you to configure [`Verifier`](struct.Verifier.html) to erase the secret key bytes
    /// after each call to [`verify`](struct.Verifier.html#method.verify)
    /// or its non-blocking equivalent. The default is to <b>not</b> clear out the secret key
    /// bytes (i.e. `false`). If you set this option to `true`, you must provide
    /// [`Verifier`](struct.Verifier.html) with a mutable secret key, e.g. a secret key
    /// constructed from a `String`, `Vec<u8>`, `&mut str`, `&mut [u8]`, etc. as opposed to
    /// one constructed from a `&str`, `&[u8]`, etc., or else verifying will return an
    /// [`Error`](struct.Error.html).
    pub fn configure_secret_key_clearing(&mut self, boolean: bool) -> &mut Verifier<'a> {
        self.hasher.config.set_secret_key_clearing(boolean);
        self
    }
    /// Allows you to configure [`Verifier`](struct.Verifier.html) to use a custom number of
    /// threads. The default is the number of physical cores on your machine. If you choose
    /// a number of threads that is greater than the lanes configuration of your hash,
    /// [`Verifier`](struct.Verifier.html) will use the minimum of the two.
    pub fn configure_threads(&mut self, threads: u32) -> &mut Verifier<'a> {
        self.hasher.config.set_threads(threads);
        self
    }
    /// Clones the [`Verifier`](struct.Verifier.html), returning a new
    /// [`Verifier`](struct.Verifier.html) with a `static` lifetime. Use this method if you
    /// would like to move a [`Verifier`](struct.Verifier.html) to another thread
    pub fn to_owned(&self) -> Verifier<'static> {
        Verifier {
            hash: self.hash.clone(),
            hasher: self.hasher.to_owned(),
        }
    }
    /// <b><u>The primary method (blocking version)</u></b>
    ///
    /// After you have configured [`Verifier`](struct.Verifier.html) to your liking and provided
    /// it will all the data it needs to verify a password, i.e.
    /// * a string-encoded hash or [`HashRaw`](output/struct.HashRaw.html),
    /// * a [`Password`](input/struct.Password.html),
    /// * a [`SecretKey`](input/struct.SecretKey.html) (if required),
    /// * [`AdditionalData`](input/struct.AdditionalData.html) (if required),
    ///
    /// call this method to verify that the password matches the hash or
    /// [`HashRaw`](output/struct.HashRaw.html)
    pub fn verify(&mut self) -> Result<bool, Error> {
        match self.hash {
            Hash::Encoded(ref s) => {
                let hash_raw = decode_rust(s)?;
                self.hasher
                    .config
                    .set_hash_len(hash_raw.raw_hash_bytes().len() as u32);
                self.hasher.config.set_iterations(hash_raw.iterations());
                self.hasher.config.set_lanes(hash_raw.lanes());
                self.hasher.config.set_memory_size(hash_raw.memory_size());
                self.hasher.config.set_opt_out_of_secret_key(true);
                self.hasher.config.set_variant(hash_raw.variant());
                self.hasher.config.set_version(hash_raw.version());
                self.hasher.salt = hash_raw.raw_salt_bytes().into();
                let hash_raw2 = self.hasher.hash_raw()?;
                let is_valid = if hash_raw.raw_hash_bytes() == hash_raw2.raw_hash_bytes() {
                    true
                } else {
                    false
                };
                Ok(is_valid)
            }
            Hash::Raw(ref hash_raw) => {
                self.hasher
                    .config
                    .set_hash_len(hash_raw.raw_hash_bytes().len() as u32);
                self.hasher.config.set_iterations(hash_raw.iterations());
                self.hasher.config.set_lanes(hash_raw.lanes());
                self.hasher.config.set_memory_size(hash_raw.memory_size());
                self.hasher.config.set_opt_out_of_secret_key(true);
                self.hasher.config.set_variant(hash_raw.variant());
                self.hasher.config.set_version(hash_raw.version());
                self.hasher.salt = hash_raw.raw_salt_bytes().into();
                let hash_raw2 = self.hasher.hash_raw()?;
                let is_valid = if hash_raw.raw_hash_bytes() == hash_raw2.raw_hash_bytes() {
                    true
                } else {
                    false
                };
                Ok(is_valid)
            }
            Hash::None => return Err(Error::new(ErrorKind::HashMissingError)),
        }
    }
    /// <b><u>The primary method (non-blocking version)</u></b>
    ///
    /// Same as [`verify`](struct.Verifier.html#method.verify) except it returns a
    /// [`Future`](https://docs.rs/futures/0.1.21/futures/future/trait.Future.html)
    /// instead of a [`Result`](https://doc.rust-lang.org/std/result/enum.Result.html)
    pub fn verify_non_blocking(&mut self) -> impl Future<Item = bool, Error = Error> {
        let mut verifier = self.to_owned();
        match verifier.hasher.config.cpu_pool() {
            Some(cpu_pool) => cpu_pool.spawn_fn(move || verifier.verify()),
            None => {
                let cpu_pool = default_cpu_pool();
                verifier.hasher.config.set_cpu_pool(cpu_pool.clone());
                cpu_pool.spawn_fn(move || verifier.verify())
            }
        }
    }
    /// Allows you to provide [`Verifier`](struct.Verifier.html) with the additional data
    /// that was originally used to create the hash. Normally hashes are not created with
    /// additional data; so you are not likely to need this method
    pub fn with_additional_data<AD>(&mut self, additional_data: AD) -> &mut Verifier<'a>
    where
        AD: Into<AdditionalData>,
    {
        self.hasher.additional_data = Some(additional_data.into());
        self
    }
    /// Allows you to provide [`Verifier`](struct.Verifier.html) with the hash to verify
    /// against (in the form of a string-encoded hash like those produced by the
    /// [`hash`](struct.Hasher.html#method.hash) or
    /// [`hash_non_blocking`](struct.Hasher.html#method.hash_non_blocking)
    /// methods on [`Hasher`](struct.Hasher.html))
    pub fn with_hash<S>(&mut self, hash: S) -> &mut Verifier<'a>
    where
        S: AsRef<str>,
    {
        self.hash = Hash::Encoded(hash.as_ref().to_string());
        self
    }
    /// Allows you to provide [`Verifier`](struct.Verifier.html) with the hash to verify
    /// against (in the form of a [`HashRaw`](output/struct.HashRaw.html) like those produced
    /// by the [`hash_raw`](struct.Hasher.html#method.hash_raw) or
    /// [`hash_raw_non_blocking`](struct.Hasher.html#method.hash_raw_non_blocking)
    /// methods on [`Hasher`](struct.Hasher.html))
    pub fn with_hash_raw(&mut self, hash_raw: &HashRaw) -> &mut Verifier<'a> {
        self.hash = Hash::Raw(hash_raw.clone());
        self
    }
    /// Allows you to provide [`Verifier`](struct.Verifier.html) with the password
    /// to verify against
    pub fn with_password<P>(&mut self, password: P) -> &mut Verifier<'a>
    where
        P: Into<Password<'a>>,
    {
        self.hasher.password = Some(password.into());
        self
    }
    /// Allows you to provide [`Verifier`](struct.Verifier.html) with the secret key
    /// that was initially used to create the hash
    pub fn with_secret_key<SK>(&mut self, secret_key: SK) -> &mut Verifier<'a>
    where
        SK: Into<SecretKey<'a>>,
    {
        self.hasher.secret_key = Some(secret_key.into());
        self
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s
    /// [`AdditionalData`](input/struct.AdditionalData.html), if any
    pub fn additional_data(&self) -> Option<&AdditionalData> {
        self.hasher.additional_data()
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s
    /// [`VerifierConfig`](config/struct.VerifierConfig.html)
    pub fn config(&self) -> VerifierConfig {
        VerifierConfig::new(
            /* backend */ self.hasher.config.backend(),
            /* cpu_pool */ self.hasher.config.cpu_pool(),
            /* password_clearing */ self.hasher.config.password_clearing(),
            /* secret_key_clearing */ self.hasher.config.secret_key_clearing(),
            /* threads */ self.hasher.config.threads(),
        )
    }
    /// Returns the [`Verifier`](struct.Verifier.html)'s string-encoded hash, if any
    pub fn hash(&self) -> Option<String> {
        match self.hash {
            Hash::Encoded(ref s) => Some(s.to_string()),
            Hash::Raw(ref hash_raw) => Some(hash_raw.encode_rust()),
            Hash::None => None,
        }
    }
    /// Returns the [`Verifier`](struct.Verifier.html)'s [`HashRaw`](output/struct.HashRaw.html),
    /// if any
    pub fn hash_raw(&self) -> Result<Option<HashRaw>, Error> {
        match self.hash {
            Hash::Encoded(ref s) => Ok(Some(decode_rust(s)?)),
            Hash::Raw(ref hash_raw) => Ok(Some(hash_raw.clone())),
            Hash::None => Ok(None),
        }
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s
    /// [`Password`](input/struct.Password.html), if any
    pub fn password(&self) -> Option<&Password<'a>> {
        self.hasher.password()
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s
    /// [`SecretKey`](input/struct.SecretKey.html), if any
    pub fn secret_key(&self) -> Option<&SecretKey<'a>> {
        self.hasher.secret_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "serde")]
    #[test]
    fn test_verifier_serialization() {
        use serde_json;

        let password = "P@ssw0rd";
        let secret_key = "secret";

        let mut hasher = Hasher::default();
        hasher
            .configure_password_clearing(false)
            .configure_secret_key_clearing(false)
            .with_additional_data("additional data")
            .with_password(password)
            .with_secret_key(secret_key)
            .with_salt("somesalt");
        let hash_raw = hasher.hash_raw().expect("failed to hash_raw");

        let mut verifier1 = Verifier::default();
        verifier1
            .configure_password_clearing(false)
            .configure_secret_key_clearing(false)
            .with_additional_data("additional data")
            .with_password(password)
            .with_secret_key(secret_key)
            .with_hash_raw(&hash_raw);
        let is_valid = verifier1.verify().unwrap();
        if !is_valid {
            panic!(
                "\nverifier1:\n{:#?}\nAdditional Data: {:?}\nHash: {}\nPasswod: {:?}\nSecret key: {:?}",
                verifier1,
                "additional data".as_bytes(),
                hash_raw.to_string(),
                password.as_bytes(),
                "secret".as_bytes()
            );
        };

        // Serialize Verifier
        let j = serde_json::to_string_pretty(&verifier1).expect("failed to serialize verifier");
        // Deserialize Verifier
        let mut verifier2: Verifier =
            serde_json::from_str(&j).expect("failed to deserialize verifier");
        // Assert that password and secret key have been erased
        assert!(verifier2.password().is_none());
        assert!(verifier2.secret_key().is_none());
        // Add a password and ensure that verify doesn't return an error
        verifier2.with_password(password);
        let is_valid = verifier2.verify().unwrap();
        assert!(!is_valid);
        // Add a secret key and ensure that verify returns is_valid
        verifier2.with_secret_key(secret_key);
        let is_valid = verifier2.verify().unwrap();
        if !is_valid {
            panic!("\nverifier2:\n{:#?}\n", verifier2);
        };
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

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<Verifier>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<Verifier>();
    }
}
