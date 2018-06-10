use futures::Future;
use futures_cpupool::CpuPool;
use scopeguard;
#[cfg(feature = "serde")]
use serde;
#[cfg(feature = "serde")]
use serde::ser::SerializeStruct;

use config::{default_cpu_pool, Backend, VerifierConfig};
use errors::DataError;
use input::{AdditionalData, Password, SecretKey};
use output::HashRaw;
use {Error, ErrorKind, Hasher};

impl Default for Verifier {
    /// Same as the [`new`](struct.Verifier.html#method.new) method
    fn default() -> Verifier {
        Verifier {
            additional_data: None,
            config: VerifierConfig::default(),
            hash: None,
            hash_raw: None,
            latest: Latest::default(),
            password: None,
            secret_key: None,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::ser::Serialize for Verifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("Verifier", 3)?;
        state.serialize_field("additionalData", &self.additional_data)?;
        state.serialize_field("config", &self.config)?;
        match self.latest {
            Latest::Hash => state.serialize_field("hash", &self.hash)?,
            Latest::HashRaw => match self.hash_raw {
                Some(ref hash_raw) => {
                    let thing_to_serialize = Some(hash_raw.to_string());
                    state.serialize_field("hash", &thing_to_serialize)?;
                }
                None => {
                    let thing_to_serialize: Option<&str> = None;
                    state.serialize_field("hash", &thing_to_serialize)?
                }
            },
        }
        state.end()
    }
}

/// <b><u>One of the two main structs.</u></b> Use it to verify passwords against hashes
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Verifier {
    additional_data: Option<AdditionalData>,
    config: VerifierConfig,
    hash: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing, skip_deserializing))]
    hash_raw: Option<HashRaw>,
    #[cfg_attr(feature = "serde", serde(skip_serializing, skip_deserializing))]
    latest: Latest,
    #[cfg_attr(feature = "serde", serde(skip_serializing, skip_deserializing))]
    password: Option<Password>,
    #[cfg_attr(feature = "serde", serde(skip_serializing, skip_deserializing))]
    secret_key: Option<SecretKey>,
}

// TODO: Getters
impl Verifier {
    /// Creates a new [`Verifier`](struct.Verifier.html) with the following configuration:
    /// * `backend`: [`Backend::C`](config/enum.Backend.html#variant.C)
    /// * `cpu_pool`: A [`CpuPool`](https://docs.rs/futures-cpupool/0.1.8/futures_cpupool/struct.CpuPool.html) ...
    ///     * with threads equal to the number of logical cores on your machine
    ///     * that is lazily created, i.e. created only if / when you call the method that
    ///       needs it ([`verify_non_blocking`](struct.Verifier.html#method.verify_non_blocking))
    /// * `password_clearing`: `false`
    /// * `secret_key_clearing`: `false`
    pub fn new() -> Verifier {
        Verifier::default()
    }
    /// Allows you to configure [`Verifier`](struct.Verifier.html) with a custom backend. The
    /// default backend is [`Backend::C`](config/enum.Backend.html#variant.C), <i>which is
    /// currently the only backend supported. A Rust backend is planned, but is not currently
    /// available. If you configure a [`Verifier`](struct.Verifier.html) with
    /// [`Backend::Rust`](config/enum.Backend.html#variant.Rust) it will error</i>
    pub fn configure_backend(&mut self, backend: Backend) -> &mut Verifier {
        self.config.set_backend(backend);
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
    pub fn configure_cpu_pool(&mut self, cpu_pool: CpuPool) -> &mut Verifier {
        self.config.set_cpu_pool(cpu_pool);
        self
    }
    /// Allows you to configure [`Verifier`](struct.Verifier.html) to erase the password bytes
    /// after each call to [`verify`](struct.Verifier.html#method.verify) or
    /// [`verify_non_blocking`](struct.Verifier.html#method.verify_non_blocking).
    /// The default is to clear out the password bytes after each call to these methods
    /// (i.e. `true`).
    pub fn configure_password_clearing(&mut self, boolean: bool) -> &mut Verifier {
        self.config.set_password_clearing(boolean);
        self
    }
    /// Allows you to configure [`Verifier`](struct.Verifier.html) to erase the secret key bytes
    /// after each call to [`verify`](struct.Verifier.html#method.verify) or
    /// [`verify_non_blocking`](struct.Verifier.html#method.verify_non_blocking).
    /// The default is to <b>not</b> clear out the secret key bytes after each call to these
    /// methods (i.e. `false`). This default was chosen to make it easier to use the same
    /// [`Verifier`](struct.Verifier.html) for multiple passwords.
    pub fn configure_secret_key_clearing(&mut self, boolean: bool) -> &mut Verifier {
        self.config.set_secret_key_clearing(boolean);
        self
    }
    /// Allows you to configure [`Verifier`](struct.Verifier.html) to use a custom number of
    /// threads. The default is the number of physical cores on your machine. If you choose
    /// a number of threads that is greater than the lanes configuration of your hash,
    /// [`Verifier`](struct.Verifier.html) will use the minimum of the two.
    pub fn configure_threads(&mut self, threads: u32) -> &mut Verifier {
        self.config.set_threads(threads);
        self
    }
    /// <b><u>The primary method (blocking version)</u></b>
    ///
    /// After you have configured [`Verifier`](struct.Verifier.html) to your liking and provided
    /// it will all the data it needs to verify a password, i.e.
    /// * a string-encoded hash or [`HashRaw`](output/struct.HashRaw.html),
    /// * a [`Password`](data/struct.Password.html),
    /// * a [`SecretKey`](data/struct.SecretKey.html) (if required),
    /// * [`AdditionalData`](data/struct.AdditionalData.html) (if required),
    ///
    /// call this method to verify that the password matches the hash or
    /// [`HashRaw`](output/struct.HashRaw.html)
    pub fn verify(&mut self) -> Result<bool, Error> {
        // ensure password and/or secret_key clearing code will run
        let mut verifier = scopeguard::guard(self, |verifier| {
            if verifier.config.password_clearing() {
                verifier.password = None;
            }
            if verifier.config.secret_key_clearing() {
                verifier.secret_key = None;
            }
        });
        // validate inputs
        verifier.validate()?;

        // calculate is_valid
        let hash_raw = verifier.hash_raw.as_ref().unwrap(); // Safe unwrap because of validation above
        let mut hasher = Hasher::default();
        hasher
            .configure_backend(verifier.config.backend())
            .configure_hash_length(hash_raw.raw_hash_bytes().len() as u32)
            .configure_iterations(hash_raw.iterations())
            .configure_lanes(hash_raw.lanes())
            .configure_memory_size(hash_raw.memory_size())
            .configure_opt_out_of_secret_key(true)
            .configure_password_clearing(verifier.config.password_clearing())
            .configure_secret_key_clearing(verifier.config.secret_key_clearing())
            .configure_threads(verifier.config.threads())
            .configure_variant(hash_raw.variant())
            .configure_version(hash_raw.version())
            .with_salt(hash_raw.raw_salt_bytes());

        if verifier.additional_data.is_some() {
            hasher.with_additional_data(verifier.additional_data().unwrap());
        }
        if verifier.config.password_clearing() {
            // Safe unwrap because of validation above
            let password: Password = verifier.password().unwrap().clone();
            hasher.with_password(password);
        } else {
            // Safe unwrap because of validation above
            let password: &Password = verifier.password().unwrap();
            hasher.with_password(password);
        }
        if verifier.secret_key.is_some() {
            if verifier.config.secret_key_clearing() {
                // Safe unwrap because of is_some above
                let secret_key: SecretKey = verifier.secret_key().unwrap().clone();
                hasher.with_secret_key(secret_key);
            } else {
                // Safe unwrap because of is_some above
                let secret_key: &SecretKey = verifier.secret_key().unwrap();
                hasher.with_secret_key(secret_key);
            }
        }

        let hash_raw2 = hasher.hash_raw()?;
        if hash_raw.raw_hash_bytes() == hash_raw2.raw_hash_bytes() {
            Ok(true)
        } else {
            Ok(false)
        }
    }
    /// <b><u>The primary method (non-blocking version)</u></b>
    ///
    /// Same as [`verify`](struct.Verifier.html#method.verify) except it returns a
    /// [`Future`](https://docs.rs/futures/0.1.21/futures/future/trait.Future.html)
    /// instead of a [`Result`](https://doc.rust-lang.org/std/result/enum.Result.html)
    pub fn verify_non_blocking(&mut self) -> impl Future<Item = bool, Error = Error> {
        let mut verifier = self.clone();
        match self.config.cpu_pool() {
            Some(cpu_pool) => cpu_pool.spawn_fn(move || {
                let is_valid = verifier.verify()?;
                Ok::<_, Error>(is_valid)
            }),
            None => {
                let cpu_pool = default_cpu_pool();
                self.config.set_cpu_pool(cpu_pool.clone());
                cpu_pool.spawn_fn(move || {
                    let is_valid = verifier.verify()?;
                    Ok::<_, Error>(is_valid)
                })
            }
        }
    }
    /// Allows you to provide [`Verifier`](struct.Verifier.html) with the additional data
    /// that was originally used to create the hash. Normally hashes are not created with
    /// additional data; so you are not likely to need this method
    pub fn with_additional_data<AD>(&mut self, additional_data: AD) -> &mut Verifier
    where
        AD: Into<AdditionalData>,
    {
        self.additional_data = Some(additional_data.into());
        self
    }
    /// Allows you to provide [`Verifier`](struct.Verifier.html) with the hash to verify
    /// against (in the form of a string-encoded hash like those produced by the
    /// [`hash`](struct.Hasher.html#method.hash) or
    /// [`hash_non_blocking`](struct.Hasher.html#method.hash_non_blocking)
    /// methods on [`Hasher`](struct.Hasher.html))
    pub fn with_hash(&mut self, hash: &str) -> &mut Verifier {
        self.hash = Some(hash.to_string());
        self.latest = Latest::Hash;
        self
    }
    /// Allows you to provide [`Verifier`](struct.Verifier.html) with the hash to verify
    /// against (in the form of a [`RawHash`](output/struct.HashRaw.html) like those produced
    /// by the [`hash_raw`](struct.Hasher.html#method.hash_raw) or
    /// [`hash_raw_non_blocking`](struct.Hasher.html#method.hash_raw_non_blocking)
    /// methods on [`Hasher`](struct.Hasher.html))
    pub fn with_hash_raw(&mut self, hash_raw: &HashRaw) -> &mut Verifier {
        use backend::encode_rust;
        self.hash_raw = Some(hash_raw.clone());
        self.hash = Some(encode_rust(hash_raw));
        self.latest = Latest::HashRaw;
        self
    }
    /// Allows you to provide [`Verifier`](struct.Verifier.html) with the password
    /// to verify against
    pub fn with_password<P>(&mut self, password: P) -> &mut Verifier
    where
        P: Into<Password>,
    {
        self.password = Some(password.into());
        self
    }
    /// Allows you to provide [`Verifier`](struct.Verifier.html) with the secret key
    /// that was initially used to create the hash
    pub fn with_secret_key<SK>(&mut self, secret_key: SK) -> &mut Verifier
    where
        SK: Into<SecretKey>,
    {
        self.secret_key = Some(secret_key.into());
        self
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s
    /// [`AdditionalData`](data/struct.AdditionalData.html), if any
    pub fn additional_data(&self) -> Option<&AdditionalData> {
        self.additional_data.as_ref()
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s
    /// [`VerifierConfig`](config/struct.VerifierConfig.html)
    pub fn config(&self) -> &VerifierConfig {
        &self.config
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s hash, if any
    pub fn hash(&mut self) -> Option<&str> {
        use backend::encode_rust;
        match self.latest {
            Latest::Hash => self.hash.as_ref().map(|s| s.as_ref()),
            Latest::HashRaw => match self.hash_raw {
                Some(ref hash_raw) => {
                    self.hash = Some(encode_rust(hash_raw));
                    self.hash.as_ref().map(|s| s.as_ref())
                }
                None => None,
            },
        }
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s HashRaw, if any.
    /// This method will return None if you never stored a hash or HashRaw in the
    /// [`Verifier`](struct.Verifier.html). It will also return None if you stored a
    /// hash in [`Verifier`](struct.Verifier.html) that was invalid (i.e. a hash that could
    /// not be decoded into a HashRaw)
    pub fn hash_raw(&mut self) -> Option<&HashRaw> {
        match self.latest {
            Latest::Hash => match self.hash {
                None => None,
                Some(ref hash) => {
                    let hash_raw = match hash.parse::<HashRaw>() {
                        Ok(hash_raw) => hash_raw,
                        Err(_) => return None,
                    };
                    self.hash_raw = Some(hash_raw);
                    self.hash_raw.as_ref()
                }
            },
            Latest::HashRaw => self.hash_raw.as_ref(),
        }
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s
    /// [`Password`](data/struct.Password.html), if any
    pub fn password(&self) -> Option<&Password> {
        self.password.as_ref()
    }
    /// Read-only access to the [`Verifier`](struct.Verifier.html)'s
    /// [`SecretKey`](data/struct.SecretKey.html), if any
    pub fn secret_key(&self) -> Option<&SecretKey> {
        self.secret_key.as_ref()
    }
}

impl Verifier {
    pub(crate) fn validate(&mut self) -> Result<(), Error> {
        match self.latest {
            Latest::Hash => match self.hash {
                Some(ref hash) => {
                    let hash_raw = hash.parse::<HashRaw>()?;
                    self.hash_raw = Some(hash_raw);
                }
                None => return Err(ErrorKind::DataError(DataError::HashMissingError).into()),
            },
            Latest::HashRaw => {
                if self.hash_raw.is_none() {
                    return Err(ErrorKind::DataError(DataError::HashMissingError).into());
                }
            }
        }
        if self.password.is_none() {
            return Err(ErrorKind::DataError(DataError::PasswordMissingError).into());
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum Latest {
    Hash,
    HashRaw,
}

impl Default for Latest {
    fn default() -> Latest {
        Latest::Hash
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
