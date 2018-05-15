use scopeguard;

use backend::{encode_rust, hash_raw_c, hash_raw_rust};
use config::{Backend, HasherConfig, Variant, Version};
use data::{AdditionalData, Password, DataPrivate, Salt, SecretKey};
use error::Error;
use ffi;
use output::HashRaw;

impl Default for Hasher {
    /// Same as the `new` method
    fn default() -> Hasher {
        Hasher {
            additional_data: AdditionalData::none(),
            config: HasherConfig::default(),
            password: Password::none(),
            salt: Salt::default(),
            secret_key: SecretKey::none(),
        }
    }
}

/// One of the two main structs. Use it to turn passwords into hashes that are safe to store in a database
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hasher {
    additional_data: AdditionalData,
    config: HasherConfig,
    #[serde(skip_serializing)]
    password: Password,
    salt: Salt,
    #[serde(skip_serializing)]
    secret_key: SecretKey,
}

impl Hasher {
    /// Creates a new `Hasher` with sensible default configuration options for an early-2014 MacBook Air.
    /// <b>Note: If you are using this library to hash user passwords for storage in a database,
    /// it is recommended that you adjust these settings for your machine
    /// (primarily `iterations`, `memory_size`, `lanes` and/or `threads`) until the time
    /// it takes to hash a password is approximately 500 milliseconds</b>. There is a script
    /// in the examples directory that will show you the various configuration options for your
    /// machine that produce hashing times between 375 and 625 milliseconds (Don't forget to run
    /// it with the `--release` flag).
    ///
    /// Here are the default configuration options:
    /// * `backend`: `Backend::C`
    /// * `hash_length`: 32 bytes
    /// * `iterations`: 128
    /// * `lanes`: the number of physical cores on your machine
    /// * `memory_size`: 4096 kibibytes
    /// * `opt_out_of_random_salt`: false
    /// * `opt_out_of_secret_key`: false
    /// * `password_clearing`: true
    /// * `salt`: random `Salt` of length 32 bytes that renews with every call to `hash` or `hash_raw`
    /// * `secret_key_clearing`: false
    /// * `threads`: the number of physical cores on your machine
    /// * `variant`: `Variant::Argon2id`
    /// * `version`: `Version::_0x13`
    pub fn new() -> Hasher {
        Hasher::default()
    }
    /// Allows you to configure `Hasher` to use a custom backend implementation. The default
    /// is `Backend::C`. <i>Note: Currently the only backend implementation supported is </i> `Backend::C` <i>.
    /// A Rust backend is planned, but is not currently available. If you configure</i>
    /// `Hasher` <i>with</i> `Backend::Rust`<i>, it will panic at runtime</i>
    pub fn configure_backend(&mut self, backend: Backend) -> &mut Hasher {
        self.config.set_backend(backend);
        self
    }
    /// Allows you to configure `Hasher` to use a custom hash length (in bytes). The default is 32.
    pub fn configure_hash_length(&mut self, hash_length: u32) -> &mut Hasher {
        self.config.set_hash_length(hash_length);
        self
    }
    /// Allows you to configure `Hasher` to use a custom number of iterations. The default is 128.
    pub fn configure_iterations(&mut self, iterations: u32) -> &mut Hasher {
        self.config.set_iterations(iterations);
        self
    }
    /// Allows you to configure `Hasher` to use a custom number of lanes. The default is
    /// the number of phycial cores on your machine.
    pub fn configure_lanes(&mut self, lanes: u32) -> &mut Hasher {
        self.config.set_lanes(lanes);
        self
    }
    /// Allows you to configure `Hasher` to use a custom memory size (in kibibytes). The default is 4096.
    pub fn configure_memory_size(&mut self, memory_size: u32) -> &mut Hasher {
        self.config.set_memory_size(memory_size);
        self
    }
    /// Allows you to configure `Hasher` to erase the password bytes after each call to `hash`
    /// or `hash_raw`. The default is to clear out the password bytes (i.e. `true`).
    pub fn configure_password_clearing(&mut self, boolean: bool) -> &mut Hasher {
        self.config.set_password_clearing(boolean);
        self
    }
    /// Allows you to configure `Hasher` to erase the secret key bytes after each call to `hash`
    /// or `hash_raw`. The default is to <b>not</b> clear out the secret key bytes (i.e. `false`).
    /// This default was chosen to make it easier to keep using the same `Hasher` for multiple passwords.
    pub fn configure_secret_key_clearing(&mut self, boolean: bool) -> &mut Hasher {
        self.config.set_secret_key_clearing(boolean);
        self
    }
    /// Allows you to configure `Hasher` to use a custom number of threads. The default is
    /// the number of phycial cores on your machine. If you choose a number of threads
    /// that is greater than the lanes configuration, `Hasher` will use the minimum of the two.
    pub fn configure_threads(&mut self, threads: u32) -> &mut Hasher {
        self.config.set_threads(threads);
        self
    }
    /// Allows you to configure `Hasher` to use a custom Argon2 variant. The default is `Variant::Argon2id`.
    /// Do <b>not</b> use a different variant unless you have a specific reason to.
    pub fn configure_variant(&mut self, variant: Variant) -> &mut Hasher {
        self.config.set_variant(variant);
        self
    }
    /// Allows you to configure `Hasher` to use a custom Argon2 version. The default and latest
    /// (as of 5/18) is `Version::_0x13`. Do <b>not</b> use a different version unless you have a
    /// specific reason to.
    pub fn configure_version(&mut self, version: Version) -> &mut Hasher {
        self.config.set_version(version);
        self
    }
    /// <b>The primary method.</b> After you have configured `Hasher` to your liking and provided
    /// it will all the data you would like it to hash (e.g. a `Password` and a `SecretKey`), call
    /// this method in order to produce an encoded `String` representing the hash, which is
    /// safe to store in a database and against which you can verify raw passwords later
    pub fn hash(&mut self) -> Result<String, Error> {
        let hash_raw = self.hash_raw()?;
        let hash = encode_rust(&hash_raw);
        Ok(hash)
    }
    /// Like the `hash` method, but instead of producing an encoded `String` representing the hash,
    /// produces a `HashRaw` struct that contains all the component parts of the string-encoded
    /// version, including the raw hash bytes and the raw salt bytes. In general, you should
    /// prefer to use the `hash` method instead of this method
    pub fn hash_raw(&mut self) -> Result<HashRaw, Error> {
        // ensure password and/or secret_key clearing code will run
        let mut hasher = scopeguard::guard(self, |hasher| {
            if hasher.config().password_clearing() {
                hasher.set_password(Password::none());
            }
            if hasher.config().secret_key_clearing() {
                hasher.set_secret_key(SecretKey::none());
            }
        });

        // reset salt if it is random
        if hasher.salt().is_random() {
            let len = hasher.salt().len();
            hasher.set_salt(Salt::random(len)?);
        }

        // validate inputs
        hasher.validate()?;

        // calculate hash_raw
        let hash_raw = match hasher.config().backend() {
            Backend::C => hash_raw_c(&mut hasher)?,
            Backend::Rust => hash_raw_rust(&mut hasher)?,
        };

        Ok(hash_raw)
    }
    /// For safety reasons, if you would like to produce a hash that does not include a random
    /// salt, you must explicitly opt out of using a random salt with this method. It is
    /// not recommended that you do this
    pub fn opt_out_of_random_salt(&mut self) -> &mut Hasher {
        self.config.set_opt_out_of_random_salt(true);
        self
    }
    /// For safety reasons, if you would like to produce a hash that does not include a secret
    /// key, you must explicitly opt out of using a secret key. It is not recommended that you
    /// do this
    pub fn opt_out_of_secret_key(&mut self) -> &mut Hasher {
        self.config.set_opt_out_of_secret_key(true);
        self
    }
    /// Allows you to provide `Hasher` with some additional data to hash alongside
    /// the `Password`, `Salt`, and (optionally) `SecretKey`. `AdditionalData` is not
    /// required and most people will not need to use this method. `AdditionalData` is like
    /// `SecretKey` in that it is not stored in the actual hash and will be required to be
    /// provided later in order to verify passwords against the hash.  Again, hashing with
    /// additional data is not common and you probably won't need to use this
    pub fn with_additional_data<AD>(&mut self, additional_data: AD) -> &mut Hasher
    where
        AD: Into<AdditionalData>,
    {
        self.additional_data = additional_data.into();
        self
    }
    /// Provides `Hasher` with the password you would like to hash. `Hasher` must be provided
    /// with a `Password` for the `hash` and `hash_raw` methods to work
    pub fn with_password<P>(&mut self, password: P) -> &mut Hasher
    where
        P: Into<Password>,
    {
        self.password = password.into();
        self
    }
    /// Allows you to provide `Hasher` with a custom `Salt` to include in the hash. The default
    /// `Hasher` is configured to use a random `Salt` of 32 bytes; so there is no need
    /// to call this method. If you would like to use a random `Salt` of different length,
    /// you can call this method with `Salt::random(your_custom_length_in_bytes)`. Using a deterministic
    /// `Salt` is possible, but discouraged. If you choose to use a deterministic `Salt`, you
    /// will have to explicitly opt out of using a random salt with the `opt_out_of_random_salt`
    /// method
    pub fn with_salt<S>(&mut self, salt: S) -> &mut Hasher
    where
        S: Into<Salt>,
    {
        self.salt = salt.into();
        self
    }
    /// Provides `Hasher` with a secret key that will be used to create the hash.
    /// The secret key will not be included in the hash output.  You must save it somewhere
    /// (ideally outside your code) to use later, as the only way to verify passwords against
    /// the hash later is to know the secret key. This library encourages you to use a
    /// secret key; so if you do not provide one, you will have to explicitly opt out of
    /// using a secret key with the `opt_out_of_secret_key` method
    pub fn with_secret_key<SK>(&mut self, secret_key: SK) -> &mut Hasher
    where
        SK: Into<SecretKey>,
    {
        self.secret_key = secret_key.into();
        self
    }
    /// Read-only access to the `Hasher`'s `AdditionalData`. If you never provided `AdditionalData`,
    /// this will return a reference to an empty `AdditionalData` (i.e. one whose underlying
    /// vector of bytes has zero length)
    pub fn additional_data(&self) -> &AdditionalData {
        &self.additional_data
    }
    /// Read-only access to the `Hasher`'s `HasherConfig`
    pub fn config(&self) -> &HasherConfig {
        &self.config
    }
    /// Read-only access to the `Hasher`'s `Password`. If you never provided a `Password`,
    /// this will return a reference to an empty `Password` (i.e. one whose underlying
    /// vector of bytes has zero length)
    pub fn password(&self) -> &Password {
        &self.password
    }
    /// Read-only access to the `Hasher`'s `Salt`
    pub fn salt(&self) -> &Salt {
        &self.salt
    }
    /// Read-only access to the `Hasher`'s `SecretKey`. If you never provided a `SecretKey`,
    /// this will return a reference to an empty `SecretKey` (i.e. one whose underlying
    /// vector of bytes has zero length)
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

impl Hasher {
    pub(crate) fn context(&mut self, buffer: &mut [u8]) -> ffi::Argon2_Context {
        ffi::Argon2_Context {
            out: buffer.as_mut_ptr(),
            outlen: buffer.len() as u32,
            pwd: self.password.as_mut_ptr(),
            pwdlen: self.password.len(),
            salt: self.salt.as_mut_ptr(),
            saltlen: self.salt.len(),
            secret: self.secret_key.as_mut_ptr(),
            secretlen: self.secret_key.len(),
            ad: self.additional_data.as_mut_ptr(),
            adlen: self.additional_data.len(),
            t_cost: self.config.iterations(),
            m_cost: self.config.memory_size(),
            lanes: self.config.lanes(),
            threads: self.config.threads(),
            version: self.config.version() as u32,
            allocate_cbk: None,
            free_cbk: None,
            flags: self.config.flags().bits(),
        }
    }
    pub(crate) fn set_password<P>(&mut self, password: P)
    where
        P: Into<Password>,
    {
        self.password = password.into();
    }
    pub(crate) fn set_salt<S>(&mut self, salt: S)
    where
        S: Into<Salt>,
    {
        self.salt = salt.into();
    }
    pub(crate) fn set_secret_key<SK>(&mut self, secret_key: SK)
    where
        SK: Into<SecretKey>,
    {
        self.secret_key = secret_key.into();
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.config.validate()?;
        self.additional_data.validate(None)?;
        self.password.validate(None)?;
        self.salt
            .validate(Some(self.config.opt_out_of_random_salt()))?;
        self.secret_key
            .validate(Some(self.config.opt_out_of_secret_key()))?;
        Ok(())
    }
}
