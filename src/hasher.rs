use scopeguard;

use backend::{encode_rust, hash_raw_c};
use config::{Backend, HasherConfig, Variant, Version};
use data::{AdditionalData, DataPrivate, Password, Salt, SecretKey};
use error::{Error, ErrorKind};
use ffi;
use output::HashRaw;

impl Default for Hasher {
    /// Same as the [`new`](struct.Hasher.html#method.new) method
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

/// <b><u>One of the two main structs.</u></b> Use it to turn passwords into hashes that are safe to store in a database
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Hasher {
    additional_data: AdditionalData,
    config: HasherConfig,
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    password: Password,
    salt: Salt,
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    secret_key: SecretKey,
}

impl Hasher {
    /// Creates a new [`Hasher`](struct.Hasher.html) with sensible default configuration options for an early-2014 MacBook Air.
    /// <b>Note: If you are using this library to hash user passwords for storage in a database,
    /// it is recommended that you adjust these settings for your machine
    /// (primarily `iterations`, and `memory_size`) until the time it takes to hash a password
    /// is approximately 500 milliseconds</b>. There is a script in the examples directory that
    /// will show you the various configuration options for your
    /// machine that produce hashing times between 375 and 625 milliseconds (Don't forget to run
    /// it with the `--release` flag). Alternatively, you can clone the repository and run the
    /// benchmark suite with `cargo bench -- bench_inputs`, which takes longer but runs many
    /// iterations for each configuration scenario; so it provides information about distributions
    /// of running time (e.g. mean, 95% confidence intervals, etc.) as opposed to just point estimates.
    ///
    /// Here are the default configuration options:
    /// * `backend`: [`Backend::C`](config/enum.Backend.html#variant.C)
    /// * `hash_length`: `32` bytes
    /// * `iterations`: `128`
    /// * `lanes`: the number of physical cores on your machine
    /// * `memory_size`: `4096` kibibytes
    /// * `opt_out_of_random_salt`: `false`
    /// * `opt_out_of_secret_key`: `false`
    /// * `password_clearing`: `true`
    /// * `salt`: random [`Salt`](data/struct.Salt.html) of length 32 bytes that renews with every call to [`hash`](struct.Hasher.html#method.hash) or [`hash_raw`](struct.Hasher.html#method.hash_raw)
    /// * `secret_key_clearing`: `false`
    /// * `threads`: the number of physical cores on your machine
    /// * `variant`: [`Variant::Argon2id`](config/enum.Variant.html#variant.Argon2id)
    /// * `version`: [`Version::_0x13`](config/enum.Verion.html#variant._0x13)
    pub fn new() -> Hasher {
        Hasher::default()
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom backend implementation. The default
    /// is [`Backend::C`](config/enum.Backend.html#variant.C). <i>Note: Currently the only backend implementation supported is </i> [`Backend::C`](config/enum.Backend.html#variant.C) <i>.
    /// A Rust backend is planned, but is not currently available. If you configure</i>
    /// [`Hasher`](struct.Hasher.html) <i>with</i> [`Backend::Rust`](config/enum.Backend.html#variant.Rust)<i>, it will panic at runtime</i>
    pub fn configure_backend(&mut self, backend: Backend) -> &mut Hasher {
        self.config.set_backend(backend);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom hash length (in bytes). The default is `32`.
    pub fn configure_hash_length(&mut self, hash_length: u32) -> &mut Hasher {
        self.config.set_hash_length(hash_length);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom number of iterations. The default is `128`.
    pub fn configure_iterations(&mut self, iterations: u32) -> &mut Hasher {
        self.config.set_iterations(iterations);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom number of lanes. The default is
    /// the number of phycial cores on your machine.
    pub fn configure_lanes(&mut self, lanes: u32) -> &mut Hasher {
        self.config.set_lanes(lanes);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom memory size (in kibibytes). The default is `4096`.
    pub fn configure_memory_size(&mut self, memory_size: u32) -> &mut Hasher {
        self.config.set_memory_size(memory_size);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to erase the password bytes after each call to [`hash`](struct.Hasher.html#method.hash)
    /// or [`hash_raw`](struct.Hasher.html#method.hash_raw). The default is to clear out the password bytes (i.e. `true`).
    pub fn configure_password_clearing(&mut self, boolean: bool) -> &mut Hasher {
        self.config.set_password_clearing(boolean);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to erase the secret key bytes after each call to [`hash`](struct.Hasher.html#method.hash)
    /// or [`hash_raw`](struct.Hasher.html#method.hash_raw). The default is to <b>not</b> clear out the secret key bytes (i.e. `false`).
    /// This default was chosen to make it easier to keep using the same [`Hasher`](struct.Hasher.html) for multiple passwords.
    pub fn configure_secret_key_clearing(&mut self, boolean: bool) -> &mut Hasher {
        self.config.set_secret_key_clearing(boolean);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom number of threads. The default is
    /// the number of phycial cores on your machine. If you choose a number of threads
    /// that is greater than the lanes configuration, [`Hasher`](struct.Hasher.html) will use the minimum of the two.
    pub fn configure_threads(&mut self, threads: u32) -> &mut Hasher {
        self.config.set_threads(threads);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom Argon2 variant. The default is [`Variant::Argon2id`](config/enum.Variant.html#variant.Argon2id).
    /// Do <b>not</b> use a different variant unless you have a specific reason to.
    pub fn configure_variant(&mut self, variant: Variant) -> &mut Hasher {
        self.config.set_variant(variant);
        self
    }
    /// Allows you to configure [`Hasher`](struct.Hasher.html) to use a custom Argon2 version. The default and latest
    /// (as of 5/18) is [`Version::_0x13`](config/enum.Version.html#variant._0x13). Do <b>not</b> use a different version unless you have a
    /// specific reason to.
    pub fn configure_version(&mut self, version: Version) -> &mut Hasher {
        self.config.set_version(version);
        self
    }
    /// <b>The primary method.</b> After you have configured [`Hasher`](struct.Hasher.html) to your liking and provided
    /// it will all the data you would like it to hash (e.g. a [`Password`](data/struct.Password.html) and a [`SecretKey`](data/struct.SecretKey.html)), call
    /// this method in order to produce an encoded `String` representing the hash, which is
    /// safe to store in a database and against which you can verify raw passwords later
    pub fn hash(&mut self) -> Result<String, Error> {
        let hash_raw = self.hash_raw()?;
        let hash = encode_rust(&hash_raw);
        Ok(hash)
    }
    /// Like the [`hash`](struct.Hasher.html#method.hash) method, but instead of producing an encoded `String` representing the hash,
    /// produces a [`HashRaw`](output/struct.HashRaw.html) struct that contains all the component parts of the string-encoded
    /// version, including the raw hash bytes and the raw salt bytes. In general, you should
    /// prefer to use the [`hash`](struct.Hasher.html#method.hash) method instead of this method
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
            Backend::Rust => return Err(ErrorKind::BackendUnsupportedError.into()),
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
    /// Allows you to provide [`Hasher`](struct.Hasher.html) with some additional data to hash alongside
    /// the [`Password`](data/struct.Password.html), [`Salt`](data/struct.Salt.html), and (optionally) [`SecretKey`](data/struct.SecretKey.html). [`AdditionalData`](data/struct.AdditionalData.html) is not
    /// required and most people will not need to use this method. [`AdditionalData`](data/struct.AdditionalData.html) is like
    /// [`SecretKey`](data/struct.SecretKey.html) in that it is not stored in the actual hash and will be required to be
    /// provided later in order to verify passwords against the hash.  Again, hashing with
    /// additional data is not common and you probably won't need to use this
    pub fn with_additional_data<AD>(&mut self, additional_data: AD) -> &mut Hasher
    where
        AD: Into<AdditionalData>,
    {
        self.additional_data = additional_data.into();
        self
    }
    /// Provides [`Hasher`](struct.Hasher.html) with the password you would like to hash. [`Hasher`](struct.Hasher.html) must be provided
    /// with a [`Password`](data/struct.Password.html) for the [`hash`](struct.Hasher.html#method.hash) and [`hash_raw`](struct.Hasher.html#method.hash_raw) methods to work
    pub fn with_password<P>(&mut self, password: P) -> &mut Hasher
    where
        P: Into<Password>,
    {
        self.password = password.into();
        self
    }
    /// Allows you to provide [`Hasher`](struct.Hasher.html) with a custom [`Salt`](data/struct.Salt.html) to include in the hash. The default
    /// [`Hasher`](struct.Hasher.html) is configured to use a random [`Salt`](data/struct.Salt.html) of 32 bytes; so there is no need
    /// to call this method. If you would like to use a random [`Salt`](data/struct.Salt.html) of different length,
    /// you can call this method with `Salt::random(your_custom_length_in_bytes)`. Using a deterministic
    /// [`Salt`](data/struct.Salt.html) is possible, but discouraged. If you choose to use a deterministic [`Salt`](data/struct.Salt.html), you
    /// will have to explicitly opt out of using a random salt with the [`opt_out_of_random_salt`](struct.Hasher.html#method.opt_out_of_random_salt)
    /// method
    pub fn with_salt<S>(&mut self, salt: S) -> &mut Hasher
    where
        S: Into<Salt>,
    {
        self.salt = salt.into();
        self
    }
    /// Provides [`Hasher`](struct.Hasher.html) with a secret key that will be used to create the hash.
    /// The secret key will not be included in the hash output.  You must save it somewhere
    /// (ideally outside your code) to use later, as the only way to verify passwords against
    /// the hash later is to know the secret key. This library encourages you to use a
    /// secret key; so if you do not provide one, you will have to explicitly opt out of
    /// using a secret key with the [`opt_out_of_secret_key`](struct.Hasher.html#method.opt_out_of_secret_key) method
    pub fn with_secret_key<SK>(&mut self, secret_key: SK) -> &mut Hasher
    where
        SK: Into<SecretKey>,
    {
        self.secret_key = secret_key.into();
        self
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s [`AdditionalData`](data/struct.AdditionalData.html). If you never provided [`AdditionalData`](data/struct.AdditionalData.html),
    /// this will return a reference to an empty [`AdditionalData`](data/struct.AdditionalData.html) (i.e. one whose underlying
    /// vector of bytes has zero length)
    pub fn additional_data(&self) -> &AdditionalData {
        &self.additional_data
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s [`HasherConfig`](config/struct.HasherConfig.html)
    pub fn config(&self) -> &HasherConfig {
        &self.config
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s [`Password`](data/struct.Password.html). If you never provided a [`Password`](data/struct.Password.html),
    /// this will return a reference to an empty [`Password`](data/struct.Password.html) (i.e. one whose underlying
    /// vector of bytes has zero length)
    pub fn password(&self) -> &Password {
        &self.password
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s [`Salt`](data/struct.Salt.html)
    pub fn salt(&self) -> &Salt {
        &self.salt
    }
    /// Read-only access to the [`Hasher`](struct.Hasher.html)'s [`SecretKey`](data/struct.SecretKey.html). If you never provided a [`SecretKey`](data/struct.SecretKey.html),
    /// this will return a reference to an empty [`SecretKey`](data/struct.SecretKey.html) (i.e. one whose underlying
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
                .opt_out_of_random_salt()
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
    #[should_panic]
    fn test_config_hash_length_too_short() {
        let mut hasher = Hasher::default();
        hasher.configure_hash_length(3).with_secret_key("secret");
        let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_config_memory_not_power_of_two() {
        let mut hasher = Hasher::default();
        hasher.configure_memory_size(9).with_secret_key("secret");
        let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_config_memory_too_short() {
        let mut hasher = Hasher::default();
        hasher.configure_memory_size(4).with_secret_key("secret");
        let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_config_no_opt_of_random_salt() {
        let mut hasher = Hasher::default();
        hasher.with_secret_key("secret").with_salt("somesalt");
        let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_config_no_opt_of_secret_key() {
        let mut hasher = Hasher::default();
        let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
    }

    #[test]
    fn test_config_opt_of_secret_key() {
        let mut hasher = Hasher::default();
        hasher.opt_out_of_secret_key();
        let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
    }

    #[test]
    fn test_config_opt_of_random_salt() {
        let mut hasher = Hasher::default();
        hasher
            .with_secret_key("secret")
            .with_salt("somesalt")
            .opt_out_of_random_salt();
        let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_data_password_is_empty() {
        let mut hasher = Hasher::default();
        hasher.with_secret_key("secret");
        let _ = hasher.with_password("").hash().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_data_salt_too_short() {
        let mut hasher = Hasher::default();
        hasher
            .with_secret_key("secret")
            .with_salt("1234567")
            .opt_out_of_random_salt();
        let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
    }

    #[test]
    fn test_random() {
        use rand::{RngCore, SeedableRng, StdRng};
        let mut seed = [0u8; 32];
        seed[0] = 1;
        seed[1] = 2;
        seed[2] = 3;
        seed[3] = 4;
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut password = vec![0u8; 12];
        for _ in 0..1_000 {
            rng.fill_bytes(&mut password);
            let mut hasher = Hasher::default();
            hasher
                .configure_hash_length(8)
                .configure_iterations(1)
                .configure_memory_size(32)
                .configure_threads(1)
                .configure_lanes(1)
                .with_secret_key("somesecret")
                .with_password(&password[..])
                .hash()
                .unwrap();
        }
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
}
