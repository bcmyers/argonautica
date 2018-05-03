use std::ffi::CStr;
use std::os::raw::c_char;

use failure;
use scopeguard;

use config::config::Config;
use config::variant::Variant;
use config::version::Version;
use data::additional_data::AdditionalData;
use data::password::Password;
use data::read::ReadPrivate;
use data::salt::Salt;
use data::secret_key::SecretKey;
use ffi;

/// The main struct / the big kahuna / the head honcho / the big cheese / where all the magic happens 😊
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Hasher {
    config: Config,

    additional_data: AdditionalData,
    password: Password,
    salt: Salt,
    secret_key: SecretKey,
}

impl Hasher {
    //! `Hasher` contains a lot of methods; here's a run down of how they are organized / named:
    //! * Constructors
    //!     * `default`: Constructor with sensible Argon2 configuration options and random salt
    //!     * `new`: Constructor that allows you to pass in a custom `Config` instead using the default configuration options
    //! * Setters
    //!     * `configure_*`: Setters for setting Argon2 configuration options
    //!     * `opt_out_of_*`: Methods for allowing you to explicitly opt out of safety features (if you really really have to 😊)
    //!     * `set_*`: Setters for setting data you would like to hash, i.e. `Password`, `Salt`, `SecretKey`, `AdditionalData`
    //! * Methods that actually do the work!
    //!     * `hash_*`
    //! * Methods for reading configuration options and/or data that was hashed
    //!     * Any method not already mentioned above
    pub fn default() -> Result<Hasher, failure::Error> {
        Ok(Hasher {
            config: Config::default(),

            additional_data: AdditionalData::none(),
            password: Password::none(),
            salt: Salt::default()?,
            secret_key: SecretKey::none(),
        })
    }
    pub fn configure_hash_length(&mut self, hash_length: u32) -> &mut Hasher {
        self.config.set_hash_length(hash_length);
        self
    }
    pub fn configure_iterations(&mut self, iterations: u32) -> &mut Hasher {
        self.config.set_iterations(iterations);
        self
    }
    pub fn configure_lanes(&mut self, lanes: u32) -> &mut Hasher {
        self.config.set_lanes(lanes);
        self
    }
    pub fn configure_memory_size(&mut self, memory_size: u32) -> &mut Hasher {
        self.config.set_memory_size(memory_size);
        self
    }
    pub fn configure_password_clearing(&mut self, boolean: bool) -> &mut Hasher {
        self.config.set_password_clearing(boolean);
        self
    }
    pub fn configure_secret_key_clearing(&mut self, boolean: bool) -> &mut Hasher {
        self.config.set_secret_key_clearing(boolean);
        self
    }
    pub fn configure_threads(&mut self, threads: u32) -> &mut Hasher {
        self.config.set_threads(threads);
        self
    }
    pub fn configure_variant(&mut self, variant: Variant) -> &mut Hasher {
        self.config.set_variant(variant);
        self
    }
    pub fn configure_version(&mut self, version: Version) -> &mut Hasher {
        self.config.set_version(version);
        self
    }
    pub fn hash(&mut self) -> Result<String, failure::Error> {
        let mut buffer = vec![0u8; self.config.hash_length() as usize];
        let mut context = self._hash_raw(&mut buffer)?;
        let encoded = self._encode(&mut context)?;
        Ok(encoded)
    }
    pub fn hash_raw(&mut self) -> Result<Vec<u8>, failure::Error> {
        let mut buffer = vec![0u8; self.config.hash_length() as usize];
        let _ = self._hash_raw(&mut buffer)?;
        Ok(buffer)
    }
    pub fn opt_out_of_random_salt(&mut self) -> &mut Hasher {
        self.config.set_opt_out_of_random_salt(true);
        self
    }
    pub fn opt_out_of_secret_key(&mut self) -> &mut Hasher {
        self.config.set_opt_out_of_secret_key(true);
        self
    }
    pub fn with_additional_data<T: Into<AdditionalData>>(
        &mut self,
        additional_data: T,
    ) -> &mut Hasher {
        self.additional_data = additional_data.into();
        self
    }
    pub fn with_password<T: Into<Password>>(&mut self, password: T) -> &mut Hasher {
        self.password = password.into();
        self
    }
    pub fn with_salt<T: Into<Salt>>(&mut self, salt: T) -> &mut Hasher {
        self.salt = salt.into();
        self
    }
    pub fn with_secret_key<T: Into<SecretKey>>(&mut self, secret_key: T) -> &mut Hasher {
        self.secret_key = secret_key.into();
        self
    }
    pub fn additional_data(&self) -> &AdditionalData {
        &self.additional_data
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn password(&self) -> &Password {
        &self.password
    }
    pub fn salt(&self) -> &Salt {
        &self.salt
    }
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    fn _encode(&self, context: &mut ffi::argon2_context) -> Result<String, failure::Error> {
        let buffer_len = unsafe {
            ffi::argon2_encodedlen(
                self.config.iterations(),
                self.config.memory_size(),
                self.config.threads(),
                self.salt.len(),
                self.config.hash_length(),
                self.config.variant() as ffi::argon2_type,
            )
        };
        let mut buffer = vec![0 as c_char; buffer_len];
        let buffer_ptr = buffer.as_mut_ptr();

        let context_ptr = context as *mut ffi::argon2_context;
        let type_ = self.config.variant() as ffi::argon2_type;

        let err = unsafe { ffi::encode_string(buffer_ptr, buffer_len, context_ptr, type_) };
        if err != 0 {
            bail!("TODO");
        }

        let c_str: &CStr = unsafe { CStr::from_ptr(buffer_ptr) };
        let s = c_str.to_str().unwrap().to_string();
        Ok(s)
    }
    fn _hash_raw(&mut self, buffer: &mut [u8]) -> Result<ffi::Argon2_Context, failure::Error> {
        let mut instance = scopeguard::guard(self, |instance| {
            if instance.config.password_clearing() {
                instance.password = Password::none();
            }
            if instance.config.secret_key_clearing() {
                instance.secret_key = SecretKey::none();
            }
        });
        instance._validate()?;
        let mut context = ffi::Argon2_Context {
            out: buffer.as_mut_ptr(),
            outlen: buffer.len() as u32,
            pwd: instance.password.as_mut_ptr(),
            pwdlen: instance.password.len(),
            salt: instance.salt.as_mut_ptr(),
            saltlen: instance.salt.len(),
            secret: instance.secret_key.as_mut_ptr(),
            secretlen: instance.secret_key.len(),
            ad: instance.additional_data.as_mut_ptr(),
            adlen: instance.additional_data.len(),
            t_cost: instance.config.iterations(),
            m_cost: instance.config.memory_size(),
            lanes: instance.config.lanes(),
            threads: instance.config.threads(),
            version: instance.config.version() as u32,
            allocate_cbk: None,
            free_cbk: None,
            flags: instance.config.flags().bits(),
        };
        let context_ptr = &mut context as *mut ffi::Argon2_Context;
        let err = unsafe { ffi::argon2_ctx(context_ptr, instance.config.variant() as u32) };
        if instance.salt.is_random() {
            instance.salt = Salt::random(instance.salt.len())?;
        }
        check_error(err)?;
        Ok(context)
    }
    fn _validate(&self) -> Result<(), failure::Error> {
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

#[cfg_attr(rustfmt, rustfmt_skip)]
fn check_error(err: i32) -> Result<(), failure::Error> {
    match err {
        ffi::Argon2_ErrorCodes_ARGON2_OK => (),
        ffi::Argon2_ErrorCodes_ARGON2_OUTPUT_PTR_NULL => bail!("TODO: Argon2 error: OUTPUT_PTR_NULL"),
        ffi::Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_SHORT => bail!("TODO: Argon2 error: OUTPUT_TOO_SHORT"),
        ffi::Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_LONG => bail!("TODO: Argon2 error: OUTPUT_TOO_LONG"),
        ffi::Argon2_ErrorCodes_ARGON2_PWD_TOO_SHORT => bail!("TODO: Argon2 error: PWD_TOO_SHORT"),
        ffi::Argon2_ErrorCodes_ARGON2_PWD_TOO_LONG => bail!("TODO: Argon2 error: PWD_TOO_LONG"),
        ffi::Argon2_ErrorCodes_ARGON2_SALT_TOO_SHORT => bail!("TODO: Argon2 error: SALT_TOO_SHORT"),
        ffi::Argon2_ErrorCodes_ARGON2_SALT_TOO_LONG => bail!("TODO: Argon2 error: SALT_TOO_LONG"),
        ffi::Argon2_ErrorCodes_ARGON2_AD_TOO_SHORT => bail!("TODO: Argon2 error: AD_TOO_SHORT"),
        ffi::Argon2_ErrorCodes_ARGON2_AD_TOO_LONG => bail!("TODO: Argon2 error: AD_TOO_LONG"),
        ffi::Argon2_ErrorCodes_ARGON2_SECRET_TOO_SHORT => bail!("TODO: Argon2 error: SECRET_TOO_LONG"),
        ffi::Argon2_ErrorCodes_ARGON2_SECRET_TOO_LONG => bail!("TODO: Argon2 error: SECRET_TOO_LONG"),
        ffi::Argon2_ErrorCodes_ARGON2_TIME_TOO_SMALL => bail!("TODO: Argon2 error: TIME_TOO_SMALL"),
        ffi::Argon2_ErrorCodes_ARGON2_TIME_TOO_LARGE => bail!("TODO: Argon2 error: TIME_TOO_LARGE"),
        ffi::Argon2_ErrorCodes_ARGON2_MEMORY_TOO_LITTLE => bail!("TODO: Argon2 error: MEMORY_TOO_LITTLE"),
        ffi::Argon2_ErrorCodes_ARGON2_MEMORY_TOO_MUCH => bail!("TODO: Argon2 error: MEMORY_TOO_MUCH"),
        ffi::Argon2_ErrorCodes_ARGON2_LANES_TOO_FEW => bail!("TODO: Argon2 error: LANES_TOO_FEW"),
        ffi::Argon2_ErrorCodes_ARGON2_LANES_TOO_MANY => bail!("TODO: Argon2 error: LANES_TOO_MANY"),
        ffi::Argon2_ErrorCodes_ARGON2_PWD_PTR_MISMATCH => bail!("TODO: Argon2 error: PWD_PTR_MISMATCH"),
        ffi::Argon2_ErrorCodes_ARGON2_SALT_PTR_MISMATCH => bail!("TODO: Argon2 error: SALT_PTR_MISMATCH"),
        ffi::Argon2_ErrorCodes_ARGON2_SECRET_PTR_MISMATCH => bail!("TODO: Argon2 error: SECRET_PTR_MISMATCH"),
        ffi::Argon2_ErrorCodes_ARGON2_AD_PTR_MISMATCH => bail!("TODO: Argon2 error: AD_PTR_MISMATCH"),
        ffi::Argon2_ErrorCodes_ARGON2_MEMORY_ALLOCATION_ERROR => bail!("TODO: Argon2 error: MEMORY_ALLOCATION_ERROR"),
        ffi::Argon2_ErrorCodes_ARGON2_FREE_MEMORY_CBK_NULL => bail!("TODO: Argon2 error: FREE_MEMORY_CBK_NULL"),
        ffi::Argon2_ErrorCodes_ARGON2_ALLOCATE_MEMORY_CBK_NULL => bail!("TODO: Argon2 error: ALLOCATE_MEMORY_CBK_NULL"),
        ffi::Argon2_ErrorCodes_ARGON2_INCORRECT_PARAMETER => bail!("TODO: Argon2 error: INCORRECT_PARAMETER"),
        ffi::Argon2_ErrorCodes_ARGON2_INCORRECT_TYPE => bail!("TODO: Argon2 error: INCORRECT_TYPE"),
        ffi::Argon2_ErrorCodes_ARGON2_OUT_PTR_MISMATCH => bail!("TODO: Argon2 error: OUT_PTR_MISMATCH"),
        ffi::Argon2_ErrorCodes_ARGON2_THREADS_TOO_FEW => bail!("TODO: Argon2 error: THREADS_TOO_FEW"),
        ffi::Argon2_ErrorCodes_ARGON2_THREADS_TOO_MANY => bail!("TODO: Argon2 error: THREADS_TOO_MANY"),
        ffi::Argon2_ErrorCodes_ARGON2_MISSING_ARGS => bail!("TODO: Argon2 error: MISSING_ARGS"),
        ffi::Argon2_ErrorCodes_ARGON2_ENCODING_FAIL => bail!("TODO: Argon2 error: ENCODING_FAIL"),
        ffi::Argon2_ErrorCodes_ARGON2_DECODING_FAIL => bail!("TODO: Argon2 error: DECODING_FAIL"),
        ffi::Argon2_ErrorCodes_ARGON2_THREAD_FAIL => bail!("TODO: Argon2 error: THREAD_FAIL"),
        ffi::Argon2_ErrorCodes_ARGON2_DECODING_LENGTH_FAIL => bail!("TODO: Argon2 error: DECODING_LENGTH_FAIL"),
        ffi::Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH => bail!("TODO: Argon2 error: VERIFY_MISMATCH"),
        _ => bail!("TODO: Argon2 error: unknown"),
    }
    Ok(())
}
