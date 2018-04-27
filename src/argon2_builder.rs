use failure;

use argon2::Argon2;
use configuration::config::Config;
use configuration::flags::Flags;
use configuration::variant::Variant;
use configuration::version::Version;
use parameters::salt::Salt;
use parameters::secret_key::SecretKey;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Argon2Builder {
    flags: Flags,
    hash_length: u32,
    iterations: u32,
    lanes: u32,
    memory_size: u32,
    threads: u32,
    variant: Variant,
    version: Version,

    additional_data: Option<Vec<u8>>,
    salt: Salt,
    secret_key: SecretKey,

    opt_out_of_random_salt: bool,
    opt_out_of_secret_key: bool,
}

impl Argon2Builder {
    pub fn default() -> Argon2Builder {
        Argon2Builder {
            flags: Flags::default(),
            hash_length: 32,
            iterations: 10,
            lanes: 1,
            memory_size: 4096,
            threads: 1,
            variant: Variant::Argon2i,
            version: Version::_0x13,

            additional_data: None,
            salt: Salt::Random(32),
            secret_key: SecretKey::None,

            opt_out_of_random_salt: false,
            opt_out_of_secret_key: false,
        }
    }
    pub fn with_salt(mut self, salt: Salt) -> Argon2Builder {
        self.salt = salt;
        self
    }
    pub fn with_secret_key(mut self, secret_key: SecretKey) -> Argon2Builder {
        self.secret_key = secret_key;
        self
    }
    pub fn opt_out_of_random_salt(mut self) -> Argon2Builder {
        self.opt_out_of_random_salt = true;
        self
    }
    pub fn opt_out_of_secret_key(mut self) -> Argon2Builder {
        self.opt_out_of_secret_key = true;
        self
    }
    pub fn build(self) -> Result<Argon2, failure::Error> {
        // Check opt-outs
        if !self.opt_out_of_random_salt {
            match self.salt {
                Salt::Random(_) => (),
                Salt::Deterministic(_) => bail!("TODO"),
                Salt::None => bail!("TODO"),
            }
        }
        if !self.opt_out_of_secret_key {
            match self.secret_key {
                SecretKey::None => bail!("TODO"),
                _ => (),
            }
        }

        // Check inputs
        if !(self.secret_key.len()? <= u32::max_value() as usize) {
            bail!("TODO");
        }
        if !(self.memory_size.is_power_of_two()) {
            bail!("TODO");
        }
        // TODO: More checks

        let config = Config::new(
            self.flags,
            self.hash_length,
            self.iterations,
            self.lanes,
            self.memory_size,
            self.threads,
            self.variant,
            self.version,
        );
        let argon2 = Argon2::new(
            config,
            self.additional_data,
            self.salt,
            self.secret_key
        );
        Ok(argon2)
    }
}

#[cfg(feature = "serde")]
mod serde {
    use serde::ser::{Serialize, Serializer};
    use serde::de::{Deserialize, Deserializer};

    use super::Argon2Builder;

    impl Serialize for Argon2Builder {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            unimplemented!()
        }
    }

    impl<'de> Deserialize<'de> for Argon2Builder {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Argon2Builder, D::Error> {
            unimplemented!()
        }
    }
}
