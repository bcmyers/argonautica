use config::defaults::DEFAULT_SALT_LENGTH;
use data::{Data, DataPrivate};
use error::{Error, ErrorKind};
use utils;

impl Default for Salt {
    /// Produces a `Salt` with random bytes of length 32 that will use a cryptographically-secure
    /// random number genertor to produce new random bytes for each call to `hash()` or
    /// `hash_raw()` on `Hasher`
    fn default() -> Salt {
        Salt {
            bytes: vec![0u8; DEFAULT_SALT_LENGTH as usize],
            is_random: true,
        }
    }
}

impl<'a> From<&'a [u8]> for Salt {
    fn from(bytes: &'a [u8]) -> Self {
        Salt {
            bytes: bytes.to_vec(),
            is_random: false,
        }
    }
}

impl<'a> From<&'a str> for Salt {
    fn from(s: &'a str) -> Self {
        let bytes = s.as_bytes().to_vec();
        Salt {
            bytes,
            is_random: false,
        }
    }
}

impl From<Vec<u8>> for Salt {
    fn from(bytes: Vec<u8>) -> Self {
        Salt {
            bytes,
            is_random: false,
        }
    }
}

impl From<String> for Salt {
    fn from(s: String) -> Self {
        let bytes = s.into_bytes();
        Salt {
            bytes,
            is_random: false,
        }
    }
}

impl<'a> From<&'a Vec<u8>> for Salt {
    fn from(bytes: &Vec<u8>) -> Self {
        Salt {
            bytes: bytes.clone(),
            is_random: false
        }
    }
}

impl<'a> From<&'a String> for Salt {
    fn from(s: &String) -> Self {
        let bytes = s.as_bytes().to_vec();
        Salt {
            bytes,
            is_random: false,
        }
    }
}

impl<'a> From<&'a Salt> for Salt {
    fn from(salt: &Salt) -> Self {
        salt.clone()
    }
}

impl Data for Salt {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Type-safe struct representing the raw bytes of your salt,</br>
/// as well as an indicator for whether or not a new random salt should be generated after each hash (the default)
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Salt {
    bytes: Vec<u8>,
    is_random: bool,
}

impl Salt {
    /// Constructs a "random" `Salt` of length provided that uses a cryptographically secure
    /// random number generator to produce new random bytes for each call to `hash()` or
    /// `hash_raw()` on `Hasher`
    pub fn random(length: u32) -> Result<Salt, Error> {
        let bytes = utils::generate_random_bytes(length)?;
        Ok(Salt {
            bytes,
            is_random: true,
        })
    }
    pub fn is_random(&self) -> bool {
        self.is_random
    }
}

impl DataPrivate for Salt {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
    fn validate(&self, extra: Option<bool>) -> Result<(), Error> {
        let opt_out_of_random_salt = extra.unwrap();
        let length = self.bytes.len();
        if length < 8 {
            return Err(ErrorKind::SaltTooShort.into());
        }
        if length >= ::std::u32::MAX as usize {
            return Err(ErrorKind::SaltTooLong.into());
        }
        if !(opt_out_of_random_salt) && !(self.is_random) {
            return Err(ErrorKind::SaltNonRandom.into());
        }
        Ok(())
    }
}
