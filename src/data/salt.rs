use base64;
use failure;
use void::Void;

use config::defaults::DEFAULT_SALT_LENGTH;
use data::read::{Read, ReadPrivate};
use utils;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Salt {
    bytes: Vec<u8>,
    is_random: bool,
}

impl Salt {
    pub fn default() -> Result<Salt, failure::Error> {
        Ok(Salt::random(DEFAULT_SALT_LENGTH)?)
    }
    pub fn random(length: u32) -> Result<Salt, failure::Error> {
        let bytes = utils::generate_random_bytes(length)?;
        Ok(Salt {
            bytes,
            is_random: true,
        })
    }
    pub fn from_base64_encoded_str(s: &str) -> Result<Salt, failure::Error> {
        let bytes = base64::decode_config(s, base64::STANDARD)?;
        Ok(Salt {
            bytes,
            is_random: false,
        })
    }
    pub fn from_base64_encoded_string(s: String) -> Result<Salt, failure::Error> {
        let bytes = base64::decode_config(&s, base64::STANDARD)?;
        Ok(Salt {
            bytes,
            is_random: false,
        })
    }
    pub fn is_random(&self) -> bool {
        self.is_random
    }
}

impl<'a> From<&'a Salt> for Salt {
    fn from(salt: &'a Salt) -> Self {
        salt.clone()
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

impl From<Vec<u8>> for Salt {
    fn from(bytes: Vec<u8>) -> Self {
        Salt {
            bytes,
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

impl<'a, 'b> From<&'a &'b str> for Salt {
    fn from(s: &'a &'b str) -> Self {
        let bytes = s.as_bytes().to_vec();
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

impl ::std::str::FromStr for Salt {
    type Err = Void;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes().to_vec();
        Ok(Salt {
            bytes,
            is_random: false,
        })
    }
}

impl Read for Salt {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ReadPrivate for Salt {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
    fn validate(&self, extra: Option<bool>) -> Result<(), failure::Error> {
        let opt_out_of_random_salt = extra.unwrap();
        let length = self.bytes.len();
        if length < 8 {
            bail!("Salt is too short; length in bytes must be greater than 8")
        }
        if length >= ::std::u32::MAX as usize {
            bail!("Salt is too long; length in bytes must be less than 2^32 - 1")
        }
        if !(opt_out_of_random_salt) && !(self.is_random) {
            bail!("Attempted to use a non-random salt without having opted out of random salt")
        }
        Ok(())
    }
}
