use base64;
use failure;
use void::Void;

use data::read::{Read, ReadPrivate};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SecretKey {
    bytes: Vec<u8>,
}

impl SecretKey {
    pub fn none() -> SecretKey {
        SecretKey { bytes: vec![] }
    }
    pub fn from_base64_encoded_str(s: &str) -> Result<SecretKey, failure::Error> {
        let bytes = base64::decode_config(s, base64::STANDARD)?;
        Ok(SecretKey { bytes })
    }
    pub fn from_base64_encoded_string(s: String) -> Result<SecretKey, failure::Error> {
        let bytes = base64::decode_config(&s, base64::STANDARD)?;
        Ok(SecretKey { bytes })
    }
}

// TODO
impl<'a> From<&'a SecretKey> for SecretKey {
    fn from(secret_key: &'a SecretKey) -> Self {
        secret_key.clone()
    }
}

impl<'a> From<&'a [u8]> for SecretKey {
    fn from(bytes: &'a [u8]) -> Self {
        SecretKey {
            bytes: bytes.to_vec(),
        }
    }
}

impl From<Vec<u8>> for SecretKey {
    fn from(bytes: Vec<u8>) -> Self {
        SecretKey { bytes }
    }
}

impl<'a> From<&'a str> for SecretKey {
    fn from(s: &'a str) -> Self {
        let bytes = s.as_bytes().to_vec();
        SecretKey { bytes }
    }
}

impl<'a, 'b> From<&'a &'b str> for SecretKey {
    fn from(s: &'a &'b str) -> Self {
        let bytes = s.as_bytes().to_vec();
        SecretKey { bytes }
    }
}

impl From<String> for SecretKey {
    fn from(s: String) -> Self {
        let bytes = s.into_bytes();
        SecretKey { bytes }
    }
}

impl ::std::str::FromStr for SecretKey {
    type Err = Void;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes().to_vec();
        Ok(SecretKey { bytes })
    }
}

impl Read for SecretKey {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ReadPrivate for SecretKey {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
    fn validate(&self, extra: Option<bool>) -> Result<(), failure::Error> {
        let opt_out_of_secret_key = extra.unwrap();
        if !(opt_out_of_secret_key) && self.bytes.len() == 0 {
            bail!("TODO: Trying to hash without a secret key when you have not explicitly opted out of using a secret key")
        }
        if self.bytes.len() >= ::std::u32::MAX as usize {
            bail!("TODO: Secret key too long; must be less than 2^32 - 1 bytes")
        }
        Ok(())
    }
}
