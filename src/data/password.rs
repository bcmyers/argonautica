use failure;
use void::Void;

use data::read::{Read, ReadPrivate};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Password {
    bytes: Vec<u8>,
}

impl Password {
    pub(crate) fn none() -> Password {
        Password { bytes: vec![] }
    }
}

impl<'a> From<&'a [u8]> for Password {
    fn from(bytes: &'a [u8]) -> Self {
        Password {
            bytes: bytes.to_vec(),
        }
    }
}

impl From<Vec<u8>> for Password {
    fn from(bytes: Vec<u8>) -> Self {
        Password { bytes }
    }
}

impl<'a> From<&'a str> for Password {
    fn from(s: &'a str) -> Self {
        let bytes = s.as_bytes().to_vec();
        Password { bytes }
    }
}

impl<'a, 'b> From<&'a &'b str> for Password {
    fn from(s: &'a &'b str) -> Self {
        let bytes = s.as_bytes().to_vec();
        Password { bytes }
    }
}

impl From<String> for Password {
    fn from(s: String) -> Self {
        let bytes = s.into_bytes();
        Password { bytes }
    }
}

impl ::std::str::FromStr for Password {
    type Err = Void;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes().to_vec();
        Ok(Password { bytes })
    }
}

impl Read for Password {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ReadPrivate for Password {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
    fn validate(&self, _extra: Option<bool>) -> Result<(), failure::Error> {
        if self.bytes.is_empty() {
            bail!("Password cannot be empty");
        }
        if self.bytes.len() >= ::std::u32::MAX as usize {
            bail!("Password is too long; length in bytes must be less than 2^32 - 1");
        }
        Ok(())
    }
}
