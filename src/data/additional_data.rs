use failure;
use void::Void;

use data::read::{Read, ReadPrivate};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AdditionalData {
    bytes: Vec<u8>,
}

impl Default for AdditionalData {
    fn default() -> AdditionalData {
        AdditionalData::none()
    }
}

impl AdditionalData {
    pub(crate) fn none() -> AdditionalData {
        AdditionalData { bytes: vec![] }
    }
}

impl<'a> From<&'a [u8]> for AdditionalData {
    fn from(bytes: &'a [u8]) -> Self {
        AdditionalData {
            bytes: bytes.to_vec(),
        }
    }
}

impl From<Vec<u8>> for AdditionalData {
    fn from(bytes: Vec<u8>) -> Self {
        AdditionalData { bytes }
    }
}

impl<'a> From<&'a str> for AdditionalData {
    fn from(s: &'a str) -> Self {
        let bytes = s.as_bytes().to_vec();
        AdditionalData { bytes }
    }
}

impl<'a, 'b> From<&'a &'b str> for AdditionalData {
    fn from(s: &'a &'b str) -> Self {
        let bytes = s.as_bytes().to_vec();
        AdditionalData { bytes }
    }
}

impl From<String> for AdditionalData {
    fn from(s: String) -> Self {
        let bytes = s.into_bytes();
        AdditionalData { bytes }
    }
}

impl ::std::str::FromStr for AdditionalData {
    type Err = Void;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes().to_vec();
        Ok(AdditionalData { bytes })
    }
}

impl Read for AdditionalData {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ReadPrivate for AdditionalData {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
    fn validate(&self, _extra: Option<bool>) -> Result<(), failure::Error> {
        if self.bytes.len() >= ::std::u32::MAX as usize {
            bail!("Additional data is too long; length in bytes must be less than 2^32 - 1");
        }
        Ok(())
    }
}
