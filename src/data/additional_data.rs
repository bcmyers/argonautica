#[cfg(feature = "serde")]
use std::fmt;

#[cfg(feature = "serde")]
use serde;

use data::{Data, DataPrivate};
use error::{Error, ErrorKind};

impl<'a> From<&'a [u8]> for AdditionalData {
    fn from(bytes: &'a [u8]) -> Self {
        AdditionalData {
            bytes: bytes.to_vec(),
        }
    }
}

impl<'a> From<&'a str> for AdditionalData {
    fn from(s: &'a str) -> Self {
        let bytes = s.as_bytes().to_vec();
        AdditionalData { bytes }
    }
}

impl From<Vec<u8>> for AdditionalData {
    fn from(bytes: Vec<u8>) -> Self {
        AdditionalData { bytes }
    }
}

impl From<String> for AdditionalData {
    fn from(s: String) -> Self {
        let bytes = s.into_bytes();
        AdditionalData { bytes }
    }
}

impl<'a> From<&'a Vec<u8>> for AdditionalData {
    fn from(bytes: &Vec<u8>) -> Self {
        AdditionalData {
            bytes: bytes.clone(),
        }
    }
}

impl<'a> From<&'a String> for AdditionalData {
    fn from(s: &String) -> Self {
        let bytes = s.as_bytes().to_vec();
        AdditionalData { bytes }
    }
}

impl<'a> From<&'a AdditionalData> for AdditionalData {
    fn from(additional_data: &AdditionalData) -> Self {
        additional_data.clone()
    }
}

impl Data for AdditionalData {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AdditionalData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AdditionalData {
    fn deserialize<D>(deserializer: D) -> Result<AdditionalData, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let visitor = AdditionalDataVisitor;
        let bytes = deserializer.deserialize_seq(visitor)?;
        Ok(AdditionalData { bytes })
    }
}

/// Type-safe struct representing the raw bytes of your additional data (if any)
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AdditionalData {
    bytes: Vec<u8>,
}

impl AdditionalData {
    pub(crate) fn none() -> AdditionalData {
        AdditionalData { bytes: vec![] }
    }
}

impl DataPrivate for AdditionalData {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
    fn validate(&self, _extra: Option<bool>) -> Result<(), Error> {
        if self.bytes.len() >= ::std::u32::MAX as usize {
            return Err(ErrorKind::AdditionalDataTooLongError.into());
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
struct AdditionalDataVisitor;

#[cfg(feature = "serde")]
impl<'de> serde::de::Visitor<'de> for AdditionalDataVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v.to_vec())
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut output: Vec<u8> = Vec::new();
        loop {
            match seq.next_element()? {
                Some(value) => {
                    output.push(value);
                }
                None => break,
            }
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<AdditionalData>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<AdditionalData>();
    }
}
