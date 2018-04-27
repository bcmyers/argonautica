use std::str::FromStr;

use base64;
use failure;
use void::Void;

use utils;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Salt {
    Random(u32),
    Deterministic(Vec<u8>),
    None,
}

impl Default for Salt {
    fn default() -> Salt {
        Salt::Random(32)
    }
}

impl Salt {
    pub fn to_bytes(&self) -> Result<Vec<u8>, failure::Error> {
        match *self {
            Salt::Random(n) => Ok(utils::generate_salt(n)?),
            Salt::Deterministic(ref bytes) => Ok(bytes.clone()),
            Salt::None => Ok(vec![]),
        }
    }
    pub fn from_base64_encoded_str(s: &str) -> Result<Salt, failure::Error> {
        let bytes = base64::decode_config(s, base64::STANDARD)?;
        Ok(Salt::Deterministic(bytes))
    }
    pub fn from_slice(slice: &[u8]) -> Salt {
        Salt::Deterministic(slice.to_vec())
    }
}

impl FromStr for Salt {
    type Err = Void;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Salt::Deterministic(s.as_bytes().to_vec()))
    }
}

#[cfg(feature = "serde")]
mod serde {
    use serde::ser::{Serialize, Serializer};
    use serde::de::{Deserialize, Deserializer};

    use super::Salt;

    impl Serialize for Salt {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            unimplemented!()
        }
    }

    impl<'de> Deserialize<'de> for Salt {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Salt, D::Error> {
            unimplemented!()
        }
    }
}
