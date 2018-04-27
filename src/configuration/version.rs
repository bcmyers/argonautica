#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Version {
    _0x10 = 0x10,
    _0x13 = 0x13,
}

#[cfg(feature = "serde")]
mod serde {
    use serde::ser::{Serialize, Serializer};
    use serde::de::{Deserialize, Deserializer};

    use super::Version;

    impl Serialize for Version {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            unimplemented!()
        }
    }

    impl<'de> Deserialize<'de> for Version {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Version, D::Error> {
            unimplemented!()
        }
    }
}
