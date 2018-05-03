use config::defaults::DEFAULT_VARIANT;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Variant {
    Argon2d = 0,
    Argon2i = 1,
    Argon2id = 2,
}

impl Default for Variant {
    fn default() -> Variant {
        DEFAULT_VARIANT
    }
}

#[cfg(feature = "serde")]
mod serde {
    use serde::de::{Deserialize, Deserializer};
    use serde::ser::{Serialize, Serializer};

    use super::Variant;

    impl Serialize for Variant {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            unimplemented!()
        }
    }

    impl<'de> Deserialize<'de> for Variant {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Variant, D::Error> {
            unimplemented!()
        }
    }
}
