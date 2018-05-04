use config::defaults::DEFAULT_VARIANT;

/// Enum repressenting the choice between variants of the Argon2 algorithm (`Argon2d`, `Argon2i`,
/// and `Argon2id`).
///
/// According to a [March 24, 2017 paper by the authors of the Argon2 algorithm](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf),
/// "`Ardon2d` is faster and uses data-depending memory access, which makes it suitable for
/// cryptocurrencies and applications with no threats from side-channel timing attackes. `Argon2i`
/// uses data-independent memory access, which is preferred for password hashing and password-based
/// key derivation"
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
