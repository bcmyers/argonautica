use std::str::FromStr;

use config::defaults::DEFAULT_VARIANT;
use {Error, ErrorKind};

impl Default for Variant {
    /// Returns [`Variant::Argon2id`](enum.Variant.html#variant.Argon2id)
    fn default() -> Variant {
        DEFAULT_VARIANT
    }
}

impl FromStr for Variant {
    ///
    type Err = Error;

    /// Performs the following mapping:
    /// * `"argon2d"` => `Ok(Variant::Argon2d)`<br/>
    /// * `"argon2i"` => `Ok(Variant::Argon2i)`<br/>
    /// * `"argon2id"` => `Ok(Variant::Argon2id)`<br/>
    /// * anything else => an error
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "argon2d" => Ok(Variant::Argon2d),
            "argon2i" => Ok(Variant::Argon2i),
            "argon2id" => Ok(Variant::Argon2id),
            _ => {
                Err(Error::new(ErrorKind::VariantEncodeError).add_context(format!("String: {}", s)))
            }
        }
    }
}

/// Enum representing the various variants of the Argon2 algorithm (
/// [`Argon2d`](enum.Variant.html#variant.Argon2d),
/// [`Argon2i`](enum.Variant.html#variant.Argon2i), and
/// [`Argon2id`](enum.Variant.html#variant.Argon2id)).
///
/// According to the [latest (as of 5/18) Argon2 RFC](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03) ...
/// "Argon2 has one primary variant: Argon2id, and two supplementary
/// variants: Argon2d and Argon2i. Argon2d uses data-dependent memory
/// access, which makes it suitable for ... applications with no threats from
/// side-channel timing attacks. Argon2i uses data-independent memory access,
/// which is preferred for password hashing and password-based key derivation.
/// Argon2id works as Argon2i for the first half of the first iteration over the memory,
/// and as Argon2d for the rest, thus providing both side-channel attack
/// protection and brute-force cost savings due to time-memory tradeoffs." If you do not
/// know which variant to use, use the default, which is [`Argon2id`](enum.Variant.html#variant.Argon2id))
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum Variant {
    /// Variant of the Argon2 algorithm that is faster and uses data-depending memory access,
    /// which makes it suitable for applications with no threats from side-channel timing attackes.
    /// Do <b><u>not</b></u> use this unless you have a specific reason to.
    Argon2d = 0,

    /// Variant of the Argon2 algorithm that uses data-independent memory access, which is
    /// preferred for password hashing and password-based key derivation. Do <b><u>not</b></u> use
    /// this unless you have a specific reason to.
    Argon2i = 1,

    /// Default variant of the Argon2 algorithm that works as Argon2i for the first half of the
    /// first iteration over the memory, and as Argon2d for the rest, thus providing both
    /// side-channel attack protection and brute-force cost savings due to time-memory tradeoffs.
    /// Use this unless you have a specific reason not to.
    Argon2id = 2,
}

impl Variant {
    /// Performs the following mapping:
    /// * `Variant::Argond2d` => `"argon2d"`<br/>
    /// * `Variant::Argond2i` => `"argon2i"`<br/>
    /// * `Variant::Argond2id` => `"argon2id"`
    pub fn as_str(&self) -> &'static str {
        match *self {
            Variant::Argon2d => "argon2d",
            Variant::Argon2i => "argon2i",
            Variant::Argon2id => "argon2id",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Variant>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Variant>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<Variant>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<Variant>();
    }
}
