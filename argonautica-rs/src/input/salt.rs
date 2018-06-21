use rand::rngs::EntropyRng;
use rand::RngCore;

use {Error, ErrorKind};

impl Default for Salt {
    /// Creates a new <u>random</u> `Salt`.
    ///
    /// Initially, the random `Salt` has nothing in it, but every time you call `hash`,
    /// `hash_raw`, or their non-blocking equivalents on a `Hasher`, the `Salt` will update with
    /// `32` new random bytes generated using a cryptographically-secure random number
    /// generator (`EntropyRng`)
    fn default() -> Salt {
        Salt::random(32)
    }
}

impl From<Vec<u8>> for Salt {
    fn from(bytes: Vec<u8>) -> Salt {
        Salt(Kind::Deterministic(bytes))
    }
}

impl From<String> for Salt {
    fn from(s: String) -> Salt {
        Salt(Kind::Deterministic(s.into_bytes()))
    }
}

impl<'a> From<&'a [u8]> for Salt {
    fn from(bytes: &[u8]) -> Salt {
        Salt(Kind::Deterministic(bytes.to_vec()))
    }
}

impl<'a> From<&'a str> for Salt {
    fn from(s: &str) -> Salt {
        Salt(Kind::Deterministic(s.as_bytes().to_vec()))
    }
}

impl<'a> From<&'a Vec<u8>> for Salt {
    fn from(bytes: &Vec<u8>) -> Salt {
        Salt(Kind::Deterministic(bytes.clone()))
    }
}

impl<'a> From<&'a String> for Salt {
    fn from(s: &String) -> Salt {
        Salt(Kind::Deterministic(s.clone().into_bytes()))
    }
}

impl<'a> From<&'a Salt> for Salt {
    fn from(salt: &Salt) -> Salt {
        salt.clone()
    }
}

/// Type-safe struct representing the raw bytes of your salt
///
/// <i>Note: A `Salt` knows if it's <b>random</b> or <b>deterministic</b>:
/// * A `Salt` will be <b>random</b> if it's constructed via the `default` or `random`
///   constructors. It will be <b>deterministic</b> if it's constructed via any of the various
///   `From` implementations
/// * A <b>random</b> `Salt` will generate new random bytes using a cryptographically-secure
///   random number generator (`EntropyRng`) upon each call to `hash`, `hash_raw` or their
///   non-blocking equivalents. A <b>deterministic</b> `Salt` remain constant upon each of these
///   calls</i>
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Salt(Kind);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
enum Kind {
    Deterministic(Vec<u8>),
    Random(Vec<u8>),
}

impl Salt {
    /// Creates a new <u>random</u> `Salt`.
    ///
    /// Initially, the random `Salt` has nothing in it, but every time you call `hash`,
    /// `hash_raw`, or their non-blocking equivalents on a `Hasher`, the `Salt` will update with
    /// new random bytes of the length specified generated using a cryptographically-secure
    /// random number generator (`EntropyRng`)
    pub fn random(len: u32) -> Salt {
        let bytes = vec![0u8; len as usize];
        Salt(Kind::Random(bytes))
    }
    /// Read-only access to the underlying byte buffer
    pub fn as_bytes(&self) -> &[u8] {
        match self.0 {
            Kind::Deterministic(ref bytes) => bytes.as_slice(),
            Kind::Random(ref bytes) => bytes.as_slice(),
        }
    }
    /// Returns `true` if the `Salt` is <u>random</u>; `false` if it is <u>deterministic</u>
    pub fn is_random(&self) -> bool {
        match self.0 {
            Kind::Deterministic(_) => false,
            Kind::Random(_) => true,
        }
    }
    /// Read-only acccess to the underlying byte buffer's length
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }
    /// Read-only access to the underlying byte buffer as a `&str` if its bytes are valid utf-8
    pub fn to_str(&self) -> Result<&str, Error> {
        let s = ::std::str::from_utf8(self.as_bytes()).map_err(|_| {
            Error::new(ErrorKind::Utf8EncodeError)
                .add_context(format!("Bytes: {:?}", self.as_bytes()))
        })?;
        Ok(s)
    }
    /// If you have a <u>random</u> `Salt`, this method will generate new random bytes of the
    /// length of your `Salt`. If you have a <u>deterministic</u> `Salt`, this method does nothing
    pub fn update(&mut self) -> Result<(), Error> {
        match self.0 {
            Kind::Random(ref mut bytes) => {
                let mut rng = EntropyRng::new();
                rng.try_fill_bytes(bytes)
                    .map_err(|_| Error::new(ErrorKind::OsRngError))?;
            }
            _ => (),
        }
        Ok(())
    }
}

impl Salt {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let len = self.len();
        if len < 8 {
            return Err(
                Error::new(ErrorKind::SaltTooShortError).add_context(format!("Length: {}", len))
            );
        }
        if len >= ::std::u32::MAX as usize {
            return Err(
                Error::new(ErrorKind::SaltTooLongError).add_context(format!("Length: {}", len))
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Salt>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Salt>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<Salt>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<Salt>();
    }
}
