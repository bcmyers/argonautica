use std::str::FromStr;

use backend::decode_rust;
use config::{Variant, Version};
use Error;

impl FromStr for HashRaw {
    ///
    type Err = Error;

    /// Takes a regular string-encoded hash and converts it into an instance
    /// of [`HashRaw`](struct.HashRaw.html)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(decode_rust(s)?)
    }
}

/// Struct representing raw hash output.
///
/// You typically won't need this struct if all you'd like to produce is a string-encoded hash,
/// which is what is returned from the regular [`hash`](../struct.Hasher.html#method.hash)
/// method on [`Hasher`](../struct.Hasher.html) (or it's non-blocking equivalent).
///
/// That said, if you want to inspect each component of a hash more directly (e.g. pull out the
/// raw hash bytes or the raw salt bytes individually), you can obtain an instance of this
/// [`HashRaw`](struct.HashRaw.html) struct, which will allows you do to those things, by either:
/// * Parsing a string-encoded hash into a [`HashRaw`](struct.HashRaw.html) via
///   `let hash_raw = hash_str.parse::<HashRaw>()?;`, or
/// * Obtaining a `HashRaw` directly by calling [`hash_raw`](../struct.Hasher.html#method.hash_raw)
///   on a [`Hasher`](../struct.Hasher.html) (or its non-blocking equivalent)
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct HashRaw {
    pub(crate) iterations: u32,
    pub(crate) lanes: u32,
    pub(crate) memory_size: u32,
    pub(crate) raw_hash_bytes: Vec<u8>,
    pub(crate) raw_salt_bytes: Vec<u8>,
    pub(crate) variant: Variant,
    pub(crate) version: Version,
}

impl HashRaw {
    /// Converts the [`HashRaw`](struct.HashRaw.html) to a string-encoded hash
    pub fn to_string(&self) -> String {
        self.encode_rust()
    }
    /// Obtain the iterations configuration that was used to produce this hash
    pub fn iterations(&self) -> u32 {
        self.iterations
    }
    /// Obtain the lanes configuration that was used to produce this hash
    pub fn lanes(&self) -> u32 {
        self.lanes
    }
    /// Obtain the memory size configuration that was used to produce this hash
    pub fn memory_size(&self) -> u32 {
        self.memory_size
    }
    /// Read-only access to the raw hash bytes
    pub fn raw_hash_bytes(&self) -> &[u8] {
        &self.raw_hash_bytes
    }
    /// Read-only access to the raw salt bytes
    pub fn raw_salt_bytes(&self) -> &[u8] {
        &self.raw_salt_bytes
    }
    /// Obtain the variant configuration that was used to produce this hash
    pub fn variant(&self) -> Variant {
        self.variant
    }
    /// Obtian the version configuration that was used to produce this hash
    pub fn version(&self) -> Version {
        self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<HashRaw>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<HashRaw>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<HashRaw>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<HashRaw>();
    }
}
