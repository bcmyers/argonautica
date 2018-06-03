use std::str::FromStr;

use backend::{decode_rust, encode_rust};
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

/// Struct representing raw hash output. If you use the regular
/// [`hash`](../struct.Hasher.html#method.hash) or
/// [`hash_non_blocking`](../struct.Hasher.html#method.hash_non_blocking) methods on
/// [`Hasher`](../struct.Hasher.html), you won't have to use this. If, however, you prefer
/// to see the raw bytes behind the hash, you can obtain an instance of this struct with the
/// [`hash_raw`](../struct.Hasher.html#method.hash_raw) or
/// [`hash_raw_non_blocking`](../struct.Hasher.html#method.hash_raw_non_blocking) methods on
/// [`Hasher`](../struct.Hasher.html)
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct HashRaw {
    iterations: u32,
    lanes: u32,
    memory_size: u32,
    raw_hash_bytes: Vec<u8>,
    raw_salt_bytes: Vec<u8>,
    variant: Variant,
    version: Version,
}

impl HashRaw {
    /// Converts the [`HashRaw`](struct.HashRaw.html) to a string-encoded hash
    pub fn to_hash(&self) -> String {
        encode_rust(self)
    }
    /// Iterations configuration used to create this hash
    pub fn iterations(&self) -> u32 {
        self.iterations
    }
    /// Lanes configuration used to create this hash
    pub fn lanes(&self) -> u32 {
        self.lanes
    }
    /// Memory size configuration used to create this hash
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
    /// Variant configuration used to create this hash
    pub fn variant(&self) -> Variant {
        self.variant
    }
    /// Version configuration used to create this hash
    pub fn version(&self) -> Version {
        self.version
    }
}

impl HashRaw {
    pub(crate) fn new(
        iterations: u32,
        lanes: u32,
        memory_size: u32,
        raw_hash_bytes: Vec<u8>,
        raw_salt_bytes: Vec<u8>,
        variant: Variant,
        version: Version,
    ) -> HashRaw {
        HashRaw {
            iterations,
            lanes,
            memory_size,
            raw_hash_bytes,
            raw_salt_bytes,
            variant,
            version,
        }
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
