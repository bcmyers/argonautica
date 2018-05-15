use std::str::FromStr;

use backend::{decode_rust, encode_rust};
use config::{Variant, Version};
use error::Error;

impl FromStr for HashRaw {
    ///
    type Err = Error;

    /// Take a regular string-encoded hash and converts it into an instance of `HashRaw`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(decode_rust(s)?)
    }
}

/// Struct representing raw hash output. If you use the regular `hash` method on `Hasher`, you won't have to use this.
/// If, however, you prefer to see the raw bytes behind the hash, you can obtain an instance of
/// this struct with the `hash_raw` method on `Hasher`
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
    /// Converts the `HashRaw` to a string-encoded hash
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
    /// Access to the raw hash bytes
    pub fn raw_hash_bytes(&self) -> &[u8] {
        &self.raw_hash_bytes
    }
    /// Access to the raw salt bytes
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
