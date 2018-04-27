use configuration::flags::Flags;
use configuration::variant::Variant;
use configuration::version::Version;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Config {
    flags: Flags,
    hash_length: u32,
    iterations: u32,
    lanes: u32,
    memory_size: u32,
    threads: u32,
    variant: Variant,
    version: Version,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            flags: Flags::default(),
            hash_length: 32,
            iterations: 10,
            lanes: 1,
            memory_size: 4096,
            threads: 1,
            variant: Variant::Argon2i,
            version: Version::_0x13,
        }
    }
}

impl Config {
    pub(crate) fn new(
        flags: Flags,
        hash_length: u32,
        iterations: u32,
        lanes: u32,
        memory_size: u32,
        threads: u32,
        variant: Variant,
        version: Version
    ) -> Config {
        Config {
            flags,
            hash_length,
            iterations,
            lanes,
            memory_size,
            threads,
            variant,
            version,
        }
    }
    pub(crate) fn flags(&self) -> Flags {
        self.flags
    }
    pub(crate) fn hash_length(&self) -> u32 {
        self.hash_length
    }
    pub(crate) fn iterations(&self) -> u32 {
        self.iterations
    }
    pub(crate) fn lanes(&self) -> u32 {
        self.lanes
    }
    pub(crate) fn memory_size(&self) -> u32 {
        self.memory_size
    }
    pub(crate) fn threads(&self) -> u32 {
        self.threads
    }
    pub(crate) fn variant(&self) -> Variant {
        self.variant
    }
    pub(crate) fn version(&self) -> Version {
        self.version
    }
}

#[cfg(feature = "serde")]
mod serde {
    use serde::ser::{Serialize, Serializer};
    use serde::de::{Deserialize, Deserializer};

    use super::Config;

    impl Serialize for Config {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            unimplemented!()
        }
    }

    impl<'de> Deserialize<'de> for Config {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Config, D::Error> {
            unimplemented!()
        }
    }
}
