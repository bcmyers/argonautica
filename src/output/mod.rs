//! Struct representing raw hash output. If you use the regular `hash` method on `Hasher`, you won't have to use this.
mod hash_raw;

pub use self::hash_raw::HashRaw;
