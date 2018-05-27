//! Struct representing raw hash output.
//!
//! You won't have to use this if you use the regular
//! [`hash`](struct.Hasher.html#method.hash) or
//! [`hash_non_blocking`](struct.Hasher.html#method.hash_non_blocking) methods
//! on [`Hasher`](struct.Hasher.html), which return a string-encoded hash.
mod hash_raw;

pub use self::hash_raw::HashRaw;
