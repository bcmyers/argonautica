//! Contains struct representing raw hash output. You won't have to use this if you use the regular
//! [`hash`](struct.Hasher.html#method.hash) method on [`Hasher`](struct.Hasher.html).
mod hash_raw;

pub use self::hash_raw::HashRaw;
