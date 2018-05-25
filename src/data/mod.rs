//! Contains structs representing data to hash (i.e.
//! [`Password`](data/struct.Password.html),
//! [`Salt`](data/struct.Salt.html),
//! [`SecretKey`](data/struct.SecretKey.html), and
//! [`AdditionalData`](data/struct.AdditionalData.html))
//!
//! All the stucts below can be constructed from `Vec<u8>`, `&[u8]`, `String`, `&str`, as well as
//! other types, as they all implement several versions of the `From` trait. Some have additional
//! constructors as well, e.g. `Salt::random(...)`, which produces a `Salt` that will create new
//! crytographically-secure, random bytes after each call to `Hasher::hash()` or `Hasher::hash_raw()`.
//!
//! Additionall, all the structs below implement the `Serialize` and `Deserialize` traits from `serde`,
//! although `Password` and `SecretKey` will serialize into empty bytes for security reasons.
//!
//! Finally, each struct below implements the `Data` trait, which provides read-only access to
//! the otherwise opaque struct's underlying bytes.
mod additional_data;
#[cfg_attr(feature = "cargo-clippy", allow(module_inception))]
mod data;
mod password;
mod salt;
mod secret_key;

pub use self::additional_data::AdditionalData;
pub use self::password::Password;
pub use self::salt::Salt;
pub use self::secret_key::SecretKey;

pub use self::data::Data;
pub(crate) use self::data::DataPrivate;
