//! Type-safe structs representing data to hash (i.e.
//! [`Password`](data/struct.Password.html),
//! [`Salt`](data/struct.Salt.html),
//! [`SecretKey`](data/struct.SecretKey.html), and
//! [`AdditionalData`](data/struct.AdditionalData.html))
//!
//! All the stucts below can be constructed from
//! [`Vec<u8>`](https://doc.rust-lang.org/std/vec/struct.Vec.html),
//! [`&[u8]`](https://doc.rust-lang.org/std/primitive.slice.html),
//! [`String`](https://doc.rust-lang.org/std/string/struct.String.html),
//! [`&str`](https://doc.rust-lang.org/std/primitive.str.html), as well as
//! other types, as they all implement several versions of the
//! [`From`](https://doc.rust-lang.org/std/convert/trait.From.html) trait. Some have additional
//! constructors as well, e.g. [`Salt::random(...)`](struct.Salt.html#method.random), which
//! produces a [`Salt`](struct.Salt.html) that will create new crytographically-secure,
//! random bytes after each hash.
//!
//! Finally, each struct below implements the [`Data`](trait.Data.html) trait, which
//! provides read-only access to the otherwise opaque structs' underlying bytes.
mod additional_data;
#[cfg_attr(feature = "cargo-clippy", allow(module_inception))]
mod data;
mod password;
mod salt_new;
mod salt;
mod secret_key;

pub use self::additional_data::AdditionalData;
pub use self::password::Password;
pub use self::salt::Salt;
pub use self::secret_key::SecretKey;

pub use self::data::Data;
pub(crate) use self::data::DataPrivate;

pub use self::salt_new::SaltNew;
