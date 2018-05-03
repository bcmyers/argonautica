//! Structs representing data to hash, i.e. `Password`, `Salt`, `SecretKey`,
//! and `AdditionalData`, plus a trait for reading bytes

pub(crate) mod additional_data;
pub(crate) mod password;
pub(crate) mod read;
pub(crate) mod salt;
pub(crate) mod secret_key;

pub use self::additional_data::AdditionalData;
pub use self::password::Password;
pub use self::read::Read;
pub use self::salt::Salt;
pub use self::secret_key::SecretKey;
