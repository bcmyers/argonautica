//! Contains [`Error`](error/struct.Error.html) struct and [`ErrorKind`](error/enum.ErrorKind.html) enum
mod error;
mod error_kind;

pub use self::error::Error;
pub use self::error_kind::ErrorKind;
