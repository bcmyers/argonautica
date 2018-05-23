//! Contains [`Error`](error/struct.Error.html) struct, [`ErrorKind`](error/enum.ErrorKind.html) enum, and [`Result`](error/type.Result.html) type
mod error;
mod error_kind;

pub use self::error::Error;
pub use self::error_kind::ErrorKind;
