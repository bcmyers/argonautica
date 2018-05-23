use error::{Error, ErrorKind};
use ffi;

pub(crate) fn check_error(err: i32) -> Result<bool, Error> {
    match err {
        ffi::Argon2_ErrorCodes_ARGON2_OK => Ok(true),
        ffi::Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH => Ok(false),
        other => Err(Error::new(ErrorKind::Bug).add_context(format!("c error code: {}", other))),
    }
}
