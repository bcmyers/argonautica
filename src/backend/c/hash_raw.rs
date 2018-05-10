use failure;

use data::Data;
use ffi;
use hasher::Hasher;
use output::HashRaw;

pub(crate) fn hash_raw_c(hasher: &mut Hasher) -> Result<HashRaw, failure::Error> {
    let mut buffer = vec![0u8; hasher.config().hash_length() as usize];
    let mut context = hasher.context(&mut buffer);
    let context_ptr = &mut context as *mut ffi::Argon2_Context;
    let err = unsafe { ffi::argon2_ctx(context_ptr, hasher.config().variant() as u32) };
    check_error(err)?;
    Ok(HashRaw::new(
        /* iterations: */ hasher.config().iterations(),
        /* lanes: */ hasher.config().lanes(),
        /* memory_size: */ hasher.config().memory_size(),
        /* raw_hash_bytes: */ buffer,
        /* raw_salt_bytes: */ hasher.salt().as_bytes().to_vec(),
        /* variant: */ hasher.config().variant(),
        /* version: */ hasher.config().version(),
    ))
}

#[cfg_attr(rustfmt, rustfmt_skip)]
fn check_error(err: i32) -> Result<(), failure::Error> {
    match err {
        ffi::Argon2_ErrorCodes_ARGON2_OK => (),
        ffi::Argon2_ErrorCodes_ARGON2_OUTPUT_PTR_NULL => bail!("TODO: Argon2 error: OUTPUT_PTR_NULL"),
        ffi::Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_SHORT => bail!("TODO: Argon2 error: OUTPUT_TOO_SHORT"),
        ffi::Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_LONG => bail!("TODO: Argon2 error: OUTPUT_TOO_LONG"),
        ffi::Argon2_ErrorCodes_ARGON2_PWD_TOO_SHORT => bail!("TODO: Argon2 error: PWD_TOO_SHORT"),
        ffi::Argon2_ErrorCodes_ARGON2_PWD_TOO_LONG => bail!("TODO: Argon2 error: PWD_TOO_LONG"),
        ffi::Argon2_ErrorCodes_ARGON2_SALT_TOO_SHORT => bail!("TODO: Argon2 error: SALT_TOO_SHORT"),
        ffi::Argon2_ErrorCodes_ARGON2_SALT_TOO_LONG => bail!("TODO: Argon2 error: SALT_TOO_LONG"),
        ffi::Argon2_ErrorCodes_ARGON2_AD_TOO_SHORT => bail!("TODO: Argon2 error: AD_TOO_SHORT"),
        ffi::Argon2_ErrorCodes_ARGON2_AD_TOO_LONG => bail!("TODO: Argon2 error: AD_TOO_LONG"),
        ffi::Argon2_ErrorCodes_ARGON2_SECRET_TOO_SHORT => bail!("TODO: Argon2 error: SECRET_TOO_LONG"),
        ffi::Argon2_ErrorCodes_ARGON2_SECRET_TOO_LONG => bail!("TODO: Argon2 error: SECRET_TOO_LONG"),
        ffi::Argon2_ErrorCodes_ARGON2_TIME_TOO_SMALL => bail!("TODO: Argon2 error: TIME_TOO_SMALL"),
        ffi::Argon2_ErrorCodes_ARGON2_TIME_TOO_LARGE => bail!("TODO: Argon2 error: TIME_TOO_LARGE"),
        ffi::Argon2_ErrorCodes_ARGON2_MEMORY_TOO_LITTLE => bail!("TODO: Argon2 error: MEMORY_TOO_LITTLE"),
        ffi::Argon2_ErrorCodes_ARGON2_MEMORY_TOO_MUCH => bail!("TODO: Argon2 error: MEMORY_TOO_MUCH"),
        ffi::Argon2_ErrorCodes_ARGON2_LANES_TOO_FEW => bail!("TODO: Argon2 error: LANES_TOO_FEW"),
        ffi::Argon2_ErrorCodes_ARGON2_LANES_TOO_MANY => bail!("TODO: Argon2 error: LANES_TOO_MANY"),
        ffi::Argon2_ErrorCodes_ARGON2_PWD_PTR_MISMATCH => bail!("TODO: Argon2 error: PWD_PTR_MISMATCH"),
        ffi::Argon2_ErrorCodes_ARGON2_SALT_PTR_MISMATCH => bail!("TODO: Argon2 error: SALT_PTR_MISMATCH"),
        ffi::Argon2_ErrorCodes_ARGON2_SECRET_PTR_MISMATCH => bail!("TODO: Argon2 error: SECRET_PTR_MISMATCH"),
        ffi::Argon2_ErrorCodes_ARGON2_AD_PTR_MISMATCH => bail!("TODO: Argon2 error: AD_PTR_MISMATCH"),
        ffi::Argon2_ErrorCodes_ARGON2_MEMORY_ALLOCATION_ERROR => bail!("TODO: Argon2 error: MEMORY_ALLOCATION_ERROR"),
        ffi::Argon2_ErrorCodes_ARGON2_FREE_MEMORY_CBK_NULL => bail!("TODO: Argon2 error: FREE_MEMORY_CBK_NULL"),
        ffi::Argon2_ErrorCodes_ARGON2_ALLOCATE_MEMORY_CBK_NULL => bail!("TODO: Argon2 error: ALLOCATE_MEMORY_CBK_NULL"),
        ffi::Argon2_ErrorCodes_ARGON2_INCORRECT_PARAMETER => bail!("TODO: Argon2 error: INCORRECT_PARAMETER"),
        ffi::Argon2_ErrorCodes_ARGON2_INCORRECT_TYPE => bail!("TODO: Argon2 error: INCORRECT_TYPE"),
        ffi::Argon2_ErrorCodes_ARGON2_OUT_PTR_MISMATCH => bail!("TODO: Argon2 error: OUT_PTR_MISMATCH"),
        ffi::Argon2_ErrorCodes_ARGON2_THREADS_TOO_FEW => bail!("TODO: Argon2 error: THREADS_TOO_FEW"),
        ffi::Argon2_ErrorCodes_ARGON2_THREADS_TOO_MANY => bail!("TODO: Argon2 error: THREADS_TOO_MANY"),
        ffi::Argon2_ErrorCodes_ARGON2_MISSING_ARGS => bail!("TODO: Argon2 error: MISSING_ARGS"),
        ffi::Argon2_ErrorCodes_ARGON2_ENCODING_FAIL => bail!("TODO: Argon2 error: ENCODING_FAIL"),
        ffi::Argon2_ErrorCodes_ARGON2_DECODING_FAIL => bail!("TODO: Argon2 error: DECODING_FAIL"),
        ffi::Argon2_ErrorCodes_ARGON2_THREAD_FAIL => bail!("TODO: Argon2 error: THREAD_FAIL"),
        ffi::Argon2_ErrorCodes_ARGON2_DECODING_LENGTH_FAIL => bail!("TODO: Argon2 error: DECODING_LENGTH_FAIL"),
        ffi::Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH => bail!("TODO: Argon2 error: VERIFY_MISMATCH"),
        _ => bail!("TODO: Argon2 error: unknown"),
    }
    Ok(())
}
