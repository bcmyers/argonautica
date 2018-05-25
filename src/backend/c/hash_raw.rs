use backend::c::check_error;
use data::Data;
use hasher::Hasher;
use output::HashRaw;
use {ffi, Error};

pub(crate) fn hash_raw_c(hasher: &mut Hasher) -> Result<HashRaw, Error> {
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
