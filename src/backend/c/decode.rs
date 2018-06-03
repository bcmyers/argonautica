#![cfg(test)]

use output::HashRaw;
use Error;

pub(crate) fn decode_c(_hash: &str) -> Result<HashRaw, Error> {
    // TODO:
    unimplemented!();
    // let error = Error::new(ErrorKind::DataError(DataError::HashDecodeError))
    //     .add_context(format!("Hash: {}", &hash));

    // let variant_str = hash.split('$').nth(1).ok_or_else(|| error.clone())?;
    // let variant = variant_str.parse::<Variant>()?;

    // let hash_str = hash.split('$').nth(5).ok_or_else(|| error.clone())?;
    // let hash_len = base64::decode_config(hash_str, base64::STANDARD_NO_PAD)
    //     .map_err(|_| error.clone())?
    //     .len();

    // let salt_str = hash.split('$').nth(4).ok_or_else(|| error.clone())?;
    // let salt_len = base64::decode_config(salt_str, base64::STANDARD_NO_PAD)
    //     .map_err(|_| error.clone())?
    //     .len();

    // let mut hash_buffer = vec![0u8; hash_len];
    // let mut password_dummy = vec![0u8; 0];
    // let mut salt_buffer = vec![0u8; salt_len];

    // let mut context = ffi::Argon2_Context {
    //     out: hash_buffer.as_mut_ptr() as *mut u8,
    //     outlen: hash_buffer.len() as u32,
    //     pwd: password_dummy.as_mut_ptr() as *mut u8,
    //     pwdlen: password_dummy.len() as u32,
    //     salt: salt_buffer.as_mut_ptr() as *mut u8,
    //     saltlen: salt_buffer.len() as u32,
    //     secret: ::std::ptr::null_mut(),
    //     secretlen: 0,
    //     ad: ::std::ptr::null_mut(),
    //     adlen: 0,
    //     t_cost: 0,
    //     m_cost: 0,
    //     lanes: 0,
    //     threads: 1,
    //     version: 0,
    //     allocate_cbk: None,
    //     free_cbk: None,
    //     flags: 0,
    // };

    // let context_ptr = &mut context as *mut ffi::argon2_context;
    // let cstring = CString::new(hash).map_err(|_| {
    //     Error::new(ErrorKind::DataError(DataError::HashDecodeError)).add_context(format!(
    //         "Hash cannot contain an interior null byte. Hash: {}",
    //         &hash
    //     ))
    // })?;
    // let cstring_ptr = cstring.as_ptr() as *const c_char;
    // let err = unsafe { ffi::decode_string(context_ptr, cstring_ptr, variant as ffi::argon2_type) };
    // if err != 0 {
    //     return Err(Error::new(ErrorKind::DataError(DataError::HashDecodeError))
    //         .add_context(format!("Hash: {}", &hash)));
    // }
    // let hash_raw = HashRaw::new(
    //     /* iterations */ context.t_cost,
    //     /* lanes */ context.lanes,
    //     /* memory_size */ context.m_cost,
    //     /* raw_hash_bytes */ hash_buffer,
    //     /* raw_salt_bytes */ salt_buffer,
    //     /* variant */ variant,
    //     /* version */ Version::from_u32(context.version)?,
    // );
    // Ok(hash_raw)
}
