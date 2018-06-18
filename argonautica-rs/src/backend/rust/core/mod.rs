#![allow(dead_code)]

// use std::mem;

// use blake2_rfc::blake2b::Blake2b;

// use input::{Data, Salt};
use {Error, Hasher};

fn h0(_hasher: &mut Hasher) -> Result<[u8; 72], Error> {
    unimplemented!();
    //     if hasher.salt().is_random() {
    //         let len = hasher.salt().len();
    //         hasher.set_salt(Salt::random(len as u32)?);
    //     }
    //     let additional_data = hasher.additional_data();
    //     let password = hasher.password();
    //     let salt = hasher.salt();
    //     let secret_key = hasher.secret_key();
    //     let input = &[
    //         &u32_to_byte_array(hasher.config().lanes()),
    //         &u32_to_byte_array(hasher.config().hash_len()),
    //         &u32_to_byte_array(hasher.config().memory_size()),
    //         &u32_to_byte_array(hasher.config().iterations()),
    //         &u32_to_byte_array(hasher.config().version() as u32),
    //         &u32_to_byte_array(hasher.config().variant() as u32),
    //         &u32_to_byte_array(password.c_len()),
    //         password.as_bytes(),
    //         &u32_to_byte_array(salt.c_len()),
    //         salt.as_bytes(),
    //         &u32_to_byte_array(secret_key.c_len()),
    //         secret_key.as_bytes(),
    //         &u32_to_byte_array(additional_data.c_len()),
    //         additional_data.as_bytes(),
    //     ];
    //     let mut blake2b = Blake2b::new(64);
    //     for i in input {
    //         blake2b.update(i);
    //     }
    //     let mut buffer = [0u8; 72];
    //     {
    //         let buffer_slice = &mut buffer[0..64];
    //         buffer_slice.copy_from_slice(blake2b.finalize().as_bytes());
    //     }
    //     Ok(buffer)
    // }

    // #[inline(always)]
    // fn u32_to_byte_array(x: u32) -> [u8; 4] {
    //     unsafe { mem::transmute(x.to_le()) }
}

#[cfg(test)]
mod tests {
    // use super::*;

    // #[test]
    // fn test_h0() {
    //     let mut hasher = Hasher::default();
    //     hasher.with_password("P@ssw0rd").with_secret_key("secret");
    //     let output = h0(&mut hasher).unwrap();
    //     println!("{:?}", &output[..]);
    // }
}
