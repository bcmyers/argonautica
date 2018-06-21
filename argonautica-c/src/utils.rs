#![allow(non_camel_case_types)]

use itoa;
use libc::{c_int, uint32_t};

use argonautica_variant_t;

fn base64_len(len: uint32_t) -> usize {
    let bits = 8 * len as usize;
    let chars = bits / 6 + if bits % 6 != 0 { 1 } else { 0 };
    chars
}

/// Function that returns the length of a string-encoded hash (in bytes and including the NULL byte).
/// If an error occurrs, the function returns -1
#[no_mangle]
pub extern "C" fn argonautica_encoded_len(
    hash_len: uint32_t,
    iterations: uint32_t,
    lanes: uint32_t,
    memory_size: uint32_t,
    salt_len: uint32_t,
    variant: argonautica_variant_t,
) -> c_int {
    let mut buf = [0u8; 1024];

    let fixed_len = 17; // $$$$$v=19m=t=p=,,
    let hash_len = base64_len(hash_len);
    let iterations_len = match itoa::write(&mut buf[..], iterations) {
        Ok(bytes_written) => bytes_written,
        Err(_) => return -1,
    };
    let lanes_len = match itoa::write(&mut buf[..], lanes) {
        Ok(bytes_written) => bytes_written,
        Err(_) => return -1,
    };
    let memory_size_len = match itoa::write(&mut buf[..], memory_size) {
        Ok(bytes_written) => bytes_written,
        Err(_) => return -1,
    };
    let salt_len = base64_len(salt_len);
    let variant_len = match variant {
        argonautica_variant_t::ARGONAUTICA_ARGON2D => 7,
        argonautica_variant_t::ARGONAUTICA_ARGON2I => 7,
        argonautica_variant_t::ARGONAUTICA_ARGON2ID => 8,
    };
    let null_byte_len = 1;

    (fixed_len
        + iterations_len
        + hash_len
        + lanes_len
        + memory_size_len
        + salt_len
        + variant_len
        + null_byte_len) as c_int
}

#[cfg(test)]
mod tests {
    use super::*;
    use argonautica::Hasher;

    fn test(
        hash_len: u32,
        iterations: u32,
        lanes: u32,
        memory_size: u32,
        salt_len: u32,
        variant: argonautica_variant_t,
    ) {
        let computed =
            argonautica_encoded_len(hash_len, iterations, lanes, memory_size, salt_len, variant);
        let expected = {
            let mut hasher = Hasher::default();
            let encoded = hasher
                .configure_hash_len(hash_len)
                .configure_iterations(iterations)
                .configure_lanes(lanes)
                .configure_memory_size(memory_size)
                .configure_variant(variant.into())
                .opt_out_of_secret_key(true)
                .with_password("P@ssw0rd")
                .with_salt(vec![1u8; salt_len as usize])
                .hash()
                .unwrap();
            (encoded.as_bytes().len() + 1) as c_int
        };
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_encoded_len() {
        for hash_len in &[8, 32, 256] {
            for iterations in &[1, 11, 111] {
                for (lanes, memory_size) in &[(1, 8), (11, 128), (111, 4096)] {
                    for salt_len in &[8, 32, 256] {
                        for variant in &[
                            argonautica_variant_t::ARGONAUTICA_ARGON2D,
                            argonautica_variant_t::ARGONAUTICA_ARGON2I,
                            argonautica_variant_t::ARGONAUTICA_ARGON2ID,
                        ] {
                            test(
                                *hash_len,
                                *iterations,
                                *lanes,
                                *memory_size,
                                *salt_len,
                                *variant,
                            );
                        }
                    }
                }
            }
        }
    }
}
