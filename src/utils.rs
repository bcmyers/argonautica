//! Functions for generating random bytes (useful for generating `SecretKey`s, for example)

use base64;
use failure;
use rand::{OsRng, Rng};

/// A utility function for generating cryptographically-secure random bytes. A quick glance at
/// this function's source should give you a good idea of what the function is doing.
pub fn generate_random_bytes(length: u32) -> Result<Vec<u8>, failure::Error> {
    let mut rng = OsRng::new()?;
    let mut salt = vec![0u8; length as usize];
    rng.fill_bytes(&mut salt);
    Ok(salt)
}

/// A utility function for generating a cryptographically-secure random base64-encoded string.
/// A quick glance at this function's source should give you a good idea of what the
/// function is doing.
pub fn generate_random_base64_encoded_string(length: u32) -> Result<String, failure::Error> {
    let mut rng = OsRng::new()?;
    let mut bytes = vec![0u8; length as usize];
    rng.fill_bytes(&mut bytes);
    let output = base64::encode_config(&bytes, base64::STANDARD);
    Ok(output)
}
