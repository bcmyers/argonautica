//! Utility functions for generating salt and secret keys

use base64;
use failure;
use rand::{OsRng, Rng};

/// A utility function for generating random salt. A quick glance at this
/// function's source code should give you a good idea of what the function is doing.
pub fn generate_salt(length: u32) -> Result<Vec<u8>, failure::Error> {
    let mut rng = OsRng::new()?;
    let mut salt = vec![0u8; length as usize];
    rng.fill_bytes(&mut salt);
    Ok(salt)
}

/// A utility function for generating a base64-encoded secret key. A quick glance at this
/// function's source code should give you a good idea of what the function is doing.
pub fn generate_secret_key(length: u32) -> Result<String, failure::Error> {
    let mut rng = OsRng::new()?;
    let mut bytes = vec![0u8; length as usize];
    rng.fill_bytes(&mut bytes);
    let output = base64::encode_config(&bytes, base64::STANDARD);
    Ok(output)
}
