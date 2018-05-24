//! Contains utility functions for generating random bytes, which can be useful for generating
//! [`SecretKey`](data/struct.SecretKey.html)s, for example.
use base64;
use rand::{OsRng, RngCore};

use error::{Error, ErrorKind};

/// A utility function for generating cryptographically-secure random bytes. A quick glance at
/// this function's source should give you a good idea of what the function is doing.
pub fn generate_random_bytes(length: u32) -> Result<Vec<u8>, Error> {
    let mut rng =
        OsRng::new().map_err(|e| Error::new(ErrorKind::OsRngError).add_context(format!("{}", e)))?;
    let mut salt = vec![0u8; length as usize];
    rng.fill_bytes(&mut salt);
    Ok(salt)
}

/// A utility function for generating a cryptographically-secure, random, base64-encoded string
/// based on [standard base64 encoding](https://docs.rs/base64/0.9.1/base64/constant.STANDARD.html).
/// A quick glance at this function's source should give you a good idea of what the function is doing.
pub fn generate_random_base64_encoded_string(length: u32) -> Result<String, Error> {
    let mut rng =
        OsRng::new().map_err(|e| Error::new(ErrorKind::OsRngError).add_context(format!("{}", e)))?;
    let mut bytes = vec![0u8; length as usize];
    rng.fill_bytes(&mut bytes);
    let output = base64::encode_config(&bytes, base64::STANDARD);
    Ok(output)
}

/// A utility function for generating a cryptographically-secure, random, base64-encoded string
/// based on a custom base64 encoding (e.g. a [url-safe encoding](https://docs.rs/base64/0.9.1/base64/constant.URL_SAFE.html)).
/// A quick glance at this function's source should give you a good idea of what the
/// function is doing.
pub fn generate_random_base64_encoded_string_config(
    length: u32,
    config: base64::Config,
) -> Result<String, Error> {
    let mut rng =
        OsRng::new().map_err(|e| Error::new(ErrorKind::OsRngError).add_context(format!("{}", e)))?;
    let mut bytes = vec![0u8; length as usize];
    rng.fill_bytes(&mut bytes);
    let output = base64::encode_config(&bytes, config);
    Ok(output)
}
