extern crate argonautica;
extern crate dotenv;
#[macro_use]
extern crate failure;
extern crate futures;

use std::env;

use argonautica::input::SecretKey;
use argonautica::{Hasher, Verifier};
use futures::Future;

// Helper method to load the secret key from a .env file. Used in `main` below.
fn load_secret_key() -> Result<SecretKey<'static>, failure::Error> {
    let dotenv_path = env::current_dir()?.join("examples").join("example.env");
    dotenv::from_path(&dotenv_path).map_err(|e| format_err!("{}", e))?;
    let base64_encoded_secret_key = env::var("SECRET_KEY")?;
    Ok(SecretKey::from_base64_encoded(&base64_encoded_secret_key)?)
}

fn main() -> Result<(), failure::Error> {
    let secret_key = load_secret_key()?;

    let mut hasher = Hasher::default();
    let mut verifier = Verifier::default();

    let future = hasher
        .with_password("P@ssw0rd")
        .with_secret_key(&secret_key)
        .hash_non_blocking()
        .and_then(|hash| {
            println!("{}", &hash);
            verifier
                .with_hash(&hash)
                .with_password("P@ssw0rd")
                .with_secret_key(&secret_key)
                .verify_non_blocking()
        })
        .and_then(|is_valid| {
            assert!(is_valid);
            Ok(())
        })
        .map_err(|e| e.into());

    future.wait()
}
