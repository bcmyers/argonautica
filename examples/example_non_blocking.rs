extern crate a2;
extern crate dotenv;
#[macro_use]
extern crate failure;
extern crate futures;

use std::env;

use a2::data::SecretKey;
use futures::Future;

fn load_secret_key() -> Result<SecretKey, failure::Error> {
    let dotenv_path = env::current_dir()?.join("examples").join("example.env");
    dotenv::from_path(&dotenv_path).map_err(|e| format_err!("{}", e))?;
    let base64_encoded_secret_key = env::var("SECRET_KEY")?;
    Ok(SecretKey::from_base64_encoded_str(
        &base64_encoded_secret_key,
    )?)
}

fn main() -> Result<(), failure::Error> {
    let secret_key = load_secret_key()?;

    let mut hasher = a2::Hasher::default();
    let mut verifier = a2::Verifier::default();

    let future = hasher
        .with_password("P@ssw0rd")
        .with_secret_key(&secret_key)
        .hash_non_blocking()
        .and_then(|hash| {
            println!("{}", &hash);
            Ok(hash)
        })
        .and_then(|hash| {
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
