extern crate argonautica;
extern crate dotenv;
#[macro_use]
extern crate failure;

use std::collections::HashMap;
use std::env;

use argonautica::config::{Variant, Version};
use argonautica::input::{Salt, SecretKey};
use argonautica::{Hasher, Verifier};

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
    hasher
        .configure_hash_len(32)
        .configure_iterations(192)
        .configure_lanes(1)
        .configure_memory_size(2u32.pow(12))
        .configure_password_clearing(true)
        .configure_secret_key_clearing(false)
        .configure_threads(1)
        .configure_variant(Variant::Argon2id)
        .configure_version(Version::_0x13)
        .with_salt(Salt::random(16))
        .with_secret_key(&secret_key);

    let mut dictionary = HashMap::new();
    for password in &["P@ssw0rd", "Hello world!", "123456", "😊"] {
        let hash = hasher.with_password(password.to_string()).hash()?;
        println!("{}", &hash);
        dictionary.insert(password.to_string(), hash);
    }

    let mut verifier = Verifier::new();
    verifier.with_secret_key(&secret_key);

    for (password, hash) in dictionary.into_iter() {
        let is_valid = verifier.with_hash(&hash).with_password(password).verify()?;
        assert!(is_valid);
    }

    Ok(())
}
