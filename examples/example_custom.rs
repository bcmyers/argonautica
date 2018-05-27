extern crate a2;
extern crate dotenv;
#[macro_use]
extern crate failure;

use std::collections::HashMap;
use std::env;

use a2::config::{Variant, Version};
use a2::data::{Salt, SecretKey};

// Helper method to load the secret key from a .env file. Used in `main` below.
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
    hasher
        .configure_hash_length(32)
        .configure_iterations(128)
        .configure_lanes(1)
        .configure_memory_size(2u32.pow(12))
        .configure_password_clearing(true)
        .configure_secret_key_clearing(false)
        .configure_threads(1)
        .configure_variant(Variant::Argon2id)
        .configure_version(Version::_0x13)
        .with_salt(Salt::random(16)?)
        .with_secret_key(&secret_key)
        .opt_out_of_random_salt(true);

    let mut dictionary = HashMap::new();
    for password in &["P@ssw0rd", "Hello world!", "123456", "😊"] {
        let hash = hasher.with_password(*password).hash()?;
        println!("{}", &hash);
        dictionary.insert(password.to_string(), hash);
    }

    let mut verifier = a2::Verifier::new();
    verifier.with_secret_key(&secret_key);

    for (password, hash) in dictionary.iter() {
        let is_valid = verifier
            .with_hash(hash)
            .with_password(password.as_str())
            .verify()?;
        assert!(is_valid);
    }

    Ok(())
}
