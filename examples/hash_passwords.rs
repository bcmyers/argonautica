extern crate a2;
extern crate dotenv;
extern crate failure;
#[macro_use]
extern crate lazy_static;

use std::env;

use a2::config::Variant;
use a2::data::{SecretKey};

lazy_static! {
    static ref BASE64_ENCODED_SECRET_KEY: String = {
        let dotenv_path = env::current_dir()
            .expect("failed to get current directory")
            .join("examples")
            .join("example.env");
        dotenv::from_path(&dotenv_path).expect("failed to load dotenv file");
        env::var("SECRET_KEY").expect("failed to get SECRET_KEY environment variable")
    };
}

fn main() {
    run().unwrap();
}

fn run() -> Result<(), failure::Error> {
    let password = "😂😂😂😂😂😂😂😂😂😂";
    let secret_key = SecretKey::from_base64_encoded_str(&*BASE64_ENCODED_SECRET_KEY)?;

    let mut hasher = a2::Hasher::default()?;
    let hash = hasher
        .configure_variant(Variant::Argon2id)
        .with_password(password)
        .with_secret_key(&secret_key)
        .hash()?;
    println!("{}", &hash);

    let mut verifier = a2::Verifier::new();
    let is_valid = verifier
        .with_hash(&hash)
        .with_password(password)
        .with_secret_key(&secret_key)
        .verify()?;

    assert!(is_valid);
    Ok(())
}

// TODO with_hash_raw
