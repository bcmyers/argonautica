extern crate a2;
extern crate base64;
extern crate failure;

use a2::Argon2Builder;
use a2::parameters::{Salt, SecretKey}}

fn main() {
    run().unwrap();
}

fn run() -> Result<(), failure::Error> {
    let secret_key_str = "secretstuff";
    let base64_encoded_secret_key = base64::encode(secret_key_str);
    let secret_key = SecretKey::Base64EncodedString(base64_encoded_secret_key);

    let salt_str = "somesalt";
    let base64_encoded_salt = base64::encode(salt_str);
    let salt = Salt::from_base64_encoded_str(&base64_encoded_salt)?;

    let argon2 = Argon2Builder::default()
        .with_secret_key(secret_key)
        .with_salt(salt)
        .opt_out_of_random_salt()
        .build()?;
    let password = "P@ssw0rd";
    let hash = argon2.hash(password)?;
    println!("{:?}", hash);
    Ok(())
}
