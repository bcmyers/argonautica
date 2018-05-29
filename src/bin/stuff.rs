extern crate a2;
extern crate failure;

use a2::{Hasher, Verifier};

fn main() -> Result<(), failure::Error> {
    let _hash =
        "$argon2id$v=19$m=4096,t=128,p=4$c29tZXNhbHQ$2st2qT80k6JAjYvcW2I2mXmW1Jp+pNOqpJZxv5vGEUw";

    let additional_data = "additional data";
    let password = "P@ssw0rd";
    let salt = "somesalt";
    let secret_key = "secret1";

    let mut hasher = Hasher::default();
    hasher
        .configure_password_clearing(false)
        .opt_out_of_random_salt(true)
        .with_additional_data(additional_data)
        .with_password(password)
        .with_secret_key(secret_key)
        .with_salt(salt);
    let hash_raw = hasher.hash_raw().unwrap();

    let mut verifier1 = Verifier::default();
    verifier1
        .configure_password_clearing(false)
        .with_additional_data(additional_data)
        .with_hash_raw(&hash_raw)
        .with_password(password)
        .with_secret_key(secret_key);
    let is_valid = verifier1.verify().unwrap();
    if !is_valid {
        panic!(
            "\nverifier1:\n{:#?}\nAdditional Data: {:?}\nHash: {}\nPassword: {:?}\nSecret key: {:?}",
            verifier1,
            "additional data".as_bytes(),
            hash_raw.to_hash(),
            password.as_bytes(),
            "secret1".as_bytes()
        );
    };
    Ok(())
}
