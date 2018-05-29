extern crate a2;
extern crate failure;
extern crate rand;

use std::process::Command;

use a2::{Hasher, Verifier};
use rand::Rng;
use rand::distributions::Alphanumeric;

#[test]
fn test_c_version() {
    // Build C
    let success = Command::new("make")
        .arg("build")
        .current_dir("./tests/c")
        .status()
        .unwrap()
        .success();
    assert!(success);

    for _ in 0..20 {
        // Generate inputs
        let password = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .collect::<String>();

        // Run C
        let output = Command::new("./test")
            .arg(&password)
            .current_dir("./tests/c")
            .output()
            .unwrap();
        assert!(output.status.success());
        let hash1 = String::from_utf8(output.stderr).unwrap();
        println!("\n{}", &hash1);

        // Run Rust
        let salt = "somesalt";
        let mut hasher = Hasher::default();
        hasher
            .configure_password_clearing(false)
            .opt_out_of_random_salt(true)
            .opt_out_of_secret_key(true)
            .with_password(&password)
            .with_salt(salt);
        let hash2 = hasher.hash().unwrap();
        println!("{}", &hash2);

        // Compare C and Rust
        assert_eq!(hash1, hash2);
    }
}

#[test]
fn test_debug() {
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
}
