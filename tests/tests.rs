extern crate a2;
extern crate rand;
extern crate serde_json;

#[test]
#[should_panic]
fn test_config_hash_length_too_short() {
    let mut hasher = a2::Hasher::default();
    hasher.configure_hash_length(3).with_secret_key("secret");
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
#[should_panic]
fn test_config_memory_not_power_of_two() {
    let mut hasher = a2::Hasher::default();
    hasher.configure_memory_size(9).with_secret_key("secret");
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
#[should_panic]
fn test_config_memory_too_short() {
    let mut hasher = a2::Hasher::default();
    hasher.configure_memory_size(4).with_secret_key("secret");
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
#[should_panic]
fn test_config_no_opt_of_random_salt() {
    let mut hasher = a2::Hasher::default();
    hasher.with_secret_key("secret").with_salt("somesalt");
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
#[should_panic]
fn test_config_no_opt_of_secret_key() {
    let mut hasher = a2::Hasher::default();
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
fn test_config_opt_of_secret_key() {
    let mut hasher = a2::Hasher::default();
    hasher.opt_out_of_secret_key();
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
fn test_config_opt_of_random_salt() {
    let mut hasher = a2::Hasher::default();
    hasher
        .with_secret_key("secret")
        .with_salt("somesalt")
        .opt_out_of_random_salt();
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
fn test_decode() {
    use a2::output::HashRaw;
    for hash in &[
        "$argon2d$v=16$m=32,t=3,p=1$c29tZXNhbHQ$F9F9xbKM80M",
        "$argon2d$v=19$m=32,t=3,p=1$c29tZXNhbHQ$8M5O+AL7X7g",
        "$argon2i$v=16$m=32,t=3,p=1$c29tZXNhbHQ$Kq7eFUPUZVI",
        "$argon2i$v=19$m=32,t=3,p=1$c29tZXNhbHQ$4QLWhz5VaKk",
        "$argon2id$v=16$m=32,t=3,p=1$c29tZXNhbHQ$tfZjSAPJqZ0",
        "$argon2id$v=19$m=32,t=3,p=1$c29tZXNhbHQ$lYNMBkRT0DI",
    ] {
        let hash_raw = hash.parse::<HashRaw>().unwrap();
        println!("{:?}", &hash_raw);
    }
}

#[test]
#[should_panic]
fn test_hasher_password_is_empty() {
    let mut hasher = a2::Hasher::default();
    hasher.with_secret_key("secret");
    let _ = hasher.with_password("").hash().unwrap();
}

#[test]
#[should_panic]
fn test_hasher_salt_too_short() {
    let mut hasher = a2::Hasher::default();
    hasher
        .with_secret_key("secret")
        .with_salt("1234567")
        .opt_out_of_random_salt();
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
fn test_raw_hash_to_hash() {
    let additional_data = "some additional data";
    let password = "P@ssw0rd";
    let salt = "somesalt";
    let secret_key = "secret";

    let mut hasher = a2::Hasher::default();
    hasher
        .configure_hash_length(32)
        .configure_iterations(3)
        .configure_lanes(4)
        .configure_memory_size(32)
        .configure_threads(4)
        .with_additional_data(additional_data)
        .with_salt(salt)
        .with_secret_key(secret_key)
        .opt_out_of_random_salt();

    let hash_raw = hasher.with_password(password).hash_raw().unwrap();
    let hash1 = hash_raw.to_hash();

    let hash2 = hasher.with_password(password).hash().unwrap();

    assert_eq!(&hash1, &hash2);

    let mut verifier = a2::Verifier::default();

    let is_valid = verifier
        .with_additional_data(additional_data)
        .with_hash_raw(&hash_raw)
        .with_password(password)
        .with_secret_key(secret_key)
        .verify()
        .unwrap();
    assert!(is_valid);

    let is_valid = verifier
        .with_additional_data(additional_data)
        .with_hash(&hash1)
        .with_password(password)
        .with_secret_key(secret_key)
        .verify()
        .unwrap();
    assert!(is_valid);

    let is_valid = verifier
        .with_additional_data(additional_data)
        .with_hash(&hash2)
        .with_password(password)
        .with_secret_key(secret_key)
        .verify()
        .unwrap();
    assert!(is_valid);
}

#[test]
fn test_serialization() {
    let mut hasher = a2::Hasher::default();
    hasher
        .opt_out_of_random_salt()
        .with_additional_data("ad")
        .with_password("password")
        .with_secret_key("secret")
        .with_salt("somesalt");

    let j = serde_json::to_string_pretty(&hasher).expect("failed to serialize hasher");
    let mut hasher: a2::Hasher = serde_json::from_str(&j).expect("failed to deserialize hasher");

    assert!(hasher.hash_raw().is_err());

    hasher.with_password("password").with_secret_key("secret");

    let hash_raw = hasher.hash_raw().expect("failed to hash_raw");

    let j = serde_json::to_string_pretty(&hash_raw).expect("failed to serialize hash_raw");
    let hash_raw2: a2::output::HashRaw =
        serde_json::from_str(&j).expect("failed to deserialize hash_raw");

    assert_eq!(&hash_raw, &hash_raw2);

    let mut verifier = a2::Verifier::default();
    verifier
        .with_additional_data("ad")
        .with_password("password")
        .with_secret_key("secret")
        .with_hash_raw(&hash_raw2);

    let j = serde_json::to_string_pretty(&verifier).expect("failed to serialize verifier");
    let mut verifier: a2::Verifier =
        serde_json::from_str(&j).expect("failed to deserialize verifier");

    let is_valid = verifier.verify().unwrap();
    assert!(!is_valid);

    let is_valid = verifier
        .with_hash_raw(&hash_raw2)
        .with_password("password")
        .with_secret_key("secret")
        .verify()
        .expect("failed to verify");

    assert!(is_valid);
}

#[test]
fn test_asdf() {
    use rand::{Rng, SeedableRng, StdRng};
    let seed: &[_] = &[1, 2, 3, 4];
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let mut password = vec![0u8; 12];
    for _ in 0..1_000 {
        rng.fill_bytes(&mut password);
        let mut hasher = a2::Hasher::default();
        hasher
            .configure_hash_length(8)
            .configure_iterations(1)
            .configure_memory_size(32)
            .configure_threads(1)
            .configure_lanes(1)
            .with_secret_key("somesecret")
            .with_password(&password[..])
            .hash()
            .unwrap();
    }
}
