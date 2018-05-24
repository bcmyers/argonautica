#![cfg(feature = "serde")]

extern crate a2;
extern crate serde_json;

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
