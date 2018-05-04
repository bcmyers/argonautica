extern crate a2;

#[test]
#[should_panic]
fn test_hasher_password_is_empty() {
    let mut hasher = a2::Hasher::default().unwrap();
    hasher.with_secret_key("secret");
    let _ = hasher.with_password("").hash().unwrap();
}

#[test]
#[should_panic]
fn test_hasher_salt_too_short() {
    let mut hasher = a2::Hasher::default().unwrap();
    hasher
        .with_secret_key("secret")
        .with_salt("1234567")
        .opt_out_of_random_salt();
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}
