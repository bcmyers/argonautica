extern crate a2;

#[test]
#[should_panic]
fn test_config_hash_length_too_short() {
    let mut hasher = a2::Hasher::default().unwrap();
    hasher.configure_hash_length(3).with_secret_key("secret");
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
#[should_panic]
fn test_config_memory_not_power_of_two() {
    let mut hasher = a2::Hasher::default().unwrap();
    hasher.configure_memory_size(9).with_secret_key("secret");
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
#[should_panic]
fn test_config_memory_too_short() {
    let mut hasher = a2::Hasher::default().unwrap();
    hasher.configure_memory_size(4).with_secret_key("secret");
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
#[should_panic]
fn test_config_no_opt_of_random_salt() {
    let mut hasher = a2::Hasher::default().unwrap();
    hasher.with_secret_key("secret").with_salt("somesalt");
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
#[should_panic]
fn test_config_no_opt_of_secret_key() {
    let mut hasher = a2::Hasher::default().unwrap();
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
fn test_config_opt_of_secret_key() {
    let mut hasher = a2::Hasher::default().unwrap();
    hasher.opt_out_of_secret_key();
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}

#[test]
fn test_config_opt_of_random_salt() {
    let mut hasher = a2::Hasher::default().unwrap();
    hasher
        .with_secret_key("secret")
        .with_salt("somesalt")
        .opt_out_of_random_salt();
    let _ = hasher.with_password("P@ssw0rd").hash().unwrap();
}
