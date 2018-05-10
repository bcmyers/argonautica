extern crate a2;

use a2::config::{Variant, Version};

pub const PASSWORDS: [&str; 2] = ["P@ssw0rd", "😊"];
pub const VARIANTS: [Variant; 3] = [Variant::Argon2d, Variant::Argon2i, Variant::Argon2id];
pub const VERSIONS: [Version; 2] = [Version::_0x10, Version::_0x13];

struct Test {
    password: String,
    variant: Variant,
    version: Version,
}

impl Test {
    fn run(self) {
        let additional_data = vec![4u8; 12];
        let secret_key = vec![3u8; 8];
        let mut hasher = a2::Hasher::default();
        hasher
            .configure_hash_length(32)
            .configure_iterations(3)
            .configure_lanes(4)
            .configure_memory_size(32)
            .configure_threads(4)
            .configure_variant(self.variant)
            .configure_version(self.version)
            .opt_out_of_random_salt()
            .with_salt(vec![2; 16])
            .opt_out_of_secret_key();
        let hash = hasher.with_password(self.password.as_str()).hash().unwrap();

        hasher.with_secret_key(secret_key.as_slice());
        let hash2 = hasher.with_password(self.password.as_str()).hash().unwrap();

        hasher.with_additional_data(additional_data.as_slice());
        let hash3 = hasher.with_password(self.password.as_str()).hash().unwrap();

        let mut verifier = a2::Verifier::new();
        verifier
            .with_hash(&hash)
            .with_password(self.password.as_str());
        let is_valid = verifier.verify().unwrap();
        assert!(is_valid);

        verifier
            .with_hash(&hash2)
            .with_password(self.password.as_str())
            .with_secret_key(secret_key.as_slice());
        let is_valid = verifier.verify().unwrap();
        assert!(is_valid);

        verifier
            .with_additional_data(additional_data.as_slice())
            .with_hash(&hash3)
            .with_password(self.password.as_str());
        let is_valid = verifier.verify().unwrap();
        assert!(is_valid);
    }
}

#[test]
fn test_verifier() {
    for password in &PASSWORDS {
        for variant in &VARIANTS {
            for version in &VERSIONS {
                Test {
                    password: password.to_string(),
                    variant: *variant,
                    version: *version,
                }.run();
            }
        }
    }
}
