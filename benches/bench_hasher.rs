#![feature(test)]

extern crate a2;
extern crate test;

use a2::config::{Variant, Version};
use a2::data::{Salt, SecretKey};
use a2::Hasher;
use test::Bencher;

pub const BASE64_ENCODED_SECRET_KEY: &str = "t9nGEsDxjWtJYdYeExdB6/HU0vg+rT6czv6HSjVjZng=";
pub const HASH_LENGTH: u32 = 32;
pub const SALT_LENGTH: u32 = 32;
pub const PASSWORD: &str = "P@ssw0rd";
pub const VARIANT: Variant = Variant::Argon2id;
pub const VERSION: Version = Version::_0x13;

#[derive(Clone)]
struct Bench {
    hasher: Option<Hasher>,
    iterations: u32,
    memory_size: u32,
    threads: u32,
}

impl Bench {
    fn setup(mut self) -> Bench {
        let mut hasher = a2::Hasher::default().unwrap();
        hasher
            .configure_hash_length(HASH_LENGTH)
            .configure_lanes(self.threads)
            .configure_iterations(self.iterations)
            .configure_memory_size(self.memory_size)
            .configure_password_clearing(true)
            .configure_secret_key_clearing(false)
            .configure_threads(self.threads)
            .configure_variant(VARIANT)
            .configure_version(VERSION)
            .with_salt(Salt::random(SALT_LENGTH).unwrap())
            .with_secret_key(
                SecretKey::from_base64_encoded_str(BASE64_ENCODED_SECRET_KEY).unwrap(),
            );
        self.hasher = Some(hasher);
        self
    }
    fn run(self) {
        self.hasher.unwrap().with_password(PASSWORD).hash().unwrap();
    }
}

#[bench]
fn bench_hashing_1(b: &mut Bencher) {
    let bench = Bench {
        hasher: None,
        iterations: 128,
        memory_size: 2u32.pow(12),
        threads: 1,
    }.setup();
    b.iter(|| {
        bench.clone().run();
    });
}

#[bench]
fn bench_hashing_2(b: &mut Bencher) {
    let bench = Bench {
        hasher: None,
        iterations: 192,
        memory_size: 2u32.pow(12),
        threads: 2,
    }.setup();
    b.iter(|| {
        bench.clone().run();
    });
}
