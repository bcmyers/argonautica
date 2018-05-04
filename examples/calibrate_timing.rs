extern crate a2;
extern crate failure;
extern crate num_cpus;

use std::time::Instant;

use a2::config::{Variant, Version};
use a2::data::{Salt, SecretKey};

pub const HASH_LENGTH: u32 = 32;
pub const ITERATIONS: [u32; 6] = [16, 32, 64, 128, 256, 512];
pub const MEMORY_SIZE: [u32; 6] = [512, 1_024, 2_048, 4_096, 8_192, 16_384];
pub const PASSWORD: &str = "P@ssw0rd";
pub const SALT_LENGTH: u32 = 32;
pub const VARIANT: Variant = Variant::Argon2id;
pub const VERSION: Version = Version::_0x13;

fn main() {
    run().unwrap();
}

fn run() -> Result<(), failure::Error> {
    let salt = Salt::random(SALT_LENGTH)?;
    let secret_key =
        SecretKey::from_base64_encoded_str("t9nGEsDxjWtJYdYeExdB6/HU0vg+rT6czv6HSjVjZng=")?;
    for threads in (1..num_cpus::get() + 1).filter(|x| *x == 1 || (*x).is_power_of_two()) {
        for memory_size in &MEMORY_SIZE {
            for iterations in &ITERATIONS {
                let mut hasher = a2::Hasher::default()?;
                hasher
                    .configure_hash_length(HASH_LENGTH)
                    .configure_iterations(*iterations)
                    .configure_lanes(threads as u32)
                    .configure_memory_size(*memory_size)
                    .configure_password_clearing(true)
                    .configure_secret_key_clearing(false)
                    .configure_threads(threads as u32)
                    .configure_variant(VARIANT)
                    .configure_version(VERSION)
                    .with_salt(&salt)
                    .with_secret_key(&secret_key);
                let now = Instant::now();
                let _ = hasher.with_password(PASSWORD).hash()?;
                let elapsed = now.elapsed();
                let millis = elapsed.as_secs() as f32 * 1_000_f32
                    + elapsed.subsec_nanos() as f32 / 1_000_000_f32;
                if millis > 375_f32 && millis < 625_f32 {
                    println!(
                        "👍  threads: {}, memory_size: {}, iterations: {}, millis: {:.0}",
                        threads, memory_size, iterations, millis,
                    );
                }
            }
        }
    }
    Ok(())
}
