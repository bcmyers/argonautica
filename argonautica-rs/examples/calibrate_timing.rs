extern crate argonautica;
extern crate failure;
extern crate num_cpus;

use std::time::Instant;

use argonautica::config::{Variant, Version};
use argonautica::input::{Salt, SecretKey};
use argonautica::Hasher;

pub const HASH_LEN: u32 = 32;
pub const ITERATIONS: [u32; 7] = [64, 128, 192, 256, 320, 384, 448];
pub const MEMORY_SIZES: [u32; 7] = [256, 512, 1_024, 2_048, 4_096, 8_192, 16_384];
pub const PASSWORD: &str = "P@ssw0rd";
pub const SALT_LEN: u32 = 32;
pub const VARIANT: Variant = Variant::Argon2id;
pub const VERSION: Version = Version::_0x13;

fn main() -> Result<(), failure::Error> {
    let salt = Salt::random(SALT_LEN);
    let secret_key =
        SecretKey::from_base64_encoded("t9nGEsDxjWtJYdYeExdB6/HU0vg+rT6czv6HSjVjZng=")?;
    let threads = num_cpus::get();
    for memory_size in &MEMORY_SIZES {
        for iterations in &ITERATIONS {
            let mut hasher = Hasher::default();
            hasher
                .configure_hash_len(HASH_LEN)
                .configure_iterations(*iterations)
                .configure_lanes(threads as u32)
                .configure_memory_size(*memory_size)
                .configure_threads(threads as u32)
                .configure_variant(VARIANT)
                .configure_version(VERSION)
                .with_password(PASSWORD)
                .with_salt(&salt)
                .with_secret_key(&secret_key);
            let now = Instant::now();
            let _ = hasher.hash()?;
            let elapsed = now.elapsed();
            let millis =
                elapsed.as_secs() as f32 * 1_000.0 + elapsed.subsec_nanos() as f32 / 1_000_000.0;
            let ok = if millis > 300.0 && millis < 500.0 {
                "👍"
            } else {
                "💩"
            };
            println!(
                "{} threads {}, memory_size: {}, iterations: {}, milliseconds: {:.0}",
                ok, threads, memory_size, iterations, millis,
            );
        }
    }
    Ok(())
}
