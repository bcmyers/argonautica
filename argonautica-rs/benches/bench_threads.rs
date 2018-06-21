extern crate argonautica;
#[macro_use]
extern crate criterion;
extern crate num_cpus;

use argonautica::config::{
    Variant, Version, DEFAULT_HASH_LEN, DEFAULT_ITERATIONS, DEFAULT_MEMORY_SIZE, DEFAULT_SALT_LEN,
    DEFAULT_VARIANT, DEFAULT_VERSION,
};
use argonautica::input::{Salt, SecretKey};
use argonautica::Hasher;
use criterion::Criterion;

const SAMPLE_SIZE: usize = 25;

const BASE64_ENCODED_SECRET_KEY: &str = "t9nGEsDxjWtJYdYeExdB6/HU0vg+rT6czv6HSjVjZng=";
const HASH_LEN: u32 = DEFAULT_HASH_LEN;
const SALT_LEN: u32 = DEFAULT_SALT_LEN;
const PASSWORD: &str = "P@ssw0rd";
const THREADS: [u32; 2] = [2, 4];
const VARIANT: Variant = DEFAULT_VARIANT;
const VERSION: Version = DEFAULT_VERSION;

struct Bench<'a> {
    hasher: Option<Hasher<'a>>,
    iterations: u32,
    memory_size: u32,
    threads: u32,
}

impl<'a> Clone for Bench<'a> {
    fn clone(&self) -> Bench<'a> {
        let hasher = match self.hasher {
            Some(ref hasher) => Some(hasher.to_owned()),
            None => None,
        };
        Bench {
            hasher,
            iterations: self.iterations,
            memory_size: self.memory_size,
            threads: self.threads,
        }
    }
}

impl<'a> Bench<'a> {
    fn setup(mut self) -> Bench<'a> {
        let mut hasher = argonautica::Hasher::default();
        hasher
            .configure_hash_len(HASH_LEN)
            .configure_lanes(self.threads)
            .configure_iterations(self.iterations)
            .configure_memory_size(self.memory_size)
            .configure_password_clearing(false)
            .configure_secret_key_clearing(false)
            .configure_threads(self.threads)
            .configure_variant(VARIANT)
            .configure_version(VERSION)
            .with_salt(Salt::random(SALT_LEN))
            .with_secret_key(SecretKey::from_base64_encoded(BASE64_ENCODED_SECRET_KEY).unwrap());
        self.hasher = Some(hasher);
        self
    }
    fn run(self) {
        self.hasher.unwrap().with_password(PASSWORD).hash().unwrap();
    }
}

fn bench_threads(c: &mut Criterion) {
    c.bench_function_over_inputs(
        "bench_threads",
        |b, &&threads| {
            let bench = Bench {
                hasher: None,
                iterations: DEFAULT_ITERATIONS,
                memory_size: DEFAULT_MEMORY_SIZE,
                threads,
            }.setup();
            b.iter(|| bench.clone().run());
        },
        &THREADS,
    );
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = bench_threads,
}
criterion_main!(benches);
