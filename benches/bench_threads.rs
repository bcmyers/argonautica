extern crate a2;
#[macro_use]
extern crate criterion;
extern crate num_cpus;

use a2::config::{
    Variant, Version, DEFAULT_HASH_LENGTH, DEFAULT_ITERATIONS, DEFAULT_MEMORY_SIZE,
    DEFAULT_PASSWORD_CLEARING, DEFAULT_SALT_LENGTH, DEFAULT_SECRET_KEY_CLEARING, DEFAULT_VARIANT,
    DEFAULT_VERSION,
};
use a2::data::{Salt, SecretKey};
use a2::Hasher;
use criterion::Criterion;

const SAMPLE_SIZE: usize = 20;

const BASE64_ENCODED_SECRET_KEY: &str = "t9nGEsDxjWtJYdYeExdB6/HU0vg+rT6czv6HSjVjZng=";
const HASH_LENGTH: u32 = DEFAULT_HASH_LENGTH;
const SALT_LENGTH: u32 = DEFAULT_SALT_LENGTH;
const PASSWORD: &str = "P@ssw0rd";
const PASSWORD_CLEARING: bool = DEFAULT_PASSWORD_CLEARING;
const SECRET_KEY_CLEARING: bool = DEFAULT_SECRET_KEY_CLEARING;
const THREADS: [u32; 3] = [1, 2, 4];
const VARIANT: Variant = DEFAULT_VARIANT;
const VERSION: Version = DEFAULT_VERSION;

#[derive(Clone)]
struct Bench {
    hasher: Option<Hasher>,
    iterations: u32,
    memory_size: u32,
    threads: u32,
}

impl Bench {
    fn setup(mut self) -> Bench {
        let mut hasher = a2::Hasher::default();
        hasher
            .configure_hash_length(HASH_LENGTH)
            .configure_lanes(self.threads)
            .configure_iterations(self.iterations)
            .configure_memory_size(self.memory_size)
            .configure_password_clearing(PASSWORD_CLEARING)
            .configure_secret_key_clearing(SECRET_KEY_CLEARING)
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
