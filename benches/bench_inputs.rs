#[macro_use]
extern crate criterion;
extern crate jasonus;
extern crate num_cpus;

use criterion::Criterion;
use jasonus::config::{Variant, Version, DEFAULT_HASH_LENGTH, DEFAULT_SALT_LENGTH, DEFAULT_VARIANT,
                      DEFAULT_VERSION};
use jasonus::data::{Salt, SecretKey};
use jasonus::Hasher;

const SAMPLE_SIZE: usize = 5;

#[derive(Debug)]
struct Config {
    iterations: u32,
    memory_size: u32,
}

impl Config {
    fn iterations(&self) -> u32 {
        self.iterations
    }
    fn memory_size(&self) -> u32 {
        self.memory_size
    }
}

const INPUTS: [Config; 25] = [
    Config {
        iterations: 64,
        memory_size: 512,
    },
    Config {
        iterations: 64,
        memory_size: 1024,
    },
    Config {
        iterations: 64,
        memory_size: 2048,
    },
    Config {
        iterations: 64,
        memory_size: 4096,
    },
    Config {
        iterations: 64,
        memory_size: 8192,
    },
    Config {
        iterations: 96,
        memory_size: 512,
    },
    Config {
        iterations: 96,
        memory_size: 1024,
    },
    Config {
        iterations: 96,
        memory_size: 2048,
    },
    Config {
        iterations: 96,
        memory_size: 4096,
    },
    Config {
        iterations: 96,
        memory_size: 8192,
    },
    Config {
        iterations: 128,
        memory_size: 512,
    },
    Config {
        iterations: 128,
        memory_size: 1024,
    },
    Config {
        iterations: 128,
        memory_size: 2048,
    },
    Config {
        iterations: 128,
        memory_size: 4096,
    },
    Config {
        iterations: 128,
        memory_size: 8192,
    },
    Config {
        iterations: 192,
        memory_size: 512,
    },
    Config {
        iterations: 192,
        memory_size: 1024,
    },
    Config {
        iterations: 192,
        memory_size: 2048,
    },
    Config {
        iterations: 192,
        memory_size: 4096,
    },
    Config {
        iterations: 192,
        memory_size: 8192,
    },
    Config {
        iterations: 256,
        memory_size: 512,
    },
    Config {
        iterations: 256,
        memory_size: 1024,
    },
    Config {
        iterations: 256,
        memory_size: 2048,
    },
    Config {
        iterations: 256,
        memory_size: 4096,
    },
    Config {
        iterations: 256,
        memory_size: 8192,
    },
];

const BASE64_ENCODED_SECRET_KEY: &str = "t9nGEsDxjWtJYdYeExdB6/HU0vg+rT6czv6HSjVjZng=";
const HASH_LENGTH: u32 = DEFAULT_HASH_LENGTH;
const SALT_LENGTH: u32 = DEFAULT_SALT_LENGTH;
const PASSWORD: &str = "P@ssw0rd";
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
        let mut hasher = jasonus::Hasher::default();
        hasher
            .configure_hash_length(HASH_LENGTH)
            .configure_lanes(self.threads)
            .configure_iterations(self.iterations)
            .configure_memory_size(self.memory_size)
            .configure_password_clearing(false)
            .configure_secret_key_clearing(false)
            .configure_threads(self.threads)
            .configure_variant(VARIANT)
            .configure_version(VERSION)
            .with_salt(Salt::random(SALT_LENGTH))
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

fn bench_inputs(c: &mut Criterion) {
    c.bench_function_over_inputs(
        "bench_inputs",
        |b, &input| {
            let iterations = input.iterations();
            let memory_size = input.memory_size();
            let bench = Bench {
                hasher: None,
                iterations,
                memory_size,
                threads: num_cpus::get_physical() as u32,
            }.setup();
            b.iter(|| bench.clone().run());
        },
        &INPUTS,
    );
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = bench_inputs,
}
criterion_main!(benches);
