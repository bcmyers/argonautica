extern crate argonautica;
extern crate futures_cpupool;

use argonautica::Hasher;
use argonautica::config::{Backend, Variant, Version};
use futures_cpupool::CpuPool;

fn main() {
    let mut hasher = Hasher::default();
    hasher
        .configure_backend(Backend::C)
        .configure_cpu_pool(CpuPool::new(2))
        .configure_hash_length(16)
        .configure_iterations(192)
        .configure_lanes(2)
        .configure_memory_size(4096)
        .configure_opt_out_of_secret_key(true)
        .configure_password_clearing(false)
        .configure_secret_key_clearing(false)
        .configure_threads(2)
        .configure_variant(Variant::Argon2id)
        .configure_version(Version::_0x13);

    let hash = hasher
        .with_password("P@ssw0rd")
        .with_salt("somesalt")
        .hash()
        .unwrap();

    println!("{}", &hash);
}
