extern crate a2;

use a2::config::{Backend, Variant, Version};

fn main() {
    let mut hasher = a2::Hasher::default();
    hasher
        .configure_backend(Backend::C)
        // 👆 a2 is designed to support multiple backends. Currently only the C
        // backend is supported (meaning, under the hood, a2 uses the canonical C library
        // to actually perform the hashing agorithm), but in the future hopefully a Rust backend
        // will also be supported. For the moment, however, you must use Backend::C
        .configure_hash_length(16)
        // 👆 The hash length (in bytes) is configurable. The default is 32.
        .configure_iterations(256)
        // 👆 Argon2 has a notion of "iterations" or "time cost". All else equal, the greater
        // the number iterations, the longer it takes to perform the hash and the more secure
        // the resulting hash. This and "memory size" (see below) are, generally speaking, the two
        // main parameters to adjust in order to increase or decrease the security of your
        // hash. The default is 128 iterations, which was chosen because, along with the default
        // memory size of 4096, this number leads to a hashing time of approximately 500 milliseconds
        // on the early-2014 Macbook Air that is the developer's machine. If you're going to use
        // a2 in production, you really should tweak this parameter (and the memory size)
        // in order to increase the time it takes to hash to the maximum you can reasonably allow
        // for your use-case (e.g. to probably about 500 milliseconds for the use-case of hashing
        // user passwords for a website)
        .configure_lanes(2)
        // 👆 Argon2 can break its work up into one or more "lanes" during some parts of the
        // hashing algorithm. If you configure it with multiple lanes and you also use multiple
        // threads (see below) the hashing algorithm will be performed its work in parallel in
        // some parts, potentially speeding up the time it takes to produce a hash. By default,
        // the number of lanes is set to the number of physical cores on your machine
        .configure_memory_size(8192)
        // 👆 Argon2 asdf
        .configure_password_clearing(true)
        // 👆 Argon2 asdf
        .configure_secret_key_clearing(false)
        // 👆 Argon2 asdf
        .configure_threads(2)
        // 👆 Argon2 asdf
        .configure_variant(Variant::Argon2id)
        // 👆 Argon2 has three variants: Argon2d, Argon2i, and Argon2id. Here is how these
        // variants are explained in the RFC: "Argon2 has one primary variant: Argon2id, and two
        // supplementary variants: Argon2d and Argon2i. Argon2d uses data-dependent memory access,
        // which makes it suitable for ... applications with no threats from side-channel timing
        // attacks. Argon2i uses data-independent memory access, which is preferred for
        // password hashing and password-based key derivation. Argon2id works as Argon2i
        // for the first half of the first iteration over the memory, and as Argon2d for
        // the rest, thus providing both side-channel attack protection and brute-force
        // cost savings due to time-memory tradeoffs." If you do not know which variant to use,
        // use the default, which is Argon2id (so calling this method with Variant::Argon2id
        // does nothing)
        .configure_version(Version::_0x13)
        // 👆 Argon2 has two versions. The latest version is 0x13 (as of 5/18). Unless you have
        // a very specific reason not to, you should always use the latest version, which
        // is also the default (so calling this method with Version::_0x13 does nothing)
        .opt_out_of_random_salt()
        // 👆 If you wish to use a non-random salt, you must explicity opt out by calling this method
        .opt_out_of_secret_key();
    // 👆 If you wish to not use a secret key, you must explicity opt out by calling this method

    let hash = hasher
        .with_password("P@ssw0rd")
        .with_salt("somesalt")
        // 👆 A non-random salt, which is a bad idea, but possible
        .hash()
        .unwrap();
    // 👆 Notice we did not include a secret key, which is also a bad idea, but possible

    println!("{}", &hash);
    // 👆 prints $argon2id$v=19$m=8192,t=256,p=2$c29tZXNhbHQ$TyX+9AspmkeMGLJRQdJozQ
}
