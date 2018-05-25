extern crate a2;
extern crate futures_cpupool;

use a2::config::{Backend, Variant, Version};

fn main() {
    let mut hasher = a2::Hasher::default();
    hasher
        .configure_backend(Backend::C)
        // 👆 a2 was designed to support multiple backends (meaning multiple implementations
        // of the underlying Argon2 algorithm). Currently only the C backend is supported,
        // which uses the cannonical Argon2 library written in C to actually do the work.
        // In the future hopefully a Rust backend will also be supported, but, for the
        // moment, you must use Backend::C, which is the default. Using Backend::Rust will
        // result in an error (again, for the moment).
        .configure_cpu_pool(futures_cpupool::CpuPool::new(2))
        // 👆 There are two non-blocking methods on `Hasher` that perform computation on
        // a separate thread and return a `Future` instead of a `Result` (`hash_non_blocking`
        // and `hash_raw_non_blocking`). These methods allows `a2` to play nice with
        // futures-heavy code, but need a `CpuPool` in order to work. The blocking
        // methods `hash` and `hash_raw` do not use a 'CpuPool'; so if you are using only
        // these blocking methods you can ignore this configuration entirely. If, however,
        // you are using the non-blocking methods and would like to provide your own `CpuPool`
        // instead of using the default, which is `CpuPool::new(num_cpus::get_physical())`,
        // you can configure your `Hasher` with a custom `CpuPool` using this method. This
        // might be useful if, for example, you are writing code in an environment which
        // makes heavy use of futures, the code you are writing uses both a `Hasher` and
        // a `Verifier`, and you would like both of them to share the same underlying
        // `CpuPool`.
        .configure_hash_length(32)
        // 👆 The hash length in bytes is configurable. The default is 32. This is probably
        // a good number to use. 16 is also probably fine. You probably shouldn't go below 16
        .configure_iterations(128)
        // 👆 Argon2 has a notion of "iterations" or "time cost". All else equal and generally
        // speaking, the greater the number of iterations, the longer it takes to perform the
        // hash and the more secure the resulting hash. More iterations basically means more
        // CPU load. This and "memory size" (see below) are the two primary parameters to
        // adjust in order to increase or decrease the security of your hash. The default is
        // 128 iterations, which was chosen because, along with the default memory size of
        // 4096, this leads to a hashing time of approximately 500 milliseconds on the
        // early-2014 Macbook Air that is the developer's machine. If you're going to use
        // a2 in production, you should probably tweak this parameter (and the memory size
        // parameter) in order to increase the time it takes to hash to the maximum you can
        // reasonably allow for your use-case (e.g. to probably about 500 milliseconds
        // for the use-case of hashing user passwords for a website)
        .configure_lanes(2)
        // 👆 Argon2 can break up its work into one or more "lanes" during some parts of
        // the hashing algorithm. If you configure it with multiple lanes and you also
        // use multiple threads (see below) the hashing algorithm will performed its
        // work in parallel in some parts, potentially speeding up the time it takes to
        // produce a hash without diminishing the security of the result. By default,
        // the number of lanes is set to the number of physical cores on your machine
        .configure_memory_size(4096)
        // 👆 Argon2 has a notion of "memory size" or "memory cost" (in kibibytes). All else
        // equal and generally speaking, the greater the memory size, the longer it takes to
        // perform the hash and the more secure the resulting hash. More memory size basically
        // means more memory used. This and "iterations" (see above) are, again, generally
        // speaking, the two parameters to adjust in order to increase or decrease the
        // security of your hash. The default is 4096 kibibytes, which was chosen because,
        // again, along with the default iterations of 128, this leads to a hashing time of
        // approximately 500 milliseconds on the early-2014 Macbook Air that is the
        // developer's machine. If you're going to use a2 in production, you should probably
        // tweak this parameter (and the iterations parameter) in order to increase the time
        // it takes to hash to the maximum you can reasonably allow for your use-case
        // (e.g. to probably about 500 milliseconds for the use-case of hashing user passwords
        // for a website)
        .configure_password_clearing(true)
        // 👆 By default, every time you call hash or hash_raw on a Hasher, the underying
        // bytes of the password you provided are completely erased, meaning you can no
        // longer access them and will have to provide a new password to Hasher in order
        // to call hash or hash_raw again. This is a security measure designed to
        // to prevent you from keeping the password bytes around for longer than you have to.
        // Using this method, however, you can turn off this security feature by passing
        // false. This is not recommended
        .configure_secret_key_clearing(false)
        // 👆 It is also possible to have the underlying bytes of the secret key you provided
        // to a Hasher be erased after each call to hash or hash_raw. Unlike with
        // password clearing, however, this option is not turned on by default. Typically,
        // you'll want to use the same Hasher instance to hash multiple passwords. With
        // the default setting of secret key clearing set to false, you can provide your
        // Hasher with your secret key once and use it for multiple passwords. If you want
        // to be extra secure and force yourself to provide the secret key to Hasher every
        // time you hash a password, you can turn this feature on by passing true to this
        // method
        .configure_threads(2)
        // 👆 If you have configured a Hasher to use more than one lane (see above), you
        // can get the hashing algorithm to run in parallel during some parts of the
        // computation by setting the number of threads to be greater than one as well,
        // potentially speeding up the time it takes to produce a hash without diminishing
        // the security of the result. By default, the number of threads is set to the number
        // of physical cores on your machine
        .configure_variant(Variant::Argon2id)
        // 👆 Argon2 has three variants: Argon2d, Argon2i, and Argon2id. Here is how these
        // variants are explained in the RFC: "Argon2 has one primary variant: Argon2id,
        // and two supplementary variants: Argon2d and Argon2i. Argon2d uses data-dependent
        // memory access, which makes it suitable for ... applications with no threats from
        // side-channel timing attacks. Argon2i uses data-independent memory access, which
        // is preferred for password hashing and password-based key derivation. Argon2id
        // works as Argon2i for the first half of the first iteration over the memory, and
        // as Argon2d for the rest, thus providing both side-channel attack protection and
        // brute-force cost savings due to time-memory tradeoffs." If you do not know which
        // variant to use, use the default, which is Argon2id
        .configure_version(Version::_0x13)
        // 👆 Argon2 has two versions: 0x10 and 0x13. The latest version is 0x13 (as of 5/18).
        // Unless you have a very specific reason not to, you should use the latest
        // version (0x13), which is also the default
        .opt_out_of_random_salt()
        // 👆 As a built-in "safety" mechanism, if you wish to use a non-random salt,
        // which is generally not a good idea, you must explicity call this method
        // in order to allow it
        .opt_out_of_secret_key();
    // 👆 As a built-in "safety" mechanism, if you wish to hash without a secret key,
    // which is generally not a good idea, you must explicity call this method
    // in order to allow it

    let hash = hasher
        .with_password("P@ssw0rd")
        .with_salt("somesalt")
        // 👆 A non-random salt, which is a bad idea, but possible
        // because we configured this Hasher with opt_out_of_random_salt
        .hash()
        // 👆 Notice we did not include a secret key, which is also a bad idea, but possible
        // because we configured this Hasher with opt_out_of_secret_key
        .unwrap();

    println!("{}", &hash);
    // 👆 prints $argon2id$v=19$m=4096,t=128,p=2$c29tZXNhbHQ$WwD2/wGGTuw7u4BW8sLM0Q
}
