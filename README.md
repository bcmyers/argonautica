# a2

[![Build Status](https://travis-ci.org/bcmyers/a2.svg?branch=master)](https://travis-ci.org/bcmyers/a2)
[![Crates.io](https://img.shields.io/crates/v/a2.svg)](https://crates.io/crates/a2)
[![Documentation](https://docs.rs/a2/badge.svg)](https://docs.rs/a2/)
[![Github.com](https://img.shields.io/badge/github-bcmyers%2Fa2-blue.svg)](http://www.github.com/bcmyers/a2)
![License](https://img.shields.io/crates/l/a2.svg)

### Overview

`a2` is a Rust crate for hashing passwords using the cryptographically-secure
[Argon2 hashing algorithm](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03),
which won the [Password Hashing Competition](https://password-hashing.net/) in 2015 and is
comparable to other secure hashing algorithms such as [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
and [scrypt](https://en.wikipedia.org/wiki/Scrypt).

`a2` was designed:

* to be easy to use,
* to have robust, beginner-friendly documentation,
* to use sensible defaults, and
* to (as much as possible), follow the [Rust API guidelines](https://rust-lang-nursery.github.io/api-guidelines/)

The library was built with a simple use-case in mind: hashing passwords for storage in a database.
That said, `a2` is also feature-complete, meaning you should be able to to anything
with `a2` that you can do with the cannonical [C implementation](https://github.com/P-H-C/phc-winner-argon2)
of Argon2.

### Hashing

Hashing passwords with `a2` is simple. Just instantiate a default [`Hasher`](struct.Hasher.html), provide it
with a password and a secret key, and then call the [`hash`](struct.Hasher.html#method.hash) method.

```rust
extern crate a2;

fn main() {
    let mut hasher = a2::Hasher::default();
    let hash = hasher
        .with_password("P@ssw0rd")
        .with_secret_key("\
            secret key that you should really store in \
            an environment variable instead of in code, \
            but this is just an example\
        ")
        .hash()
        .unwrap();
    println!("{}", &hash);
    // 👆 prints a hash, which will be random since the default Hasher uses a random salt
}
```

### Verifying

Verifying passwords against a hash is equally as simple. Just instantiate a
default [`Verifier`](struct.Verifier.html), provide it with the password and the hash you would like to compare,
provide it with the secret key that was used to create the hash, and then call the [`verify`](struct.Verifier.html#method.verify)
method.

```rust
extern crate a2;

fn main() {
    let mut verifier = a2::Verifier::default();
    let is_valid = verifier
        .with_hash("\
           $argon2id$v=19$m=4096,t=128,p=2\
           $IyOw2pHShVfLBeCtdpQbtzLrlL9mxdUhwtMbSqow4u8\
           $w9SjhB3X2Dzbz62eJNqN/FcoHslse27cmGfuxzofHDc\
        ")
        .with_password("P@ssw0rd")
        .with_secret_key("\
            secret key that you should really store in \
            an environment variable instead of in code, \
            but this is just an example\
        ")
        .verify()
        .unwrap();
    assert!(is_valid);
}
```

### Configuration

The default configurations for [`Hasher`](struct.Hasher.html) and [`Verifier`](struct.Verifier.html) were chosen to be reasonably secure for
the general use-case of hashing passwords for storage in a website database, but if you want to use
`a2` for a different use-case or if you just disagree with the chosen defaults, customizing
`a2` to meet your needs should hopefully as easy and as intuitive as using the defaults.

Here is an example that shows how to use [`Hasher`](struct.Hasher.html)'s custom configuration options. It provides
color on each of the options.

```rust
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
```

### Installation

`a2` should be relatively straightforward to include in your Rust project:

* Place `extern crate a2;` in your code (typically in either `lib.rs` or `main.rs`)
* Place the following in the `[dependencies]` section of your `Cargo.toml`:
  * `a2 = "0.1.0"`, <b>or</b>
  * `a2 = { version = "0.1.0", features = ["serde"] }`</br>
    (The optional serde feature allows you to serialize or deserialize structs and
    enums from `a2` using the [serde](https://github.com/serde-rs/serde) ecosystem).

That said, `a2` uses [cc](https://github.com/alexcrichton/cc-rs) to compile the cannonical
[C implemenation](https://github.com/P-H-C/phc-winner-argon2) of Argon2 into a
static archive during the build process. This means that you need a C compiler on your
machine in order to build `a2`. I can anticipate this causing issues for some users.
At the moment, all I can say is please submit an issue if `a2` fails to build on your machine and
I'll try to look into it, but to be honest, compiling C programs is not really an area of expertise
for me (so if anyone wants to help out in this area, that would be much appreciated!).

`a2` runs on stable Rust and requires Rust version 1.26.0 or greater.

### Alternatives

If `a2` isn't your cup of tea, other Rust crates that will do Argon2 hashing for you
include [argon2rs](https://github.com/bryant/argon2rs) and [rust-argon2](https://github.com/sru-systems/rust-argon2).
As already mentioned, there's also a cannonical [C implementation](https://github.com/P-H-C/phc-winner-argon2),
which `a2` actually uses under the hood if you're using the C backend. Finally, if you're interesting
in password hashing with a different algorithm, [rust-bcrypt](https://github.com/Keats/rust-bcrypt)
might be worth checking out.

For what it's worth, besides API differences, one thing `a2` focuses on relative to other similar
libraries is the ability to easily create hashes using a secret key. Your mileage may vary,
but the crate's author found it somewhat difficult to create hashes using a secret key when
experimenting with alternative Rust libraries.

License: MIT/Apache-2.0
