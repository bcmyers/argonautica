//! [![Build Status](https://travis-ci.org/bcmyers/jasonus.svg?branch=master)](https://travis-ci.org/bcmyers/jasonus)
//! [![Crates.io](https://img.shields.io/crates/v/jasonus.svg)](https://crates.io/crates/jasonus)
//! [![Documentation](https://docs.rs/jasonus/badge.svg)](https://docs.rs/jasonus/)
//! [![Github.com](https://img.shields.io/badge/github-bcmyers%2Fjasonus-blue.svg)](http://www.github.com/bcmyers/jasonus)
//! ![License](https://img.shields.io/crates/l/jasonus.svg)
//!
//! ## Overview
//!
//! <b>jasonus</b> is a Rust crate for hashing passwords using the cryptographically-secure
//! [Argon2 hashing algorithm](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03),
//! which won the [Password Hashing Competition](https://password-hashing.net/) in 2015 and is
//! comparable to other secure hashing algorithms such as [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
//! and [scrypt](https://en.wikipedia.org/wiki/Scrypt).
//!
//! <b>jasonus</b> was designed:
//! * to be easy to use,
//! * to have robust, beginner-friendly documentation, and
//! * to (as much as possible) follow the [Rust API guidelines](https://rust-lang-nursery.github.io/api-guidelines/)
//!
//! <b>jasonus</b> was built with a simple use-case in mind: hashing passwords for storage in a
//! website's database. That said, <b>jasonus</b> is <u>"feature-complete"</u>, meaning anything you can
//! do with the cannonical [C implementation](https://github.com/P-H-C/phc-winner-argon2) of
//! Argon2 you should able to do with <b>jasonus</b>.
//!
//! <i>\* Indeed, jasonus even has a feature that even the cannonical C implementation currently lacks,
//! namely hashing with secret keys (the C implementation implements this, but doesn't expose it
//! publicly)</i>
//!
//! ## Hashing
//!
//! Hashing passwords with <b>jasonus</b> is simple.  Just instantiate a default
//! [`Hasher`](struct.Hasher.html), provide it with a password and a secret key, and then
//! call the [`hash`](struct.Hasher.html#method.hash) method.
//! ```
//! extern crate jasonus;
//!
//! use jasonus::Hasher;
//!
//! fn main() {
//!     let mut hasher = Hasher::default();
//!     let hash = hasher
//!         .with_password("P@ssw0rd")
//!         .with_secret_key("\
//!             secret key that you should really store in \
//!             an environment variable instead of in code, \
//!             but this is just an example\
//!         ")
//!         .hash()
//!         .unwrap();
//!
//!     println!("{}", &hash);
//!     // 👆 prints a hash, which will be random since the default Hasher uses a random salt
//! }
//! ```
//! ## Verifying
//!
//! Verifying passwords against a hash is equally as simple. Just instantiate a default
//! [`Verifier`](struct.Verifier.html), provide it with the password and the hash you would
//! like to compare, provide it with the secret key that was used to create the hash, and
//! then call the [`verify`](struct.Verifier.html#method.verify) method.
//! ```
//! extern crate jasonus;
//!
//! use jasonus::Verifier;
//!
//! fn main() {
//!     let mut verifier = Verifier::default();
//!     let is_valid = verifier
//!         .with_hash("
//!             $argon2id$v=19$m=4096,t=128,p=2$\
//!             539gu1a/qkTRCHKPuECV7jcRgWH/hRDjxidNdQJ7cKs$\
//!             On6oPYf4jttaWb4kRCyyffDVYkBF+R4cEBl8WADZhw0\
//!         ")
//!         .with_password("P@ssw0rd")
//!         .with_secret_key("\
//!             secret key that you should really store in \
//!             an environment variable instead of in code, \
//!             but this is just an example\
//!         ")
//!         .verify()
//!         .unwrap();
//!
//!     assert!(is_valid);
//! }
//! ```
//! ## Alternatives
//!
//! If <b>jasonus</b> isn't your cup of tea, other Rust crates that will do Argon2 hashing for you
//! include [argon2rs](https://github.com/bryant/argon2rs) and
//! [rust-argon2](https://github.com/sru-systems/rust-argon2). If you're interesting
//! in password hashing with a different algorithm,
//! [rust-bcrypt](https://github.com/Keats/rust-bcrypt) might be worth checking out.
//!
//! For what it's worth, besides API differences, <b>jasonus</b> has three key features that other
//! Rust crates currently do not:
//! * <b>jasonus</b> has the ability to create hashes with a secret key, which not even the
//!   [C implementation](https://github.com/P-H-C/phc-winner-argon2) exposes publicly
//! * <b>jasonus</b> is the only Rust crate that implements the newest Argon2 variant: Argon2id
//! * <b>jasonus</b> uses [SIMD](https://en.wikipedia.org/wiki/SIMD) instructions by default if your
//!   processor has access to them, which can lead to significantly faster hashing times
//!     * For example, on default settings, <b>jasonus</b> runs ~30% faster than other Rust crates on the
//!       developer's early-2014 Macbook, which has access to
//!       [SIMD instructions](https://software.intel.com/sites/landingpage/IntrinsicsGuide/)
//!       through
//!       [AVX1.0](https://en.wikipedia.org/wiki/Advanced_Vector_Extensions#Advanced_Vector_Extensions)
//!     * <i>Note: If for some reason you would like to turn SIMD off, compile with the
//!       </i>`without_simd`<i> feature enabled, which will be necessary if you're compiling
//!       for machines other than your own</i>
//!     * <i>Further note: [argon2rs](https://github.com/bryant/argon2rs) has a
//!       [SIMD](https://en.wikipedia.org/wiki/SIMD) feature as well, but it's currently
//!       available on nightly Rust only</i>
//!
//! ```
//! ## Configuration
//!
//! The default configurations for [`Hasher`](struct.Hasher.html) and
//! [`Verifier`](struct.Verifier.html) were chosen to be reasonably secure for the general
//! use-case of hashing passwords for storage in a website database, but if you want to use
//! <b>jasonus</b> for different reasons or if you just disagree with the chosen defaults, customizing
//! <b>jasonus</b> to meet your needs should hopefully be as easy and as intuitive as using the defaults.
//!
//! Here is an example that shows how to use [`Hasher`](struct.Hasher.html)'s custom
//! configuration options. It provides color on each of the options.
//! ```
//! extern crate jasonus;
//! extern crate futures_cpupool;
//!
//! use jasonus::Hasher;
//! use jasonus::config::{Backend, Variant, Version};
//! use futures_cpupool::CpuPool;
//!
//! fn main() {
//!     let mut hasher = Hasher::default();
//!     hasher
//!         .configure_backend(Backend::C) // Default is `Backend::C`
//!         // 👆 jasonus was designed to support multiple backends (meaning multiple implementations
//!         // of the underlying Argon2 algorithm). Currently only the C backend is supported,
//!         // which uses the cannonical Argon2 library written in C to actually do the work.
//!         // In the future hopefully a Rust backend will also be supported, but, for the
//!         // moment, you must use `Backend::C`, which is the default. Using `Backend::Rust` will
//!         // result in an error (again, for the moment).
//!         .configure_cpu_pool(CpuPool::new(2))
//!         // 👆 There are two non-blocking methods on `Hasher` that perform computation on
//!         // a separate thread and return a `Future` instead of a `Result` (`hash_non_blocking`
//!         // and `hash_raw_non_blocking`). These methods allow jasonus to play nicely with
//!         // futures-heavy code, but need a `CpuPool` in order to work. The blocking
//!         // methods `hash` and `hash_raw` do not use a 'CpuPool'; so if you are using only
//!         // these blocking methods you can ignore this configuration entirely. If, however,
//!         // you are using the non-blocking methods and would like to provide your own `CpuPool`
//!         // instead of using the default, which is a lazily created `CpuPool` with the number
//!         // of threads equal to the number of logical cores on your machine, you can
//!         // configure your `Hasher` with a custom `CpuPool` using this method. This
//!         // might be useful if, for example, you are writing code in an environment which
//!         // makes heavy use of futures, the code you are writing uses both a `Hasher` and
//!         // a `Verifier`, and you would like both of them to share the same underlying
//!         // `CpuPool`.
//!         .configure_hash_length(32) // Default is `32`
//!         // 👆 The hash length in bytes is configurable. The default is 32. This is probably
//!         // a good number to use. 16 is also probably fine. You probably shouldn't go below 16
//!         .configure_iterations(128) // Default is `128`
//!         // 👆 Argon2 has a notion of "iterations" or "time cost". All else equal and generally
//!         // speaking, the greater the number of iterations, the longer it takes to perform the
//!         // hash and the more secure the resulting hash. More iterations basically means more
//!         // CPU load. This and "memory size" (see below) are the two primary parameters to
//!         // adjust in order to increase or decrease the security of your hash. The default is
//!         // 128 iterations, which was chosen because, along with the default memory size of
//!         // 4096, this leads to a hashing time of approximately 500 milliseconds on the
//!         // early-2014 Macbook Air that is the developer's machine. If you're going to use
//!         // jasonus in production, you should probably tweak this parameter (and the memory size
//!         // parameter) in order to increase the time it takes to hash to the maximum you can
//!         // reasonably allow for your use-case (e.g. to probably about 500 milliseconds
//!         // for the use-case of hashing user passwords for a website)
//!         .configure_lanes(2) // Default is number of logical cores on your machine
//!         // 👆 Argon2 can break up its work into one or more "lanes" during some parts of
//!         // the hashing algorithm. If you configure it with multiple lanes and you also
//!         // use multiple threads (see below) the hashing algorithm will performed its
//!         // work in parallel in some parts, potentially speeding up the time it takes to
//!         // produce a hash without diminishing the security of the result. By default,
//!         // the number of lanes is set to the number of logical cores on your machine
//!         .configure_memory_size(4096) // Default is `4096`
//!         // 👆 Argon2 has a notion of "memory size" or "memory cost" (in kibibytes). All else
//!         // equal and generally speaking, the greater the memory size, the longer it takes to
//!         // perform the hash and the more secure the resulting hash. More memory size basically
//!         // means more memory used. This and "iterations" (see above) are, again, generally
//!         // speaking, the two parameters to adjust in order to increase or decrease the
//!         // security of your hash. The default is 4096 kibibytes, which was chosen because,
//!         // again, along with the default iterations of 128, this leads to a hashing time of
//!         // approximately 500 milliseconds on the early-2014 Macbook Air that is the
//!         // developer's machine. If you're going to use jasonus in production, you should probably
//!         // tweak this parameter (and the iterations parameter) in order to increase the time
//!         // it takes to hash to the maximum you can reasonably allow for your use-case
//!         // (e.g. to probably about 500 milliseconds for the use-case of hashing user passwords
//!         // for a website)
//!         .configure_password_clearing(false) // Default is `false`
//!         // 👆 It is possible to have the underlying bytes of the password you provided
//!         // to `Hasher` be erased after each call to `hash`, `hash_raw` or their non-blocking
//!         // equivalents. If you want this extra security feature, set this configuration
//!         // to `true` (the default is `false`). If you set this configuration to `true`,
//!         // you will be required to provide `Hasher` with an owned password (e.g.
//!         // a `String` or a `Vec<u8>` instead of a `&str` or a `&[u8]`), since the only way
//!         // `Hasher` can ensure all the underlying bytes of the password are indeed
//!         // erased is to own the data
//!         .configure_secret_key_clearing(false) // Default is `false`
//!         // 👆 It is also possible to have the underlying bytes of the secret key you provided
//!         // to `Hasher` be erased after each call to `hash`, `hash_raw` or their non-blocking
//!         // equivalents. If you want this extra security feature, set this configuration
//!         // to `true` (the default is `false`). If you set this configuration to `true`,
//!         // you will be required to provide `Hasher` with an owned secret key (e.g.
//!         // a `String` or a `Vec<u8>` instead of a `&str` or a `&[u8]`), since the only way
//!         // `Hasher` can ensure all the underlying bytes of the secret key are indeed
//!         // erased is to own the data
//!         .configure_threads(2) // Default is number of logical cores on your machine
//!         // 👆 If you have configured `Hasher` to use more than one lane (see above), you
//!         // can get the hashing algorithm to run in parallel during some parts of the
//!         // computation by setting the number of threads to be greater than one as well,
//!         // potentially speeding up the time it takes to produce a hash without diminishing
//!         // the security of the result. By default, the number of threads is set to the number
//!         // of logical cores on your machine. If you set the number of threads to a number
//!         // greater than the number of lanes, `Hasher` will automatically reduce the number
//!         // of threads to the number of lanes
//!         .configure_variant(Variant::Argon2id) // Default is `Variant::Argon2id`
//!         // 👆 Argon2 has three variants: Argon2d, Argon2i, and Argon2id. Here is how these
//!         // variants are explained in the RFC: "Argon2 has one primary variant: Argon2id,
//!         // and two supplementary variants: Argon2d and Argon2i. Argon2d uses data-dependent
//!         // memory access, which makes it suitable for ... applications with no threats from
//!         // side-channel timing attacks. Argon2i uses data-independent memory access, which
//!         // is preferred for password hashing and password-based key derivation. Argon2id
//!         // works as Argon2i for the first half of the first iteration over the memory, and
//!         // as Argon2d for the rest, thus providing both side-channel attack protection and
//!         // brute-force cost savings due to time-memory tradeoffs." If you do not know which
//!         // variant to use, use the default, which is Argon2id
//!         .configure_version(Version::_0x13) // Default is `Version::_0x13`
//!         // 👆 Argon2 has two versions: 0x10 and 0x13. The latest version is 0x13 (as of 5/18).
//!         // Unless you have a very specific reason not to, you should use the latest
//!         // version (0x13), which is also the default
//!         .opt_out_of_random_salt(true) // Default is `false`
//!         // 👆 As a built-in security mechanism, if you wish to use a non-random salt,
//!         // which is generally not a good idea, you must explicity call this method
//!         // with `true` in order to allow it
//!         .opt_out_of_secret_key(true); // Default is `false`
//!         // 👆 As a built-in security mechanism, if you wish to hash without a secret key,
//!         // which is generally not a good idea, you must explicity call this method
//!         // with `true` in order to allow it
//!
//!     let hash = hasher
//!         .with_password("P@ssw0rd")
//!         .with_salt("somesalt")
//!         // 👆 A non-random salt, which is a bad idea, but possible because we configured
//!         // `Hasher` with `opt_out_of_random_salt(true)`
//!         .hash()
//!         // 👆 Notice we did not include a secret key, which is also a bad idea, but possible
//!         // because we configured `Hasher` with `opt_out_of_secret_key(true)`
//!         .unwrap();
//!
//!     println!("{}", &hash);
//!     // 👆 prints $argon2id$v=19$m=4096,t=128,p=2$c29tZXNhbHQ$WwD2/wGGTuw7u4BW8sLM0Q
//! }
//! ```
//! ## Installation
//!
//! <b>jasonus</b> should be relatively straightforward to include in your Rust project:
//! * Place `extern crate jasonus;` in your code (typically in either `lib.rs` or `main.rs`)
//! * Place the following in the `[dependencies]` section of your `Cargo.toml`:
//!     * `jasonus = "0.1.0"`, or
//!     * `jasonus = { version = "0.1.0", features = ["serde"] }`</br>
//!     (The optional serde feature allows you to serialize / deserialize structs and
//!     enums from <b>jasonus</b> using the [serde](https://github.com/serde-rs/serde) ecosystem).
//!
//! That said, <b>jasonus</b> uses [cc](https://github.com/alexcrichton/cc-rs) and
//! [bindgen](https://github.com/rust-lang-nursery/rust-bindgen) to compile the cannonical
//! [C implemenation](https://github.com/P-H-C/phc-winner-argon2) of Argon2 into a
//! static archive during the build process. This means you need a C compiler on your
//! machine in order to build <b>jasonus</b>. More specifically, you need:
//! * [LLVM/Clang](https://llvm.org/) (version 3.9 or higher)
//!     * Mac OS: `brew install llvm`, which requires [Homebrew](https://brew.sh/)
//!     * Debian-based linux: `apt-get install llvm-[version]-dev libclang-[version]-dev clang-[version]`
//!     * Arch linux: `pacman -S clang`
//!     * Windows: Download a pre-built binary [here](http://releases.llvm.org/download.html)
//!
//! <b>jasonus</b> runs on stable Rust version 1.26.0 or greater.
//!
//! ## License
//!
//! <b>jasonus</b> is licensed under either of:
//! * [The Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0), or
//! * [The MIT license](http://opensource.org/licenses/MIT)
//!
//! at your option.

#![warn(
    missing_debug_implementations, missing_docs, unused_imports, unused_unsafe, unused_variables
)] // TODO
#![doc(html_root_url = "https://docs.rs/jasonus/0.1.0")]

extern crate base64;
#[macro_use]
extern crate bitflags;
#[cfg(feature = "development")]
extern crate blake2_rfc;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate futures_cpupool;
extern crate libc;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
extern crate num_cpus;
extern crate rand;
extern crate scopeguard;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;
#[cfg(all(test, feature = "serde"))]
extern crate serde_json;

mod backend;
mod error;
mod error_kind;
mod ffi;
mod hasher;
mod verifier;

pub mod config;
pub mod errors;
pub mod external;
pub use error::Error;
pub use error_kind::ErrorKind;
pub use hasher::Hasher;
pub mod input;
pub mod output;
pub mod utils;
pub use verifier::Verifier;

// TODO: Change password clearing default
// TODO: Python
// TODO: External
// TODO: Logging
// TODO: SQLite database for Actix-web example
// TODO: Wasm?
