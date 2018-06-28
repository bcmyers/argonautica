//! [![Build Status](https://travis-ci.org/bcmyers/argonautica.svg?branch=master)](https://travis-ci.org/bcmyers/argonautica)
//! [![Crates.io](https://img.shields.io/crates/v/argonautica.svg)](https://crates.io/crates/argonautica)
//! [![Documentation](https://docs.rs/argonautica/badge.svg)](https://docs.rs/argonautica/)
//! [![Github.com](https://img.shields.io/badge/github-bcmyers%2Fargonautica-blue.svg)](http://www.github.com/bcmyers/argonautica)
//! ![License](https://img.shields.io/crates/l/argonautica.svg)
//!
//! # Overview
//!
//! <b>argonautica</b> is a Rust crate for hashing passwords using the cryptographically-secure
//! [Argon2 hashing algorithm](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03).
//!
//! [Argon2]((https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03)) won the
//! [Password Hashing Competition](https://password-hashing.net/) in 2015, a several
//! year project to identify a successor to [bcrypt](https://en.wikipedia.org/wiki/Bcrypt),
//! [scrypt](https://en.wikipedia.org/wiki/Scrypt), and other common cryptographically-secure
//! hashing algorithms.
//!
//! The <b>argonautica</b> crate was designed:
//! * to be easy to use,
//! * to have robust, beginner-friendly documentation, and
//! * to (as much as possible) follow the
//!   [Rust API guidelines](https://rust-lang-nursery.github.io/api-guidelines/)
//!
//! <b>argonautica</b> was built with a simple use-case in mind: hashing passwords for storage in a
//! website's database. That said, it's also "feature-complete", meaning anything you can do with
//! the cannonical [C implementation](https://github.com/P-H-C/phc-winner-argon2) of Argon2
//! you can do with argonautica*.
//!
//! <i>\* Indeed, argonautica has a feature that even the cannonical C implementation
//! lacks, i.e. hashing passwords with secret keys (the C implementation implements this, but
//! does not expose it publicly)</i>
//!
//! # Hashing
//!
//! Hashing passwords with <b>argonautica</b> is simple.  Just instantiate a default
//! [`Hasher`](struct.Hasher.html), provide it with a password and a secret key, and then
//! call the [`hash`](struct.Hasher.html#method.hash) method.
//! ```
//! extern crate argonautica;
//!
//! use argonautica::Hasher;
//!
//! fn main() {
//!     let mut hasher = Hasher::default();
//!     let hash = hasher
//!         .with_password("P@ssw0rd")
//!         .with_secret_key("\
//!             secret key that you should really store in a .env file \
//!             instead of in code, but this is just an example\
//!         ")
//!         .hash()
//!         .unwrap();
//!
//!     println!("{}", &hash);
//!     // 👆 prints a hash, which will be random since the default Hasher uses a random salt
//! }
//! ```
//! # Verifying
//!
//! Verifying passwords against a hash is equally as simple. Just instantiate a default
//! [`Verifier`](struct.Verifier.html), provide it with the password and the hash you would
//! like to compare, provide it with the secret key that was used to create the hash, and
//! then call the [`verify`](struct.Verifier.html#method.verify) method.
//! ```
//! extern crate argonautica;
//!
//! use argonautica::Verifier;
//!
//! fn main() {
//!     let mut verifier = Verifier::default();
//!     let is_valid = verifier
//!         .with_hash("
//!             $argon2id$v=19$m=4096,t=192,p=4$\
//!             o2y5PU86Vt+sr93N7YUGgC7AMpTKpTQCk4tNGUPZMY4$\
//!             yzP/ukZRPIbZg6PvgnUUobUMbApfF9RH6NagL9L4Xr4\
//!         ")
//!         .with_password("P@ssw0rd")
//!         .with_secret_key("\
//!             secret key that you should really store in a .env file \
//!             instead of in code, but this is just an example\
//!         ")
//!         .verify()
//!         .unwrap();
//!
//!     assert!(is_valid);
//! }
//! ```
//! # Alternatives
//!
//! If <b>argonautica</b> isn't your cup of tea, other Rust crates that will do Argon2 hashing for you
//! include [argon2rs](https://github.com/bryant/argon2rs) and
//! [rust-argon2](https://github.com/sru-systems/rust-argon2). If you're interesting
//! in password hashing with a different algorithm,
//! [rust-bcrypt](https://github.com/Keats/rust-bcrypt) might be worth checking out.
//!
//! For what it's worth, besides API differences, <b>argonautica</b> has three key features that
//! other crates currently lack:
//! * The ability to use [SIMD](https://en.wikipedia.org/wiki/SIMD) instructions (even on stable),
//!   which can lead to significantly faster hashing times
//!     * For example, on default settings, argonautica with SIMD runs <b>over twice
//!       as fast</b> as other crates on the developer's early-2014 Macbook, which has access to
//!       [SIMD instructions](https://software.intel.com/sites/landingpage/IntrinsicsGuide/)
//!       through
//!       [AVX2](https://en.wikipedia.org/wiki/Advanced_Vector_Extensions#Advanced_Vector_Extensions)
//!     * <i>Note: SIMD instructions are specific to your CPU; so if you're compiling for
//!       machines other than your own, you should not turn on the SIMD feature</i>
//! * The ability to hash passwords with a secret key, which not even the
//!   [C implementation](https://github.com/P-H-C/phc-winner-argon2) exposes publicly
//! * The newest Argon2 variant: Argon2id
//!
//! # Configuration
//!
//! The default configurations for [`Hasher`](struct.Hasher.html) and
//! [`Verifier`](struct.Verifier.html) were chosen to be reasonably secure for the general
//! use-case of hashing passwords for storage in a website database, but if you want to use
//! <b>argonautica</b> for different reasons or if you just disagree with the chosen defaults,
//! customizing <b>argonautica</b> to meet your needs should hopefully be as easy and as intuitive
//! as using the defaults.
//!
//! Here is an example that shows how to use [`Hasher`](struct.Hasher.html)'s custom
//! configuration options. It provides color on each of the options.
//! ```
//! extern crate argonautica;
//! extern crate futures_cpupool;
//!
//! use argonautica::Hasher;
//! use argonautica::config::{Backend, Variant, Version};
//! use futures_cpupool::CpuPool;
//!
//! fn main() {
//!     let mut hasher = Hasher::default();
//!     hasher
//!         .configure_backend(Backend::C) // Default is `Backend::C`
//!         // 👆 argonautica was designed to support multiple backends (meaning multiple
//!         // implementations of the underlying Argon2 algorithm). Currently only the C backend
//!         // is supported, which uses the cannonical Argon2 library written in C to actually
//!         // do the work. In the future hopefully a Rust backend will also be supported, but,
//!         // for the moment, you must use `Backend::C`, which is the default. Using
//!         // `Backend::Rust` will result in an error (again, for the moment).
//!         .configure_cpu_pool(CpuPool::new(2))
//!         // 👆 There are two non-blocking methods on `Hasher` that perform computation on
//!         // a separate thread and return a `Future` instead of a `Result` (`hash_non_blocking`
//!         // and `hash_raw_non_blocking`). These methods allow argonautica to play nicely with
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
//!         .configure_hash_len(16) // Default is `32`
//!         // 👆 The hash length in bytes is configurable. The default is 32. This is probably
//!         // a good number to use. 16 is also probably fine. You probably shouldn't go below 16
//!         .configure_iterations(192) // Default is `192`
//!         // 👆 Argon2 has a notion of "iterations" or "time cost". All else equal and generally
//!         // speaking, the greater the number of iterations, the longer it takes to perform the
//!         // hash and the more secure the resulting hash. More iterations basically means more
//!         // CPU load. This and "memory size" (see below) are the two primary parameters to
//!         // adjust in order to increase or decrease the security of your hash. The default is
//!         // 192 iterations, which was chosen because, along with the default memory size of
//!         // 4096, this leads to a hashing time of approximately 300 milliseconds on the
//!         // early-2014 Macbook Air that is the developer's machine. If you're going to use
//!         // argonautica in production, you should probably tweak this parameter (and the memory
//!         // size parameter) in order to increase the time it takes to hash to the maximum you
//!         // can reasonably allow for your use-case (e.g. to probably about 300-500 milliseconds
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
//!         // again, along with the default iterations of 192, this leads to a hashing time of
//!         // approximately 300 milliseconds on the early-2014 Macbook Air that is the
//!         // developer's machine. If you're going to use argonautica in production, you should
//!         // probably tweak this parameter (and the iterations parameter) in order to increase
//!         // the time it takes to hash to the maximum you can reasonably allow for your use-case
//!         // (e.g. to probably about 300-500 milliseconds for the use-case of hashing user
//!         // passwords for a website)
//!         .configure_password_clearing(false) // Default is `false`
//!         // 👆 It is possible to have the underlying bytes of the password you provided
//!         // to `Hasher` be erased after each call to `hash`, `hash_raw` or their non-blocking
//!         // equivalents. If you want this extra security feature, set this configuration
//!         // to `true` (the default is `false`). If you set this configuration to `true`,
//!         // you will be required to provide `Hasher` with a mutable password (e.g.
//!         // a `String`, a `Vec<u8>`, a `&mut str`, or a `&mut [u8]` instead of a
//!         // `&str` or a `&[u8]`)
//!         .configure_secret_key_clearing(false) // Default is `false`
//!         // 👆 It is also possible to have the underlying bytes of the secret key you provided
//!         // to `Hasher` be erased after each call to `hash`, `hash_raw` or their non-blocking
//!         // equivalents. If you want this extra security feature, set this configuration
//!         // to `true` (the default is `false`). If you set this configuration to `true`,
//!         // you will be required to provide `Hasher` with a mutable secret key (e.g.
//!         // a `String`, a `Vec<u8>`, a `&mut str`, or a `&mut [u8]` instead of a `&str`
//!         // or a `&[u8]`)
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
//!         .opt_out_of_secret_key(true); // Default is `false`
//!         // 👆 As an extra security measure, if you want to hash without a secret key, which
//!         // is not recommended, you must explicitly declare that this is your intention
//!         // by calling this method and setting the `opt_out_of_secret_key` configuration to
//!         // `true` (by default, it is set to `false`); otherwise hashing will return an error
//!         // when you fail to provide a secret key
//!
//!     let hash = hasher
//!         .with_password("P@ssw0rd")
//!         .with_salt("somesalt")
//!         .hash()
//!         .unwrap();
//!         // 👆 Note: We are able to hash witout a secret key because we explicitly
//!         // set `opt_out_of_secret_key` to `true` above
//!
//!     assert_eq!(
//!         &hash,
//!         "$argon2id$v=19$m=4096,t=192,p=2$c29tZXNhbHQ$sw41ZsxebJmOJ6vSHe6BGQ",
//!     );
//! }
//! ```
//! # Installation
//!
//! <b>argonautica</b> should be relatively straightforward to include in your Rust project:
//! * Place `extern crate argonautica;` in your code (typically in either `lib.rs` or `main.rs`)
//! * In the `[dependencies]` section of your `Cargo.toml`, place ...
//!     * ... if you're building for your own machine ...
//!         * `argonautica = { version = "0.1.0", features = ["simd"] }`, or
//!         * `argonautica = { version = "0.1.0", features = ["serde", "simd"] }`
//!     * ... if you're building for a different machine ...
//!         * `argonautica = "0.1.0"`, or
//!         * `argonautica = { version = "0.1.0", features = ["serde"] }`
//!
//! That said, <b>argonautica</b> uses [cc](https://github.com/alexcrichton/cc-rs) and
//! [bindgen](https://github.com/rust-lang-nursery/rust-bindgen) to compile the cannonical
//! [C implemenation](https://github.com/P-H-C/phc-winner-argon2) of Argon2 into a
//! static archive during the build process. This means you need a C compiler on your
//! machine in order to build <b>argonautica</b>. More specifically, you need:
//! * [LLVM/Clang](https://llvm.org/) (version 3.9 or higher)
//!     * Mac OS: `brew install llvm`, which requires [Homebrew](https://brew.sh/)
//!     * Debian-based linux: `apt-get install clang llvm-dev libclang-dev`
//!     * Arch linux: `pacman -S clang`
//!     * Windows: Download a pre-built binary [here](http://releases.llvm.org/download.html)
//!
//! <b>argonautica</b> runs on stable Rust version 1.26.0 or greater.
//!
//! # License
//!
//! <b>argonautica</b> is licensed under either of:
//! * [The Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0), or
//! * [The MIT license](http://opensource.org/licenses/MIT)
//!
//! at your option.

#![deny(
    missing_debug_implementations, missing_docs, unused_imports, unused_unsafe, unused_variables
)]
#![doc(html_root_url = "https://docs.rs/argonautica/0.1.5")]

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
pub use error::Error;
pub use error_kind::ErrorKind;
pub use hasher::Hasher;
pub mod input;
pub mod output;
pub mod utils;
pub use verifier::Verifier;
