extern crate base64;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate num_cpus;
extern crate rand;
extern crate scopeguard;
#[cfg(feature = "serde")]
extern crate serde;
extern crate void;

mod ffi;
mod hasher;
mod verifier;

pub mod config;
pub mod data;
pub use hasher::Hasher;
pub mod utils;
pub use verifier::Verifier;
