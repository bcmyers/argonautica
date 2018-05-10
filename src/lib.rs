// TODO: Check for errors before serializing
extern crate base64;
#[macro_use]
extern crate bitflags;
// extern crate blake2_rfc;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
extern crate num_cpus;
extern crate rand;
extern crate scopeguard;
extern crate serde;
#[macro_use]
extern crate serde_derive;

mod backend;
mod ffi;
mod hasher;
mod verifier;

pub mod config;
pub mod data;
pub use hasher::Hasher;
pub mod output;
pub mod utils;
pub use verifier::Verifier;
