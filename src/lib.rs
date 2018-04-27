extern crate base64;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate failure;
extern crate rand;
#[cfg(feature = "serde")]
extern crate serde;
extern crate void;

mod argon2;
mod argon2_builder;

pub use argon2::Argon2;
pub use argon2_builder::Argon2Builder;
pub mod configuration;
pub mod parameters;
pub mod utils;

mod ffi {
    #![allow(dead_code)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
