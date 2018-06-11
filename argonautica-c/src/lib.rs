//! [argonautica-c](https://github.com/bcmyers/argonautica/tree/master/argonautica-c)
//! is wrapper for
//! [argonautica-rs](https://github.com/bcmyers/argonautica/tree/master/argonautica-rs).
//!
//! It allows you to write C or C++ code that uses
//! [argonautica-rs](https://github.com/bcmyers/argonautica/tree/master/argonautica-rs).
#![deny(
    missing_debug_implementations, missing_docs, unused_imports, unused_unsafe, unused_variables
)]
#![doc(html_root_url = "https://docs.rs/argonautica-c/0.1.0")]

extern crate argonautica;
extern crate itoa;
extern crate libc;

mod hash;
mod types;
mod utils;
mod verify;

pub use hash::*;
pub use types::*;
pub use utils::*;
pub use verify::*;
