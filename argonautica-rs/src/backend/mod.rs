pub mod c;
pub mod rust;

#[cfg(test)]
pub use c::encode_c;
pub use rust::decode_rust;
