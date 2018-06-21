mod c;
mod rust;

#[cfg(test)]
pub(crate) use self::c::encode_c;
pub(crate) use self::rust::decode_rust;
