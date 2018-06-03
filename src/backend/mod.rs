mod c;
mod rust;

#[cfg(test)]
pub(crate) use self::c::encode_c;
pub(crate) use self::c::hash_raw_c;
pub(crate) use self::rust::decode_rust;
pub(crate) use self::rust::encode_rust;
