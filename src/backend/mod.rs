mod c;
mod rust;

pub(crate) use self::c::decode_c;
pub(crate) use self::c::encode_c;
pub(crate) use self::c::hash_raw_c;
pub(crate) use self::c::verify_c;
pub(crate) use self::rust::decode_rust;
pub(crate) use self::rust::encode_rust;
pub(crate) use self::rust::hash_raw_rust;
pub(crate) use self::rust::verify_rust;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        for hash in &[
            "$argon2id$v=19$m=4096,t=128,p=2$gt4I/z7gnC8Ao0ofCFvz+2LGxI3it1TnCnlxn0PWKko$v6V587B9qbKraulhK/6vFUq93BGWugdzgRhtyap9tDM",
            "$argon2i$v=16$m=32,t=3,p=1$gt4I/z7gnC8Ao0ofCFvz+2LGxI3it1TnCnlxn0PWKko$v6V587B9qbKraulhK/6vFUq93BGWugdzgRhtyap9tDM",
            "$argon2d$v=16$m=32,t=3,p=1$gt4I/z7gnC8Ao0ofCFvz+2LGxI3it1TnCnlxn0PWKko$v6V587B9qbKraulhK/6vFUq93BGWugdzgRhtyap9tDM",
        ] {
            let c_hash_raw = decode_c(*hash).unwrap();
            let rust_hash_raw = decode_rust(*hash).unwrap();
            assert_eq!(c_hash_raw, rust_hash_raw);

            let c_hash = encode_c(&c_hash_raw).unwrap();
            let rust_hash = encode_rust(&rust_hash_raw);
            assert_eq!(c_hash, rust_hash);
        }
    }
}
