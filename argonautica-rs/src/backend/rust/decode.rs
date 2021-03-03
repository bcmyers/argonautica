use base64;

use Error;
use config::{Variant, Version};
use output::HashRaw;

pub(crate) fn decode_rust(hash: &str) -> Result<HashRaw, Error> {
    let (rest, intermediate) = parse_hash(hash).map_err(|e| {
        Error::HashDecodeError(e)
    })?;
    let raw_hash_bytes = base64::decode_config(rest, base64::STANDARD_NO_PAD).map_err(|e| {
        Error::HashDecodeError(e)
    })?;
    let hash_raw = HashRaw {
        iterations: intermediate.iterations,
        lanes: intermediate.lanes,
        memory_size: intermediate.memory_size,
        raw_hash_bytes: raw_hash_bytes,
        raw_salt_bytes: intermediate.raw_salt_bytes,
        variant: intermediate.variant,
        version: intermediate.version,
    };
    Ok(hash_raw)
}

struct IntermediateStruct {
    variant: Variant,
    version: Version,
    memory_size: u32,
    iterations: u32,
    lanes: u32,
    raw_salt_bytes: Vec<u8>,
}

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(parse_hash<&str, IntermediateStruct>, do_parse!(
    take_until!("$") >>
    take!(1) >>
    variant: map_res!(take_until!("$"), |x: &str| x.parse::<Variant>()) >>
    take_until!("$v=") >>
    take!(3) >>
    version: map_res!(take_until!("$"), |x: &str| x.parse::<Version>()) >>
    take_until!("$m=") >>
    take!(3) >>
    memory_size: map_res!(take_until!(","), |x: &str| x.parse::<u32>()) >>
    take_until!(",t=") >>
    take!(3) >>
    iterations: map_res!(take_until!(","), |x: &str| x.parse::<u32>()) >>
    take_until!(",p=") >>
    take!(3) >>
    lanes: map_res!(take_until!("$"), |x: &str| x.parse::<u32>()) >>
    take_until!("$") >>
    take!(1) >>
    raw_salt_bytes: map_res!(take_until!("$"), |x: &str| {
        base64::decode_config(x, base64::STANDARD_NO_PAD)
    }) >>
    take_until!("$") >>
    take!(1) >>
    (IntermediateStruct {
        iterations,
        lanes,
        memory_size,
        raw_salt_bytes,
        variant,
        version,
    })
));

#[cfg(test)]
mod tests {
    use rand::{RngCore, SeedableRng};
    use rand::rngs::StdRng;

    use backend::c::decode_c;
    use hasher::Hasher;

    use super::*;

    #[test]
    fn test_decode() {
        let hash = "$argon2id$v=19$m=4096,t=128,p=2$gt4I/z7gnC8Ao0ofCFvz+2LGxI3it1TnCnlxn0PWKko$v6V587B9qbKraulhK/6vFUq93BGWugdzgRhtyap9tDM";
        let hash_raw = decode_rust(hash).unwrap();
        assert_eq!(hash_raw.variant(), Variant::Argon2id);
        assert_eq!(hash_raw.version(), Version::_0x13);
        assert_eq!(hash_raw.memory_size(), 4096);
        assert_eq!(hash_raw.iterations(), 128);
        assert_eq!(hash_raw.lanes(), 2);

        let hash = "$argon2i$v=16$m=32,t=3,p=1$gt4I/z7gnC8Ao0ofCFvz+2LGxI3it1TnCnlxn0PWKko$v6V587B9qbKraulhK/6vFUq93BGWugdzgRhtyap9tDM";
        let hash_raw = decode_rust(hash).unwrap();
        assert_eq!(hash_raw.variant(), Variant::Argon2i);
        assert_eq!(hash_raw.version(), Version::_0x10);
        assert_eq!(hash_raw.memory_size(), 32);
        assert_eq!(hash_raw.iterations(), 3);
        assert_eq!(hash_raw.lanes(), 1);

        let hash = "$argon2d$v=16$m=32,t=3,p=1$gt4I/z7gnC8Ao0ofCFvz+2LGxI3it1TnCnlxn0PWKko$v6V587B9qbKraulhK/6vFUq93BGWugdzgRhtyap9tDM";
        let hash_raw = decode_rust(hash).unwrap();
        assert_eq!(hash_raw.variant(), Variant::Argon2d);
        assert_eq!(hash_raw.version(), Version::_0x10);
        assert_eq!(hash_raw.memory_size(), 32);
        assert_eq!(hash_raw.iterations(), 3);
        assert_eq!(hash_raw.lanes(), 1);
    }

    #[test]
    #[ignore] // TODO: Turn back on once implemented decode_c
    fn test_decode_against_c() {
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let mut password = vec![0u8; 12];
        let mut secret_key = vec![0u8; 32];
        for _ in 0..100 {
            rng.fill_bytes(&mut password);
            rng.fill_bytes(&mut secret_key);
            for hash_len in &[8, 32, 128] {
                let mut hasher = Hasher::default();
                let hash = hasher
                    .configure_hash_len(*hash_len)
                    .configure_iterations(1)
                    .configure_memory_size(32)
                    .configure_threads(1)
                    .configure_lanes(1)
                    .with_secret_key(&secret_key[..])
                    .with_password(&password[..])
                    .hash()
                    .unwrap();
                let hash_raw1 = decode_rust(&hash).unwrap();
                let hash_raw2 = decode_c(&hash).unwrap();
                assert_eq!(hash_raw1, hash_raw2);
            }
        }
    }
}
