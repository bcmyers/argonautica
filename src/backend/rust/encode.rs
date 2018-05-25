use base64;

use output::HashRaw;

pub(crate) fn encode_rust(hash_raw: &HashRaw) -> String {
    let hash_encoded = base64::encode_config(hash_raw.raw_hash_bytes(), base64::STANDARD_NO_PAD);
    let salt_encoded = base64::encode_config(hash_raw.raw_salt_bytes(), base64::STANDARD_NO_PAD);

    format!(
        "${}$v={}$m={},t={},p={}${}${}",
        hash_raw.variant().as_str(),
        hash_raw.version().as_str(),
        hash_raw.memory_size(),
        hash_raw.iterations(),
        hash_raw.lanes(),
        salt_encoded,
        hash_encoded,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_against_c() {
        use backend::c::encode_c;
        use hasher::Hasher;
        use rand::{RngCore, SeedableRng, StdRng};

        let mut seed = [0u8; 32];
        seed[0] = 1;
        seed[1] = 2;
        seed[2] = 3;
        seed[3] = 4;
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut password = vec![0u8; 12];
        let mut secret_key = vec![0u8; 32];
        for _ in 0..100 {
            rng.fill_bytes(&mut password);
            rng.fill_bytes(&mut secret_key);
            for hash_length in &[8, 32, 128] {
                let mut hasher = Hasher::default();
                let hash_raw = hasher
                    .configure_hash_length(*hash_length)
                    .configure_iterations(1)
                    .configure_memory_size(32)
                    .configure_threads(1)
                    .configure_lanes(1)
                    .with_secret_key(&secret_key[..])
                    .with_password(&password[..])
                    .hash_raw()
                    .unwrap();
                let hash1 = encode_rust(&hash_raw);
                let hash2 = encode_c(&hash_raw).unwrap();
                assert_eq!(hash1, hash2);
            }
        }
    }
}
