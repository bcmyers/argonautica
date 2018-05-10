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
