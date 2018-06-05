extern crate failure;
extern crate jasonus;
extern crate serde;
extern crate serde_json;

fn serialize_hasher() -> Result<String, failure::Error> {
    let additional_data = [1u8, 2, 3, 4];
    let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut hasher = jasonus::Hasher::default();
    hasher
        .with_additional_data(&additional_data[..])
        .with_password("P@ssw0rd") // note: for security reasons, password is never serialized
        .with_salt(&salt[..])
        .with_secret_key("secret"); // note: for security reasons, secret key is never serialized
    let j = serde_json::to_string_pretty(&hasher)?;
    println!("*** Serialized Hasher ***");
    println!("{}\n", &j);
    // *** Serialized hasher ***
    // {
    //   "additionalData": [1, 2, 3, 4],
    //   "config": {
    //     "backend": "c",
    //     "hashLength": 32,
    //     "iterations": 128,
    //     "lanes": 2,
    //     "memorySize": 4096,
    //     "optOutOfRandomSalt": false,
    //     "optOutOfSecretKey": false,
    //     "passwordClearing": true,
    //     "secretKeyClearing": false,
    //     "threads": 2,
    //     "variant": "argon2id",
    //     "version": "_0x13"
    //   },
    //   "salt": {
    //     "bytes": [1, 2, 3, 4, 5, 6, 7, 8],
    //     "isRandom": false
    //   }
    // }
    Ok(j)
}

fn deserialize_hasher(j: &str) -> Result<jasonus::Hasher, failure::Error> {
    let hasher: jasonus::Hasher = serde_json::from_str(&j)?;
    println!("*** Deserialized Hasher ***");
    println!("{:#?}\n", &hasher);
    // *** Deserialized hasher ***
    // Hasher {
    //     additional_data: AdditionalData { bytes: [1, 2, 3, 4] },
    //     config: HasherConfig {
    //         backend: C,
    //         hash_length: 32,
    //         iterations: 128,
    //         lanes: 2,
    //         memory_size: 4096,
    //         opt_out_of_random_salt: false,
    //         opt_out_of_secret_key: false,
    //         password_clearing: true,
    //         secret_key_clearing: false,
    //         threads: 2,
    //         variant: Argon2id,
    //         version: _0x13
    //     },
    //     cpu_pool: CpuPool { size: 4 },
    //     password: Password { bytes: [] },
    //     salt: Salt {
    //         bytes: [1, 2, 3, 4, 5, 6, 7, 8],
    //         is_random: false
    //     },
    //     secret_key: SecretKey { bytes: [] }
    // }

    Ok(hasher)
}

fn serialize_verifier() -> Result<String, failure::Error> {
    let additional_data = [1u8, 2, 3, 4];
    let mut verifier = jasonus::Verifier::default();
    verifier
        .with_additional_data(&additional_data[..])
        .with_hash("$argon2id$v=19$m=4096,t=128,p=2$c29tZXNhbHQ$WwD2/wGGTuw7u4BW8sLM0Q")
        .with_password("P@ssw0rd")
        .with_secret_key("secret");
    let j = serde_json::to_string_pretty(&verifier)?;
    println!("*** Serialized Verifier ***");
    println!("{}\n", &j);
    // *** Serialized Verifier ***
    // {
    //   "additionalData": [1, 2, 3, 4],
    //   "config": {
    //     "backend": "c",
    //     "passwordClearing": true,
    //     "secretKeyClearing": false
    //   },
    //   "hash": "$argon2id$v=19$m=4096,t=128,p=2$c29tZXNhbHQ$WwD2/wGGTuw7u4BW8sLM0Q"
    // }
    Ok(j)
}

fn deserialize_verifier(j: &str) -> Result<jasonus::Verifier, failure::Error> {
    let verifier: jasonus::Verifier = serde_json::from_str(&j)?;
    println!("*** Deserialized Verifier ***");
    println!("{:#?}\n", &verifier);
    Ok(verifier)
}

fn main() -> Result<(), failure::Error> {
    let j = serialize_hasher()?;
    let _ = deserialize_hasher(&j)?;

    let j = serialize_verifier()?;
    let _ = deserialize_verifier(&j)?;
    Ok(())
}
