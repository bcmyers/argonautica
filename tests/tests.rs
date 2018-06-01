extern crate a2;
extern crate failure;
extern crate rand;

use std::path::{Path, PathBuf};
use std::process::Command;

use a2::config::{Variant, Version};
use a2::{Hasher, Verifier};
use rand::distributions::Alphanumeric;
use rand::Rng;

fn build_c() -> Result<PathBuf, failure::Error> {
    let build_dir = PathBuf::from("tests/c/build");
    if build_dir.exists() {
        ::std::fs::remove_dir_all(&build_dir)?;
    }
    ::std::fs::create_dir_all(&build_dir)?;
    let success = Command::new("cmake")
        .arg("..")
        .current_dir(&build_dir)
        .status()?
        .success();
    if !success {
        return Err(failure::err_msg("cmake command failed"));
    }
    assert!(success);
    let success = Command::new("make")
        .current_dir(&build_dir)
        .status()?
        .success();
    if !success {
        return Err(failure::err_msg("make command failed"));
    }
    Ok(build_dir)
}

fn parse_c_stderr(stderr: &[u8]) -> Result<(String, String, Vec<u8>, Vec<u8>), failure::Error> {
    let stderr = ::std::str::from_utf8(stderr)?;
    let v = stderr.trim().split("\n").collect::<Vec<&str>>();
    if v.len() != 4 {
        return Err(failure::err_msg("invalid output from C"));
    }
    let encoded1 = v[0].to_string();
    let encoded2 = v[1].to_string();
    let hash1 = v[2].replace("[", "")
        .replace("]", "")
        .split(",")
        .into_iter()
        .map(|s| Ok::<_, failure::Error>(s.parse::<u8>()?))
        .collect::<Result<Vec<u8>, failure::Error>>()?;
    let hash2 = v[3].replace("[", "")
        .replace("]", "")
        .split(",")
        .into_iter()
        .map(|s| Ok::<_, failure::Error>(s.parse::<u8>()?))
        .collect::<Result<Vec<u8>, failure::Error>>()?;
    Ok((encoded1, encoded2, hash1, hash2))
}

fn test_hasher_without_secret_key<P: AsRef<Path>>(
    build_dir: P,
    hash_length: u32,
    iterations: u32,
    lanes: u32,
    memory_size: u32,
    threads: u32,
    variant: Variant,
    version: Version,
) {
    // Generate inputs
    let mut rng = rand::thread_rng();
    let password = rng.sample_iter(&Alphanumeric).take(32).collect::<String>();
    let salt = rng.sample_iter(&Alphanumeric).take(8).collect::<String>();

    let hash_length_string = format!("{}", hash_length);
    let iterations_string = format!("{}", iterations);
    let lanes_string = format!("{}", lanes);
    let memory_size_string = format!("{}", memory_size);
    let threads_string = format!("{}", threads);
    let variant_string = match variant {
        Variant::Argon2d => "1".to_string(),
        Variant::Argon2i => "2".to_string(),
        Variant::Argon2id => "3".to_string(),
    };
    let version_string = match version {
        Version::_0x10 => "16".to_string(),
        Version::_0x13 => "19".to_string(),
    };

    // Run C without simd
    let output = Command::new("./test")
        .args(&[
            "",
            &password,
            &salt,
            "",
            &hash_length_string,
            &iterations_string,
            &lanes_string,
            &memory_size_string,
            &threads_string,
            &variant_string,
            &version_string,
        ])
        .current_dir(build_dir.as_ref())
        .output()
        .unwrap();
    if !output.status.success() {
        panic!(
            "\nC executable failed:\nstdout: {}\nstderr: {}\n",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap(),
        )
    }
    let (encoded1, encoded2, hash1, hash2) = parse_c_stderr(&output.stderr).unwrap();

    // Run C with simd
    let output = Command::new("./test_simd")
        .args(&[
            "",
            &password,
            &salt,
            "",
            &hash_length_string,
            &iterations_string,
            &lanes_string,
            &memory_size_string,
            &threads_string,
            &variant_string,
            &version_string,
        ])
        .current_dir(build_dir.as_ref())
        .output()
        .unwrap();
    if !output.status.success() {
        panic!(
            "C simd executable failed:\nstdout: {}\nstderr: {}\n",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap(),
        )
    }
    let (encoded3, encoded4, hash3, hash4) = parse_c_stderr(&output.stderr).unwrap();

    // Run Rust
    let mut hasher = Hasher::default();
    hasher
        .configure_hash_length(hash_length)
        .configure_iterations(iterations)
        .configure_memory_size(memory_size)
        .configure_lanes(lanes)
        .configure_password_clearing(false)
        .configure_secret_key_clearing(false)
        .configure_threads(threads)
        .configure_variant(variant)
        .configure_version(version)
        .opt_out_of_random_salt(true)
        .opt_out_of_secret_key(true)
        .with_password(&password)
        .with_salt(&salt);
    let encoded5 = hasher.hash().unwrap();
    let hash5 = hasher.hash_raw().unwrap().raw_hash_bytes().to_vec();

    // Print results
    println!("{}", &encoded1);
    println!("{}", &encoded2);
    println!("{}", &encoded3);
    println!("{}", &encoded4);
    println!("{}", &encoded5);
    println!("{:?}", &hash1);
    println!("{:?}", &hash2);
    println!("{:?}", &hash3);
    println!("{:?}", &hash4);
    println!("{:?}", &hash5);
    println!();

    // Compare results
    assert_eq!(&encoded1, &encoded2);
    assert_eq!(&encoded2, &encoded3);
    assert_eq!(&encoded3, &encoded4);
    assert_eq!(&encoded4, &encoded5);
    assert_eq!(&hash1, &hash2);
    assert_eq!(&hash2, &hash3);
    assert_eq!(&hash3, &hash4);
    assert_eq!(&hash4, &hash5);
}

#[test]
#[ignore]
fn test_c_version() {
    let build_dir = build_c().unwrap();
    let hash_lengths = [8, 16, 32];
    let iterations = [4, 8, 16, 64, 128];
    let memory_sizes = [64, 128, 256];
    let threads = [1, 2, 4];
    let variants = [Variant::Argon2d, Variant::Argon2i, Variant::Argon2id];
    let versions = [Version::_0x10, Version::_0x13];
    for hash_length in &hash_lengths {
        for iterations in &iterations {
            for memory_size in &memory_sizes {
                for threads in &threads {
                    for variant in &variants {
                        for version in &versions {
                            test_hasher_without_secret_key(
                                &build_dir,
                                *hash_length,
                                *iterations,
                                *threads,
                                *memory_size,
                                *threads,
                                *variant,
                                *version,
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn test_debug() {
    let _hash =
        "$argon2id$v=19$m=4096,t=128,p=4$c29tZXNhbHQ$2st2qT80k6JAjYvcW2I2mXmW1Jp+pNOqpJZxv5vGEUw";

    let additional_data = "additional data";
    let password = "P@ssw0rd";
    let salt = "somesalt";
    let secret_key = "secret1";

    let mut hasher = Hasher::default();
    hasher
        .configure_password_clearing(false)
        .opt_out_of_random_salt(true)
        .with_additional_data(additional_data)
        .with_password(password)
        .with_secret_key(secret_key)
        .with_salt(salt);
    let hash_raw = hasher.hash_raw().unwrap();

    let mut verifier1 = Verifier::default();
    verifier1
        .configure_password_clearing(false)
        .with_additional_data(additional_data)
        .with_hash_raw(&hash_raw)
        .with_password(password)
        .with_secret_key(secret_key);
    let is_valid = verifier1.verify().unwrap();
    if !is_valid {
        panic!(
            "\nverifier1:\n{:#?}\nAdditional Data: {:?}\nHash: {}\nPassword: {:?}\nSecret key: {:?}",
            verifier1,
            "additional data".as_bytes(),
            hash_raw.to_hash(),
            password.as_bytes(),
            "secret1".as_bytes()
        );
    };
}
