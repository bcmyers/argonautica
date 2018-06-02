extern crate a2;
extern crate failure;
extern crate rand;

use std::path::PathBuf;
use std::process::Command;

use a2::config::{Variant, Version};
use rand::distributions::Alphanumeric;
use rand::Rng;

fn build_c() -> PathBuf {
    let build_dir = PathBuf::from("tests/c/build");
    if build_dir.exists() {
        ::std::fs::remove_dir_all(&build_dir).expect("unable to remove build dir");
    }
    ::std::fs::create_dir_all(&build_dir).expect("unable to create build dir");
    let success = Command::new("cmake")
        .arg("..")
        .current_dir(&build_dir)
        .status()
        .unwrap()
        .success();
    if !success {
        panic!("cmake failed");
    }
    assert!(success);
    let success = Command::new("make")
        .current_dir(&build_dir)
        .status()
        .unwrap()
        .success();
    if !success {
        panic!("make failed");
    }
    build_dir
}

fn parse_stderr_hash(stderr: &[u8]) -> (String, Vec<u8>) {
    let stderr = ::std::str::from_utf8(stderr).expect("stderr from C is invalid utf-8");
    let v = stderr.trim().split("\n").collect::<Vec<&str>>();
    if v.len() != 2 {
        panic!("invalid stderr from C: {}", stderr);
    }
    let encoded = v[0].to_string();
    let hash = v[1].replace("[", "")
        .replace("]", "")
        .split(",")
        .into_iter()
        .map(|s| Ok::<_, failure::Error>(s.parse::<u8>()?))
        .collect::<Result<Vec<u8>, failure::Error>>()
        .expect("unable to parse hash from C stderr");
    (encoded, hash)
}

fn parse_stderr_hash_c(
    stderr: &[u8],
) -> Result<(String, String, Vec<u8>, Vec<u8>), failure::Error> {
    let stderr = ::std::str::from_utf8(stderr)?;
    let v = stderr.trim().split("\n").collect::<Vec<&str>>();
    if v.len() != 4 {
        return Err(failure::err_msg("invalid stderr from C"));
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

#[derive(Debug)]
struct Input {
    additional_data_len: usize,
    build_dir: PathBuf,
    flags: u32,
    hash_length: u32,
    iterations: u32,
    lanes: u32,
    memory_size: u32,
    password_len: usize,
    secret_key_len: usize,
    salt_len: usize,
    threads: u32,
    variant: Variant,
    version: Version,
}

fn generate_inputs(input: &Input) -> (String, String, String, String, Vec<String>) {
    let mut rng = rand::thread_rng();
    let additional_data = if input.additional_data_len == 0 {
        "".to_string()
    } else {
        rng.sample_iter(&Alphanumeric)
            .take(input.additional_data_len)
            .collect::<String>()
    };
    let secret_key = if input.secret_key_len == 0 {
        "".to_string()
    } else {
        rng.sample_iter(&Alphanumeric)
            .take(input.secret_key_len)
            .collect::<String>()
    };
    let password = rng.sample_iter(&Alphanumeric)
        .take(input.password_len)
        .collect::<String>();
    let salt = rng.sample_iter(&Alphanumeric)
        .take(input.salt_len)
        .collect::<String>();

    let flags_string = format!("{}", input.flags);
    let hash_length_string = format!("{}", input.hash_length);
    let iterations_string = format!("{}", input.iterations);
    let lanes_string = format!("{}", input.lanes);
    let memory_size_string = format!("{}", input.memory_size);
    let threads_string = format!("{}", input.threads);
    let variant_string = match input.variant {
        Variant::Argon2d => "0".to_string(),
        Variant::Argon2i => "1".to_string(),
        Variant::Argon2id => "2".to_string(),
    };
    let version_string = match input.version {
        Version::_0x10 => "16".to_string(),
        Version::_0x13 => "19".to_string(),
    };
    (
        additional_data,
        password,
        salt,
        secret_key,
        vec![
            flags_string,
            hash_length_string,
            iterations_string,
            lanes_string,
            memory_size_string,
            threads_string,
            variant_string,
            version_string,
        ],
    )
}

fn test_hash_single(input: &Input) {
    let (additional_data, password, salt, secret_key, other_args) = generate_inputs(input);

    // Run C without simd
    let output = Command::new("./test_hash")
        .arg(&additional_data)
        .arg(&password)
        .arg(&salt)
        .arg(&secret_key)
        .args(&other_args)
        .current_dir(&input.build_dir)
        .output()
        .unwrap();
    if !output.status.success() {
        panic!(
            "\nC executable failed:\nstdout: {}\nstderr: {}\n",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap(),
        )
    }
    let (encoded1, hash1) = parse_stderr_hash(&output.stderr);

    // Run C with simd
    let output = Command::new("./test_hash_simd")
        .arg(&additional_data)
        .arg(&password)
        .arg(&salt)
        .arg(&secret_key)
        .args(&other_args)
        .current_dir(&input.build_dir)
        .output()
        .unwrap();
    if !output.status.success() {
        panic!(
            "C simd executable failed:\nstdout: {}\nstderr: {}\n",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap(),
        )
    }
    let (encoded2, hash2) = parse_stderr_hash(&output.stderr);

    // Print results
    println!("{}", &encoded1);
    println!("{}", &encoded2);
    println!("{:?}", &hash1);
    println!("{:?}", &hash2);
    println!();

    // Compare results
    if (&encoded1 != &encoded2) || (&hash1 != &hash2) {
        panic!("\nFailed with input:\n{:#?}\n", &input);
    }
}

fn test_hash_c_single(input: &Input) {
    let (additional_data, password, salt, secret_key, other_args) = generate_inputs(input);

    // Run C without simd
    let output = Command::new("./test_hash_c")
        .arg(&additional_data)
        .arg(&password)
        .arg(&salt)
        .arg(&secret_key)
        .args(&other_args)
        .current_dir(&input.build_dir)
        .output()
        .unwrap();
    if !output.status.success() {
        panic!(
            "\nC executable failed:\nstdout: {}\nstderr: {}\n",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap(),
        )
    }
    let (encoded1, encoded2, hash1, hash2) = parse_stderr_hash_c(&output.stderr).unwrap();

    // Run C with simd
    let output = Command::new("./test_hash_c_simd")
        .arg(&additional_data)
        .arg(&password)
        .arg(&salt)
        .arg(&secret_key)
        .args(&other_args)
        .current_dir(&input.build_dir)
        .output()
        .unwrap();
    if !output.status.success() {
        panic!(
            "C simd executable failed:\nstdout: {}\nstderr: {}\n",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap(),
        )
    }
    let (encoded3, encoded4, hash3, hash4) = parse_stderr_hash_c(&output.stderr).unwrap();

    // Print results
    println!("{}", &encoded1);
    println!("{}", &encoded2);
    println!("{}", &encoded3);
    println!("{}", &encoded4);
    println!("{:?}", &hash1);
    println!("{:?}", &hash2);
    println!("{:?}", &hash3);
    println!("{:?}", &hash4);
    println!();

    // Compare results
    if (&encoded1 != &encoded2) || (&encoded2 != &encoded3) || (&encoded3 != &encoded4)
        || (&hash1 != &hash2) || (&hash2 != &hash3) || (&hash3 != &hash4)
    {
        panic!("\nFailed with input:\n{:#?}\n", &input);
    }
}

// TODO: Rename
#[test]
fn test_stuff_and_things() {
    let build_dir = build_c();
    let flags = [0b00, 0b01, 0b10];
    let hash_lengths = [8, 32];
    let iterations = [8, 32];
    let lane_threads = [(1, 1), (4, 4), (4, 1)];
    let memory_sizes = [32, 128];
    let password_lens = [8, 32];
    let salt_lens = [8, 32];
    let variants = [Variant::Argon2d, Variant::Argon2i, Variant::Argon2id];
    let versions = [Version::_0x10, Version::_0x13];
    for flags in &flags {
        for hash_length in &hash_lengths {
            for iterations in &iterations {
                for lane_thread in &lane_threads {
                    for memory_size in &memory_sizes {
                        for password_len in &password_lens {
                            for salt_len in &salt_lens {
                                for variant in &variants {
                                    for version in &versions {
                                        let input = Input {
                                            additional_data_len: 8,
                                            build_dir: build_dir.clone(),
                                            flags: *flags,
                                            hash_length: *hash_length,
                                            iterations: *iterations,
                                            lanes: (*lane_thread).0,
                                            memory_size: *memory_size,
                                            password_len: *password_len,
                                            salt_len: *salt_len,
                                            secret_key_len: 32,
                                            threads: (*lane_thread).1,
                                            variant: *variant,
                                            version: *version,
                                        };
                                        test_hash_single(&input);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn test_hash_c() {
    let build_dir = build_c();
    let flags = [0b00]; // Note: for high level, cannot set flags
    let hash_lengths = [8, 32];
    let iterations = [8, 32];
    let lane_threads = [(1, 1), (4, 4)]; // Note: for high level, lanes and threads have to be the same
    let memory_sizes = [32, 128];
    let password_lens = [8, 32];
    let salt_lens = [8, 32];
    let variants = [Variant::Argon2d, Variant::Argon2i, Variant::Argon2id];
    let versions = [Version::_0x10, Version::_0x13];
    for flags in &flags {
        for hash_length in &hash_lengths {
            for iterations in &iterations {
                for lane_thread in &lane_threads {
                    for memory_size in &memory_sizes {
                        for password_len in &password_lens {
                            for salt_len in &salt_lens {
                                for variant in &variants {
                                    for version in &versions {
                                        let input = Input {
                                            additional_data_len: 0, // Note: for high level, can't have additional data
                                            build_dir: build_dir.clone(),
                                            flags: *flags,
                                            hash_length: *hash_length,
                                            iterations: *iterations,
                                            lanes: (*lane_thread).0,
                                            memory_size: *memory_size,
                                            password_len: *password_len,
                                            salt_len: *salt_len,
                                            secret_key_len: 0, // Note: for high level, can't have secret key
                                            threads: (*lane_thread).1,
                                            variant: *variant,
                                            version: *version,
                                        };
                                        test_hash_c_single(&input);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
