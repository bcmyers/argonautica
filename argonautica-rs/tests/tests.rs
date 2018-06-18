extern crate argonautica;
extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate rand;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use argonautica::config::{Variant, Version};
use argonautica::{Hasher, Verifier};
use rand::distributions::Alphanumeric;
use rand::Rng;

lazy_static! {
    static ref BUILD_EXISTS: Mutex<bool> = Mutex::new(false);
}

#[derive(Debug)]
struct Input {
    additional_data_len: usize,
    build_dir: PathBuf,
    flags: u32,
    hash_len: u32,
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

fn build_c<P: AsRef<Path>>(build_dir: P) {
    let mut build_exists = BUILD_EXISTS.lock().unwrap();
    if *build_exists {
        return;
    }
    let build_dir = build_dir.as_ref();
    if build_dir.exists() {
        ::std::fs::remove_dir_all(build_dir).expect("unable to remove build dir");
    }
    ::std::fs::create_dir_all(build_dir).expect("unable to create build dir");
    let success = Command::new("cmake")
        .arg("..")
        .current_dir(build_dir)
        .status()
        .unwrap()
        .success();
    if !success {
        panic!("cmake failed");
    }
    assert!(success);
    let success = Command::new("make")
        .current_dir(build_dir)
        .status()
        .unwrap()
        .success();
    if !success {
        panic!("make failed");
    }
    *build_exists = true;
}

fn generate_args(input: &Input) -> Vec<String> {
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
    let password = rng
        .sample_iter(&Alphanumeric)
        .take(input.password_len)
        .collect::<String>();
    let salt = rng
        .sample_iter(&Alphanumeric)
        .take(input.salt_len)
        .collect::<String>();

    let flags_string = format!("{}", input.flags);
    let hash_len_string = format!("{}", input.hash_len);
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
    vec![
        additional_data,
        password,
        salt,
        secret_key,
        flags_string,
        hash_len_string,
        iterations_string,
        lanes_string,
        memory_size_string,
        threads_string,
        variant_string,
        version_string,
    ]
}

fn run_c(exe: &str, dir: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new(exe)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    if !output.status.success() {
        panic!(
            "\nC executable failed:\nstdout: {}stderr: {}",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap(),
        )
    }
    output.stderr
}

fn parse_stderr(stderr: &[u8]) -> (String, Vec<u8>) {
    let stderr = ::std::str::from_utf8(stderr).expect("stderr from C is invalid utf-8");
    let v = stderr.trim().split("\n").collect::<Vec<&str>>();
    if v.len() != 2 {
        panic!("invalid stderr from C: {}", stderr);
    }
    let encoded = v[0].to_string();
    let hash = v[1]
        .replace("[", "")
        .replace("]", "")
        .split(",")
        .into_iter()
        .map(|s| Ok::<_, failure::Error>(s.parse::<u8>()?))
        .collect::<Result<Vec<u8>, failure::Error>>()
        .expect("unable to parse hash from C stderr");
    (encoded, hash)
}

fn test(input: &Input) {
    let args = generate_args(input);
    let args = args.iter().map(|s| (*s).as_ref()).collect::<Vec<&str>>();

    // Run C without simd
    let stderr = run_c("./test_low_level", &input.build_dir, &args);
    let (encoded1, hash1) = parse_stderr(&stderr);

    // Run C with simd
    let stderr = run_c("./test_low_level_simd", &input.build_dir, &args);
    let (encoded2, hash2) = parse_stderr(&stderr);

    // Hash Rust
    let password_clearing = (input.flags & 0b01) == 1;
    let secret_key_clearing = ((input.flags >> 1) & 0b1) == 1;
    let mut hasher = Hasher::default();
    hasher
        .configure_hash_len(input.hash_len)
        .configure_iterations(input.iterations)
        .configure_lanes(input.lanes)
        .configure_memory_size(input.memory_size)
        .configure_password_clearing(password_clearing)
        .configure_secret_key_clearing(secret_key_clearing)
        .configure_threads(input.threads)
        .configure_variant(input.variant)
        .configure_version(input.version)
        .with_additional_data(args[0])
        .with_salt(args[2]);
    if password_clearing {
        hasher.with_password(args[1].to_string());
    } else {
        hasher.with_password(args[1]);
    }
    if secret_key_clearing {
        hasher.with_secret_key(args[3].to_string());
    } else {
        hasher.with_secret_key(args[3]);
    }
    let encoded3 = hasher.hash().unwrap();

    if password_clearing {
        assert!(hasher.password().is_none());
        hasher.with_password(args[1].to_string());
    } else {
        assert!(hasher.password().is_some());
    }
    if secret_key_clearing {
        assert!(hasher.secret_key().is_none());
        hasher.with_secret_key(args[3].to_string());
    } else {
        assert!(hasher.secret_key().is_some());
    }
    let hash3 = hasher.hash_raw().unwrap().raw_hash_bytes().to_vec();

    // Verify Rust
    let mut verifier = Verifier::default();
    verifier
        .configure_password_clearing(password_clearing)
        .configure_secret_key_clearing(secret_key_clearing)
        .with_additional_data(args[0])
        .with_hash(&encoded3);
    if password_clearing {
        verifier.with_password(args[1].to_string());
    } else {
        verifier.with_password(args[1]);
    }
    if secret_key_clearing {
        verifier.with_secret_key(args[3].to_string());
    } else {
        verifier.with_secret_key(args[3]);
    }
    let is_valid = verifier.verify().unwrap();

    if password_clearing {
        assert!(verifier.password().is_none());
    } else {
        assert!(verifier.password().is_some());
    }
    if secret_key_clearing {
        assert!(verifier.secret_key().is_none());
    } else {
        assert!(verifier.secret_key().is_some());
    }
    assert!(is_valid);

    // Print results
    println!("{}", &encoded1);
    println!("{}", &encoded2);
    println!("{}", &encoded3);
    println!("{:?}", &hash1);
    println!("{:?}", &hash2);
    println!("{:?}", &hash3);
    println!();

    // Compare results
    if (&encoded1 != &encoded2)
        || (&encoded2 != &encoded3)
        || (&hash1 != &hash2)
        || (&hash2 != &hash3)
    {
        panic!(
            "\nCompare failed:\n{:#?}\n{}\n{}\n{}\n{:?}\n{:?}\n{:?}\n",
            &input, &encoded1, &encoded2, &encoded3, &hash1, &hash2, &hash3,
        );
    }
}

#[test]
#[ignore]
fn test_integration() {
    let build_dir = PathBuf::from("tests/c/build");
    build_c(&build_dir);
    let additional_data_lens = [0, 32];
    let flags = [0b00, 0b01, 0b10, 0b11];
    let hash_lens = [8, 32];
    let iterations = [8, 16];
    let lane_threads = [(1, 1), (4, 4), (4, 1)];
    let memory_sizes = [32, 64];
    let password_lens = [8, 32];
    let salt_lens = [8, 32];
    let secret_key_lens = [0, 32];
    let variants = [Variant::Argon2d, Variant::Argon2i, Variant::Argon2id];
    let versions = [Version::_0x10, Version::_0x13];
    for flags in &flags {
        for additional_data_len in &additional_data_lens {
            for hash_len in &hash_lens {
                for iterations in &iterations {
                    for lane_thread in &lane_threads {
                        for memory_size in &memory_sizes {
                            for password_len in &password_lens {
                                for salt_len in &salt_lens {
                                    for secret_key_len in &secret_key_lens {
                                        for variant in &variants {
                                            for version in &versions {
                                                let input = Input {
                                                    additional_data_len: *additional_data_len,
                                                    build_dir: build_dir.clone(),
                                                    flags: *flags,
                                                    hash_len: *hash_len,
                                                    iterations: *iterations,
                                                    lanes: (*lane_thread).0,
                                                    memory_size: *memory_size,
                                                    password_len: *password_len,
                                                    salt_len: *salt_len,
                                                    secret_key_len: *secret_key_len,
                                                    threads: (*lane_thread).1,
                                                    variant: *variant,
                                                    version: *version,
                                                };
                                                test(&input);
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
    }
}

fn parse_stderr_c(stderr: &[u8]) -> (String, String, Vec<u8>, Vec<u8>) {
    let stderr = ::std::str::from_utf8(stderr).expect("stderr from C is invalid utf-8");
    let v = stderr.trim().split("\n").collect::<Vec<&str>>();
    if v.len() != 4 {
        panic!("invalid stderr from C: {}", stderr);
    }
    let encoded1 = v[0].to_string();
    let encoded2 = v[1].to_string();
    let hash1 = v[2]
        .replace("[", "")
        .replace("]", "")
        .split(",")
        .into_iter()
        .map(|s| Ok::<_, failure::Error>(s.parse::<u8>()?))
        .collect::<Result<Vec<u8>, failure::Error>>()
        .expect("unable to parse hash from C stderr");
    let hash2 = v[3]
        .replace("[", "")
        .replace("]", "")
        .split(",")
        .into_iter()
        .map(|s| Ok::<_, failure::Error>(s.parse::<u8>()?))
        .collect::<Result<Vec<u8>, failure::Error>>()
        .expect("unable to parse hash from C stderr");
    (encoded1, encoded2, hash1, hash2)
}

fn test_c(input: &Input) {
    let args = generate_args(input);
    let args = args.iter().map(|s| (*s).as_ref()).collect::<Vec<&str>>();

    // Run C without simd
    let stderr = run_c("./test_high_level", &input.build_dir, &args);
    let (encoded1, encoded2, hash1, hash2) = parse_stderr_c(&stderr);

    // Run C with simd
    let stderr = run_c("./test_high_level_simd", &input.build_dir, &args);
    let (encoded3, encoded4, hash3, hash4) = parse_stderr_c(&stderr);

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
    if (&encoded1 != &encoded2)
        || (&encoded2 != &encoded3)
        || (&encoded3 != &encoded4)
        || (&hash1 != &hash2)
        || (&hash2 != &hash3)
        || (&hash3 != &hash4)
    {
        panic!(
            "\nCompare failed:\n{:#?}\n{}\n{}\n{}\n{}\n{:?}\n{:?}\n{:?}\n{:?}\n",
            &input, &encoded1, &encoded2, &encoded3, &encoded4, &hash1, &hash2, &hash3, &hash4,
        );
    }
}

#[test]
#[ignore]
fn test_c_code() {
    let build_dir = PathBuf::from("tests/c/build");
    build_c(&build_dir);
    let flags = [0b00]; // Note: for high level, cannot set flags
    let hash_lens = [8, 32];
    let iterations = [8, 32];
    let lane_threads = [(1, 1), (4, 4)]; // Note: for high level, lanes and threads have to be the same
    let memory_sizes = [32, 128];
    let password_lens = [8, 32];
    let salt_lens = [8, 32];
    let variants = [Variant::Argon2d, Variant::Argon2i, Variant::Argon2id];
    let versions = [Version::_0x10, Version::_0x13];
    for flags in &flags {
        for hash_len in &hash_lens {
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
                                            hash_len: *hash_len,
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
                                        test_c(&input);
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
