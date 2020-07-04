use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    configure_environment();
    compile_argon2();
    generate_bindings();
}

fn configure_environment() {
    for dir in &["phc-winner-argon2/include", "phc-winner-argon2/src"] {
        for entry in fs::read_dir(dir).expect("Unable to read phc-winner-argon2 directory") {
            let entry = entry.expect("Unable to read file in phc-winner-argon2 directory");
            let path = entry.path();
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    for key in &[
        "CC",
        "CFLAGS",
        "CPPFLAGS",
        "CXX",
        "LDFLAGS",
        "LLVM_CONFIG_PATH",
        "SYSROOT",
        "TARGET",
    ] {
        println!("cargo:rerun-if-env-changed={}", key);
    }

    for (k, v) in env::vars() {
        println!("cargo:rustc-env={}={}", k, v);
    }
}

fn compile_argon2() {
    let mut config = cc::Build::new();
    config
        .file("phc-winner-argon2/src/argon2.c")
        .file("phc-winner-argon2/src/blake2/blake2b.c")
        .file("phc-winner-argon2/src/core.c")
        .file("phc-winner-argon2/src/encoding.c")
        .file("phc-winner-argon2/src/thread.c")
        .flag_if_supported("-g")
        .flag_if_supported("-pthread")
        .flag_if_supported("-std=c89")
        .include("phc-winner-argon2/include")
        .include("phc-winner-argon2/src")
        .shared_flag(false)
        .static_flag(true);

    let opt_level = env::var("OPT_LEVEL")
        .expect("Cannot fail")
        .parse::<u32>()
        .expect("Cannot fail");
    config.opt_level(opt_level);

    if can_build_with_optimizations() {
        config.file("phc-winner-argon2/src/opt.c");
    } else {
        config.file("phc-winner-argon2/src/ref.c");
    }

    if let Ok(value) = env::var("CARGO_CFG_TARGET_FEATURE") {
        for item in value.split(",") {
            config.flag_if_supported(&format!("-m{}", item));
        }
    }

    config.compile("libargon2.a");
}

fn generate_bindings() {
    let mut builder = bindgen::Builder::default()
        .header("phc-winner-argon2/include/argon2.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .rustified_enum("Argon2_ErrorCodes")
        .rustified_enum("Argon2_type")
        .rustified_enum("Argon2_version");

    if let Ok(value) = env::var("SYSROOT") {
        builder = builder.clang_arg("--sysroot").clang_arg(value);
    }

    if let Ok(value) = env::var("TARGET") {
        builder = builder.clang_arg("-target").clang_arg(value);
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let path = {
        let out_dir = env::var("OUT_DIR").expect("Cannot fail");
        PathBuf::from(out_dir).join("bindings.rs")
    };

    bindings
        .write_to_file(path)
        .expect("Unable to write bindings");
}

fn can_build_with_optimizations() -> bool {
    let temp = tempfile::tempdir().expect("Unable to create a temporary directory");

    let mut config = cc::Build::new();
    config
        .cargo_metadata(false)
        .file("phc-winner-argon2/src/opt.c")
        .flag("-c")
        .include("phc-winner-argon2/include")
        .include("phc-winner-argon2/src")
        .opt_level(0)
        .out_dir(temp)
        .shared_flag(false)
        .static_flag(true)
        .warnings(false);

    if let Ok(value) = env::var("CARGO_CFG_TARGET_FEATURE") {
        for item in value.split(",") {
            config.flag_if_supported(&format!("-m{}", item));
        }
    }

    config.try_compile("libthrowaway.a").is_ok()
}
