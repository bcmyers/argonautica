#[derive(Copy, Clone, Debug, Eq, PartialEq, Fail)]
pub enum ErrorKind {
    #[fail(display = "Additional data too long. Length in bytes must be less than 2^32.")]
    AdditionalDataTooLong,

    #[fail(display = "Rust backend not yet supported. Please use the C backend.")]
    BackendUnsupported,

    #[fail(display = "A fatal error occurred: code {}. This is an error with \
                      the a2 crate and should not happen. Please file an issue.",
           _0)]
    Fatal(i32),

    #[fail(display = "Hash encoding error.")]
    HashEncoding,

    #[fail(display = "Hash invalid.")]
    HashInvalid,

    #[fail(display = "Hash length too short. Hash length must be at least 4")]
    HashLengthTooShort,

    #[fail(display = "Invalid base64.")]
    InvalidBase64,

    #[fail(display = "Invalid utf-8.")]
    InvalidUtf8,

    #[fail(display = "Too few iterations. Iterations must be greater than 0.")]
    IterationsTooFew,

    #[fail(display = "Too few lanes. Lanes must be greater than 0.")]
    LanesTooFew,

    #[fail(display = "Too many lanes. Lanes must be less than 2^24.")]
    LanesTooMany,

    #[fail(display = "Invalid memory size. Memory size must be a power of two.")]
    MemorySizeInvalid,

    #[fail(display = "Memory size too small. Memory size must be at least 8 times the number of lanes.")]
    MemorySizeTooSmall,

    #[fail(display = "Failed to create random number generator. Not enough OS entropy.")]
    OsRng,

    #[fail(display = "Failed to parse Variant.")]
    ParseVariant,

    #[fail(display = "Failed to parse Version.")]
    ParseVersion,

    #[fail(display = "Password too short. Length in bytes must be greater than 0.")]
    PasswordTooShort,

    #[fail(display = "Password too long. Length in bytes must be less than 2^32.")]
    PasswordTooLong,

    #[fail(display = "Attempted to use a non-random salt without having opted out of random salt.")]
    SaltNonRandom,

    #[fail(display = "Salt too short. Length in bytes must be at least 8.")]
    SaltTooShort,

    #[fail(display = "Salt too long. Length in bytes must be less than 2^32.")]
    SaltTooLong,

    #[fail(display = "Trying to hash without a secret key when you have not explicitly opted out of using a secret key.")]
    SecretKeyMissing,

    #[fail(display = "Secret key too long. Length in bytes must be less than 2^32.")]
    SecretKeyTooLong,

    #[fail(display = "Too many threads. Threads must be less than 2^24.")]
    ThreadsTooMany,
}

// ARGON2_OK = 0,

// ARGON2_OUTPUT_PTR_NULL = -1,

// ARGON2_OUTPUT_TOO_SHORT = -2,
// ARGON2_OUTPUT_TOO_LONG = -3,

// ARGON2_PWD_TOO_SHORT = -4,
// ARGON2_PWD_TOO_LONG = -5,

// ARGON2_SALT_TOO_SHORT = -6,
// ARGON2_SALT_TOO_LONG = -7,

// ARGON2_AD_TOO_SHORT = -8,
// ARGON2_AD_TOO_LONG = -9,

// ARGON2_SECRET_TOO_SHORT = -10,
// ARGON2_SECRET_TOO_LONG = -11,

// ARGON2_TIME_TOO_SMALL = -12,
// ARGON2_TIME_TOO_LARGE = -13,

// ARGON2_MEMORY_TOO_LITTLE = -14,
// ARGON2_MEMORY_TOO_MUCH = -15,

// ARGON2_LANES_TOO_FEW = -16,
// ARGON2_LANES_TOO_MANY = -17,

// ARGON2_PWD_PTR_MISMATCH = -18,    /* NULL ptr with non-zero length */
// ARGON2_SALT_PTR_MISMATCH = -19,   /* NULL ptr with non-zero length */
// ARGON2_SECRET_PTR_MISMATCH = -20, /* NULL ptr with non-zero length */
// ARGON2_AD_PTR_MISMATCH = -21,     /* NULL ptr with non-zero length */

// ARGON2_MEMORY_ALLOCATION_ERROR = -22,

// ARGON2_FREE_MEMORY_CBK_NULL = -23,
// ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24,

// ARGON2_INCORRECT_PARAMETER = -25,
// ARGON2_INCORRECT_TYPE = -26,

// ARGON2_OUT_PTR_MISMATCH = -27,

// ARGON2_THREADS_TOO_FEW = -28,
// ARGON2_THREADS_TOO_MANY = -29,

// ARGON2_MISSING_ARGS = -30,

// ARGON2_ENCODING_FAIL = -31,

// ARGON2_DECODING_FAIL = -32,

// ARGON2_THREAD_FAIL = -33,

// ARGON2_DECODING_LENGTH_FAIL = -34,

// ARGON2_VERIFY_MISMATCH = -35
