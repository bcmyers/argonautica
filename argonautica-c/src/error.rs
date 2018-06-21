#![allow(non_camel_case_types)]

use argonautica::Error;
use libc::c_char;

/// Given an `argonautica_error_t`, this function will return an error message as a static `char*`
#[no_mangle]
pub extern "C" fn argonautica_error_msg(err: argonautica_error_t) -> *const c_char {
    err.to_str()
}

/// Argonautica errors
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(C)]
pub enum argonautica_error_t {
    /// OK. No error occurred
    ARGONAUTICA_OK = 0,

    /// Additional data too long. Length in bytes must be less than 2^32
    ARGONAUTICA_ERROR_ADDITIONAL_DATA_TOO_LONG = 1,

    /// Rust backend not yet supported. Please use the C backend
    ARGONAUTICA_ERROR_BACKEND_UNSUPPORTED = 2,

    /// Base64 decode error. Bytes provided were invalid base64
    ARGONAUTICA_ERROR_BASE64_DECODE = 3,

    /// This is a bug in the argonautica crate and should not occur. Please file an issue
    ARGONAUTICA_ERROR_BUG = 4,

    /// Hash decode error. Hash provided was invalid
    ARGONAUTICA_ERROR_HASH_DECODE = 5,

    /// Hash length too short. Hash length must be at least 4
    ARGONAUTICA_ERROR_HASH_LEN_TOO_SHORT = 6,

    /// Hash missing. Attempted to verify without first having provided a hash
    ARGONAUTICA_ERROR_HASH_MISSING = 7,

    /// Iterations too few. Iterations must be greater than 0
    ARGONAUTICA_ERROR_ITERATIONS_TOO_FEW = 8,

    /// Lanes too few. Lanes must be greater than 0
    ARGONAUTICA_ERROR_LANES_TOO_FEW = 9,

    /// Lanes too many. Lanes must be less than 2^24
    ARGONAUTICA_ERROR_LANES_TOO_MANY = 10,

    /// Attempted to allocate memory (using malloc) and failed
    ARGONAUTICA_ERROR_MEMORY_ALLOCATION = 11,

    /// Memory size invalid. Memory size must be a power of two
    ARGONAUTICA_ERROR_MEMORY_SIZE_INVALID = 12,

    /// Memory size too small. Memory size must be at least 8 times the number of lanes
    ARGONAUTICA_ERROR_MEMORY_SIZE_TOO_SMALL = 13,

    /// Null pointer error. Passed a null pointer as an argument where that is not allowed
    ARGONAUTICA_ERROR_NULL_PTR = 14,

    /// Failed to access OS random number generator
    ARGONAUTICA_ERROR_OS_RNG = 15,

    /// Password missing. Attempted to verify without first having provided a password
    ARGONAUTICA_ERROR_PASSWORD_MISSING = 16,

    /// Password too short. Length in bytes must be greater than 0
    ARGONAUTICA_ERROR_PASSWORD_TOO_SHORT = 17,

    /// Password too long. Length in bytes must be less than 2^32
    ARGONAUTICA_ERROR_PASSWORD_TOO_LONG = 18,

    /// Salt too short. Length in bytes must be at least 8
    ARGONAUTICA_ERROR_SALT_TOO_SHORT = 19,

    /// Salt too long. Length in bytes must be less than 2^32
    ARGONAUTICA_ERROR_SALT_TOO_LONG = 20,

    /// Secret key too long. Length in bytes must be less than 2^32
    ARGONAUTICA_ERROR_SECRET_KEY_TOO_LONG = 21,

    /// Threading failure
    ARGONAUTICA_ERROR_THREAD = 22,

    /// Threads too few. Threads must be greater than 0
    ARGONAUTICA_ERROR_THREADS_TOO_FEW = 23,

    /// Threads too many. Threads must be less than 2^24
    ARGONAUTICA_ERROR_THREADS_TOO_MANY = 24,

    /// Utf-8 encode error. Bytes provided could not be encoded into utf-8
    ARGONAUTICA_ERROR_UTF8_ENCODE = 25,
}

impl argonautica_error_t {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn to_str(&self) -> *const c_char {
        use argonautica_error_t::*;
        let s: &'static [u8] = match self {
            ARGONAUTICA_OK => b"OK. No error occurred\0",
            ARGONAUTICA_ERROR_ADDITIONAL_DATA_TOO_LONG => b"Additional data too long. Length in bytes must be less than 2^32\0",
            ARGONAUTICA_ERROR_BACKEND_UNSUPPORTED => b"Rust backend not yet supported. Please use the C backend\0",
            ARGONAUTICA_ERROR_BASE64_DECODE => b"Base64 decode error. Bytes provided were invalid base64\0",
            ARGONAUTICA_ERROR_BUG => b"This is a bug in the argonautica crate and should not occur. Please file an issue\0",
            ARGONAUTICA_ERROR_HASH_DECODE => b"Hash decode error. Hash provided was invalid\0",
            ARGONAUTICA_ERROR_HASH_LEN_TOO_SHORT => b"Hash length too short. Hash length must be at least 4\0",
            ARGONAUTICA_ERROR_HASH_MISSING => b"Hash missing. Attempted to verify without first having provided a hash\0",
            ARGONAUTICA_ERROR_ITERATIONS_TOO_FEW => b"Iterations too few. Iterations must be greater than 0\0",
            ARGONAUTICA_ERROR_LANES_TOO_FEW => b"Lanes too few. Lanes must be greater than 0\0",
            ARGONAUTICA_ERROR_LANES_TOO_MANY => b"Lanes too many. Lanes must be less than 2^24\0",
            ARGONAUTICA_ERROR_MEMORY_ALLOCATION => b"Attempted to allocate memory (using malloc) and failed\0",
            ARGONAUTICA_ERROR_MEMORY_SIZE_INVALID => b"Memory size invalid. Memory size must be a power of two\0",
            ARGONAUTICA_ERROR_MEMORY_SIZE_TOO_SMALL => b"Memory size too small. Memory size must be at least 8 times the number of lanes\0",
            ARGONAUTICA_ERROR_NULL_PTR => b"Null pointer error. Passed a null pointer as an argument where that is not allowed\0",
            ARGONAUTICA_ERROR_OS_RNG => b"Failed to access OS random number generator\0",
            ARGONAUTICA_ERROR_PASSWORD_MISSING => b"Password missing. Attempted to verify without first having provided a password\0",
            ARGONAUTICA_ERROR_PASSWORD_TOO_SHORT => b"Password too short. Length in bytes must be greater than 0\0",
            ARGONAUTICA_ERROR_PASSWORD_TOO_LONG => b"Password too long. Length in bytes must be less than 2^32\0",
            ARGONAUTICA_ERROR_SALT_TOO_SHORT => b"Salt too short. Length in bytes must be at least 8\0",
            ARGONAUTICA_ERROR_SALT_TOO_LONG => b"Salt too long. Length in bytes must be less than 2^32\0",
            ARGONAUTICA_ERROR_SECRET_KEY_TOO_LONG => b"Secret key too long. Length in bytes must be less than 2^32\0",
            ARGONAUTICA_ERROR_THREAD => b"Threading failure\0",
            ARGONAUTICA_ERROR_THREADS_TOO_FEW => b"Threads too few. Threads must be greater than 0\0",
            ARGONAUTICA_ERROR_THREADS_TOO_MANY => b"Threads too many. Threads must be less than 2^24\0",
            ARGONAUTICA_ERROR_UTF8_ENCODE => b"Utf-8 encode error. Bytes provided could not be encoded into utf-8\0",
        };
        s.as_ptr() as *const c_char
    }
}

impl From<Error> for argonautica_error_t {
    fn from(err: Error) -> argonautica_error_t {
        use argonautica::ErrorKind::*;
        use argonautica_error_t::*;
        match err.kind() {
            AdditionalDataTooLongError => ARGONAUTICA_ERROR_ADDITIONAL_DATA_TOO_LONG,
            BackendEncodeError => ARGONAUTICA_ERROR_BUG,
            BackendUnsupportedError => ARGONAUTICA_ERROR_BACKEND_UNSUPPORTED,
            Base64DecodeError => ARGONAUTICA_ERROR_BASE64_DECODE,
            Bug => ARGONAUTICA_ERROR_BUG,
            HashDecodeError => ARGONAUTICA_ERROR_HASH_DECODE,
            HashLenTooShortError => ARGONAUTICA_ERROR_HASH_LEN_TOO_SHORT,
            HashMissingError => ARGONAUTICA_ERROR_HASH_MISSING,
            IterationsTooFewError => ARGONAUTICA_ERROR_ITERATIONS_TOO_FEW,
            LanesTooFewError => ARGONAUTICA_ERROR_LANES_TOO_FEW,
            LanesTooManyError => ARGONAUTICA_ERROR_LANES_TOO_MANY,
            MemoryAllocationError => ARGONAUTICA_ERROR_MEMORY_ALLOCATION,
            MemorySizeInvalidError => ARGONAUTICA_ERROR_MEMORY_SIZE_INVALID,
            MemorySizeTooSmallError => ARGONAUTICA_ERROR_MEMORY_SIZE_TOO_SMALL,
            OsRngError => ARGONAUTICA_ERROR_OS_RNG,
            PasswordImmutableError => ARGONAUTICA_ERROR_BUG,
            PasswordMissingError => ARGONAUTICA_ERROR_PASSWORD_MISSING,
            PasswordTooLongError => ARGONAUTICA_ERROR_PASSWORD_TOO_LONG,
            PasswordTooShortError => ARGONAUTICA_ERROR_PASSWORD_TOO_SHORT,
            SaltTooLongError => ARGONAUTICA_ERROR_SALT_TOO_LONG,
            SaltTooShortError => ARGONAUTICA_ERROR_SALT_TOO_SHORT,
            SecretKeyImmutableError => ARGONAUTICA_ERROR_BUG,
            SecretKeyMissingError => ARGONAUTICA_ERROR_BUG,
            SecretKeyTooLongError => ARGONAUTICA_ERROR_SECRET_KEY_TOO_LONG,
            ThreadError => ARGONAUTICA_ERROR_THREAD,
            ThreadsTooFewError => ARGONAUTICA_ERROR_THREADS_TOO_FEW,
            ThreadsTooManyError => ARGONAUTICA_ERROR_THREADS_TOO_MANY,
            Utf8EncodeError => ARGONAUTICA_ERROR_UTF8_ENCODE,
            VariantEncodeError => ARGONAUTICA_ERROR_BUG,
            VersionEncodeError => ARGONAUTICA_ERROR_BUG,
            __Nonexhaustive => ARGONAUTICA_ERROR_BUG,
        }
    }
}
