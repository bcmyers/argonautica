#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/*
 * Available backends
 */
typedef enum {
  /*
   * The C backend
   */
  ARGONAUTICA_C = 0,
  /*
   * The Rust backend
   */
  ARGONAUTICA_RUST = 1,
} argonautica_backend_t;

/*
 * Argonautica errors
 */
typedef enum {
  /*
   * OK. No error occurred
   */
  ARGONAUTICA_OK = 0,
  /*
   * Additional data too long. Length in bytes must be less than 2^32
   */
  ARGONAUTICA_ERROR_ADDITIONAL_DATA_TOO_LONG = 1,
  /*
   * Rust backend not yet supported. Please use the C backend
   */
  ARGONAUTICA_ERROR_BACKEND_UNSUPPORTED = 2,
  /*
   * Base64 decode error. Bytes provided were invalid base64
   */
  ARGONAUTICA_ERROR_BASE64_DECODE = 3,
  /*
   * This is a bug in the argonautica crate and should not occur. Please file an issue
   */
  ARGONAUTICA_ERROR_BUG = 4,
  /*
   * Hash decode error. Hash provided was invalid
   */
  ARGONAUTICA_ERROR_HASH_DECODE = 5,
  /*
   * Hash length too short. Hash length must be at least 4
   */
  ARGONAUTICA_ERROR_HASH_LEN_TOO_SHORT = 6,
  /*
   * Hash missing. Attempted to verify without first having provided a hash
   */
  ARGONAUTICA_ERROR_HASH_MISSING = 7,
  /*
   * Iterations too few. Iterations must be greater than 0
   */
  ARGONAUTICA_ERROR_ITERATIONS_TOO_FEW = 8,
  /*
   * Lanes too few. Lanes must be greater than 0
   */
  ARGONAUTICA_ERROR_LANES_TOO_FEW = 9,
  /*
   * Lanes too many. Lanes must be less than 2^24
   */
  ARGONAUTICA_ERROR_LANES_TOO_MANY = 10,
  /*
   * Attempted to allocate memory (using malloc) and failed
   */
  ARGONAUTICA_ERROR_MEMORY_ALLOCATION = 11,
  /*
   * Memory size invalid. Memory size must be a power of two
   */
  ARGONAUTICA_ERROR_MEMORY_SIZE_INVALID = 12,
  /*
   * Memory size too small. Memory size must be at least 8 times the number of lanes
   */
  ARGONAUTICA_ERROR_MEMORY_SIZE_TOO_SMALL = 13,
  /*
   * Null pointer error. Passed a null pointer as an argument where that is not allowed
   */
  ARGONAUTICA_ERROR_NULL_PTR = 14,
  /*
   * Failed to access OS random number generator
   */
  ARGONAUTICA_ERROR_OS_RNG = 15,
  /*
   * Password missing. Attempted to verify without first having provided a password
   */
  ARGONAUTICA_ERROR_PASSWORD_MISSING = 16,
  /*
   * Password too short. Length in bytes must be greater than 0
   */
  ARGONAUTICA_ERROR_PASSWORD_TOO_SHORT = 17,
  /*
   * Password too long. Length in bytes must be less than 2^32
   */
  ARGONAUTICA_ERROR_PASSWORD_TOO_LONG = 18,
  /*
   * Salt too short. Length in bytes must be at least 8
   */
  ARGONAUTICA_ERROR_SALT_TOO_SHORT = 19,
  /*
   * Salt too long. Length in bytes must be less than 2^32
   */
  ARGONAUTICA_ERROR_SALT_TOO_LONG = 20,
  /*
   * Secret key too long. Length in bytes must be less than 2^32
   */
  ARGONAUTICA_ERROR_SECRET_KEY_TOO_LONG = 21,
  /*
   * Threading failure
   */
  ARGONAUTICA_ERROR_THREAD = 22,
  /*
   * Threads too few. Threads must be greater than 0
   */
  ARGONAUTICA_ERROR_THREADS_TOO_FEW = 23,
  /*
   * Threads too many. Threads must be less than 2^24
   */
  ARGONAUTICA_ERROR_THREADS_TOO_MANY = 24,
  /*
   * Utf-8 encode error. Bytes provided could not be encoded into utf-8
   */
  ARGONAUTICA_ERROR_UTF8_ENCODE = 25,
} argonautica_error_t;

/*
 * Available argon2 variants
 */
typedef enum {
  /*
   * argon2d
   */
  ARGONAUTICA_ARGON2D = 0,
  /*
   * argond2i
   */
  ARGONAUTICA_ARGON2I = 1,
  /*
   * argon2id
   */
  ARGONAUTICA_ARGON2ID = 2,
} argonautica_variant_t;

/*
 * Available argon2 versions
 */
typedef enum {
  /*
   * 0x10
   */
  ARGONAUTICA_0x10 = 13,
  /*
   * 0x13
   */
  ARGONAUTICA_0x13 = 16,
} argonautica_version_t;

/*
 * Function that returns the length of a string-encoded hash (in bytes and including the NULL byte).
 * If an error occurrs, the function returns -1
 */
int argonautica_encoded_len(uint32_t hash_len,
                            uint32_t iterations,
                            uint32_t lanes,
                            uint32_t memory_size,
                            uint32_t salt_len,
                            argonautica_variant_t variant);

/*
 * Given an `argonautica_error_t`, this function will return an error message as a static `char*`
 */
const char *argonautica_error_msg(argonautica_error_t err);

/*
 * Function that hashes a password. It will modify the provided `encoded` buffer
 * and return an `argonautica_error_t` indicating whether or not the hash was successful.
 *
 * Arguments (from the perspective of C code):
 * * Encoded:
 *     * `encoded` = a `char*` that points to a buffer whose length (in bytes) is sufficient
 *       to hold the resulting string-encoded hash (including it's NULL byte)
 *     * To determine what the length of the string-encoded hash will be
 *       ahead of time (including the NULL byte), use the `argonautica_encoded_len` function
 *     * This function will modify the encoded buffer (that's it's whole point :))
 * * Additional data:
 *     * To hash with additional data:
 *         * `additional_data` = a `uint8_t*` pointing to the additional data buffer
 *         * `additional_data_len` = a `uint32_t` indicating the number of bytes in the additional data buffer
 *         * This function will not modify the additional data buffer
 *     * To hash <b>without</b> additional data:
 *         * `additional_data` = `NULL`
 *         * `additional_data_len` = `0`
 * * Password:
 *     * `password` = a `uint8_t*` pointing to the password buffer
 *     * `password_len` = a `uint32_t` indicating the number of bytes in the password buffer
 *     * If `password_clearing` (see below) is any value other than zero, this function will set `password` to `NULL`, set `password_len` to `0`, and zero out the bytes in the password buffer
 * * Salt:
 *     * To hash with a random salt (which is recommended):
 *         * `salt` = `NULL`
 *         * `salt_len` = a `uint32_t` indicating the length of the salt (in number of bytes)
 *     * To hash with a deterministic salt (which is not recommended)
 *         * `salt` = a `uint8_t*` pointing to the salt buffer
 *         * `salt_len` = a `uint32_t` indicating the number of bytes in the salt buffer
 *         * This function will not modify the salt buffer
 * * Secret key:
 *     * To hash with a secret key (which is recommended):
 *         * `secret_key` = a `uint8_t*` pointing to the secret key buffer
 *         * `secret_key_len` = a `uint32_t` indicating the number of bytes in the secret key buffer
 *         * If `secret_key_clearing` (see below) is any value other than zero, this function will set `secret_key` to `NULL`, set `secret_key_len` to `0`, and zero out the bytes in the secret key buffer
 *     * To hash without a secret key (which is not recommended):
 *         * `secret_key` = `NULL`
 *         * `secret_key_len` = `0`
 * * Backend:
 *     * `backend` = `ARGONAUTICA_C` for the C backend
 *     * `backend` = `ARGONAUTICA_RUST` for the Rust backend
 * * Hash length:
 *     * `hash_len` = a `uint32_t` indicating the desired hash length (in number of bytes)
 * * Iterations:
 *     * `iterations` = a `uint32_t` indicating the desired number of iterations
 * * Lanes:
 *     * `lanes` = a `uint32_t` indicating the desired number of lanes
 * * Memory size:
 *     * `memory_size` = a `uint32_t` indicating the desired memory size (in kibibytes)
 * * Password clearing:
 *     * If `password_clearing` is any value other than zero, this function will set `password` to `NULL`, set `password_len` to `0`, and zero out the bytes in the password buffer
 * * Secret key clearing:
 *     * If `secret_key_clearing` is any value other than zero, this function will set `secret_key` to `NULL`, set `secret_key_len` to `0`, and zero out the bytes in the secret key buffer
 * * Threads:
 *     * `threads` = a `uint32_t` indicating the desired number of threads
 * * Variant:
 *     * `variant` = `ARGONAUTICA_ARGON2D` for argon2d
 *     * `variant` = `ARGONAUTICA_ARGON2I` for argon2i
 *     * `variant` = `ARGONAUTICA_ARGON2ID` for argon2id
 * * Version:
 *     * `version` = `ARGONAUTICA_0x10` for 0x10
 *     * `version` = `ARGONAUTICA_0x13` for 0x13
 */
argonautica_error_t argonautica_hash(char *encoded,
                                     const uint8_t *additional_data,
                                     uint32_t additional_data_len,
                                     uint8_t *password,
                                     uint32_t password_len,
                                     const uint8_t *salt,
                                     uint32_t salt_len,
                                     uint8_t *secret_key,
                                     uint32_t secret_key_len,
                                     argonautica_backend_t backend,
                                     uint32_t hash_len,
                                     uint32_t iterations,
                                     uint32_t lanes,
                                     uint32_t memory_size,
                                     int password_clearing,
                                     int secret_key_clearing,
                                     uint32_t threads,
                                     argonautica_variant_t variant,
                                     argonautica_version_t version);

/*
 * Function that verifies a password against a hash. It will modify the provided `is_valid` int
 * and return an `argonautica_error_t` indicating whether or not the verification was successful.
 *
 * On success, `is_valid` will be modified to be `1` if the hash / password combination is valid
 * or `0` if the hash / password combination is not valid.
 *
 * `encoded` is a `char*` pointing to the string-encoded hash.
 *
 * For a description of the other arguments, see the documentation for
 * `argonautica_hash`
 */
argonautica_error_t argonautica_verify(int *is_valid,
                                       const uint8_t *additional_data,
                                       uint32_t additional_data_len,
                                       const char *encoded,
                                       uint8_t *password,
                                       uint32_t password_len,
                                       uint8_t *secret_key,
                                       uint32_t secret_key_len,
                                       argonautica_backend_t backend,
                                       int password_clearing,
                                       int secret_key_clearing,
                                       uint32_t threads);
