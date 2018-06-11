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
   * No error occurred
   */
  ARGONAUTICA_OK = 0,
  /*
   * TODO:
   */
  ARGONAUTICA_ERROR1 = 1,
  /*
   * TODO:
   */
  ARGONAUTICA_ERROR2 = 2,
} argonautica_error_t;

/*
 * Available argon2 variants
 */
typedef enum {
  /*
   * argon2d
   */
  ARGONAUTICA_ARGON2D = 1,
  /*
   * argond2i
   */
  ARGONAUTICA_ARGON2I = 2,
  /*
   * argon2id
   */
  ARGONAUTICA_ARGON2ID = 3,
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
 * Function that returns the length of a string-encoded hash (in bytes and including the NULL byte)
 */
int argonautica_encoded_len(uint32_t hash_len,
                            uint32_t iterations,
                            uint32_t lanes,
                            uint32_t memory_size,
                            uint32_t salt_len,
                            argonautica_variant_t variant);

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
