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
 * Frees memory associated with a `char *` that was returned from `argonautica_hash`
 */
void argonautica_free(char *string);

/*
 * Hash function that can be called from C that returns a string-encoded hash. This function
 * allocates memory and hands ownership of that memory over to C; so in your C code you must
 * call `argonautica_free` at some point after using the pointer returned from this function
 * in order to avoid leaking memory
 *
 * <u>Arguments (from the perspective of C code):</u>
 * * <b>Additional data</b>:
 *     * To hash <b>with</b> additional data:
 *         * `additional_data` = a `uint8_t*` pointing to the additional data buffer
 *         * `additional_data_len` = a `uint32_t` indicating the number of bytes in the additional data buffer
 *         * This function will <b>not</b> modify the additional data buffer
 *     * To hash <b>without</b> additional data:
 *         * `additional_data` = `NULL`
 *         * `additional_data_len` = `0`
 * * <b>Password</b>:
 *     * `password` = a `uint8_t*` pointing to the password buffer
 *     * `password_len` = a `uint32_t` indicating the number of bytes in the password buffer
 *     * If `password_clearing` (see below) is <b>any value other than zero</b>, this function will set `password` to `NULL`, set `password_len` to `0`, and zero out the bytes in the password buffer
 * * <b>Salt</b>:
 *     * To hash with a <b>random</b> salt:
 *         * `salt` = `NULL`
 *         * `salt_len` = a `uint32_t` indicating the length of the salt (in number of bytes)
 *     * To hash with a <b>deterministic</b> salt
 *         * `salt` = a `uint8_t*` pointing to the salt buffer
 *         * `salt_len` = a `uint32_t` indicating the number of bytes in the salt buffer
 *         * This function will <b>not</b> modify the salt buffer
 * * <b>Secret key</b>:
 *     * To hash <b>with</b> a secret key:
 *         * `secret_key` = a `uint8_t*` pointing to the secret key buffer
 *         * `secret_key_len` = a `uint32_t` indicating the number of bytes in the secret key buffer
 *         * If `secret_key_clearing` (see below) is <b>any value other than zero</b>, this function will set `secret_key` to `NULL`, set `secret_key_len` to `0`, and zero out the bytes in the secret key buffer
 *     * To hash <b>without</b> a secret key:
 *         * `secret_key` = `NULL`
 *         * `secret_key_len` = `0`
 * * <b>Backend</b>
 *     * `backend` = `ARGONAUTICA_C` for the C backend
 *     * `backend` = `ARGONAUTICA_RUST` for the Rust backend
 * * <b>Hash length</b>
 *     * `hash_len` = a `uint32_t` indicating the desired hash length (in number of bytes)
 * * <b>Iterations</b>
 *     * `iterations` = a `uint32_t` indicating the desired number of iterations
 * * <b>Lanes</b>
 *     * `lanes` = a `uint32_t` indicating the desired number of lanes
 * * <b>Memory size</b>
 *     * `memory_size` = a `uint32_t` indicating the desired memory size (in kibibytes)
 * * <b>Password clearing</b>
 *     * If `password_clearing` is <b>any value other than zero</b>, this function will set `password` to `NULL`, set `password_len` to `0`, and zero out the bytes in the password buffer
 * * <b>Secret key clearing</b>
 *     * If `secret_key_clearing` is <b>any value other than zero</b>, this function will set `secret_key` to `NULL`, set `secret_key_len` to `0`, and zero out the bytes in the secret key buffer
 * * <b>Threads</b>
 *     * `threads` = a `uint32_t` indicating the desired number of threads
 * * <b>Variant</b>
 *     * `variant` = `ARGONAUTICA_ARGON2D` for argon2d
 *     * `variant` = `ARGONAUTICA_ARGON2I` for argon2i
 *     * `variant` = `ARGONAUTICA_ARGON2ID` for argon2id
 * * <b>Version</b>
 *     * `version` = `ARGONAUTICA_0x10` for 0x10
 *     * `version` = `ARGONAUTICA_0x13` for 0x13
 * * <b>Error code</b>
 *     * `error_code` = an `argonautica_error_t*` that will be set to `ARGONAUTICA_OK` if there
 *       was no error and another variant of `argonautica_error_t` if an error occurred
 */
const char *argonautica_hash(const uint8_t *additional_data,
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
                             argonautica_version_t version,
                             argonautica_error_t *error_code);

/*
 * Verify function that can be called from C. Unlike `argonautica_hash`, this
 * function does <b>not</b> allocate memory that you need to free; so there is no need
 * to call `argonautica_free` after using this function
 *
 * `encoded` is the string-encoded hash as a `char*`.
 *
 * For a description of the other arguments, see documentation for
 * [`argonautica_hash`](function.argonautica_hash.html)
 */
argonautica_error_t argonautica_verify(const uint8_t *additional_data,
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
