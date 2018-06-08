#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define DEFAULT_HASH_LENGTH 32

#define DEFAULT_ITERATIONS 192

#define DEFAULT_MEMORY_SIZE 4096

#define DEFAULT_OPT_OUT_OF_RANDOM_SALT false

#define DEFAULT_OPT_OUT_OF_SECRET_KEY false

#define DEFAULT_PASSWORD_CLEARING false

#define DEFAULT_SALT_LENGTH 32

#define DEFAULT_SECRET_KEY_CLEARING false

/*
 * Available backends
 */
typedef enum {
  /*
   * TODO:
   */
  ARGONAUTICA_C = 0,
  /*
   * TODO:
   */
  ARGONAUTICA_RUST = 1,
} argonautica_backend_t;

/*
 * Argonautica errors
 */
typedef enum {
  /*
   * TODO:
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
   * TODO:
   */
  ARGONAUTICA_ARGON2D = 1,
  /*
   * TODO:
   */
  ARGONAUTICA_ARGON2I = 2,
  /*
   * TODO:
   */
  ARGONAUTICA_ARGON2ID = 3,
} argonautica_variant_t;

/*
 * Available argon2 versions
 */
typedef enum {
  /*
   * TODO:
   */
  ARGONAUTICA_0x10 = 13,
  /*
   * TODO:
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
 * <b><u>Arguments (from the perspective of C code):</u></b>
 * * <b>Additional data</b>:
 *     * To hash <b>with</b> additional data:
 *         * `additional_data_ptr` = a `uint32_t*` pointing to the additional data buffer
 *         * `additional_data_len` = a `size_t` indicating the number of bytes in the additional data buffer
 *         * If `additional_data_len` exceeds 2^32 -1, this function will return `NULL`
 *         * This function will <b>not</b> modify the additional data buffer
 *     * To hash <b>without</b> additional data:
 *         * `additional_data_ptr` = `NULL`
 *         * `additional_data_len` = `0`
 * * <b>Password</b>:
 *     * `password_ptr` = a `uint32_t*` pointing to the password buffer
 *     * `password_len` = a `size_t` indicating the number of bytes in the password buffer
 *     * If `password_len` exceeds 2^32 -1, this function will return `NULL`
 *     * If `password_clearing` = `1` (see below), this function will set the `password_ptr` to `NULL`, set the `password_len` to `0`, and zero out the bytes in the password buffer
 * * <b>Salt</b>:
 *     * To hash with a <b>random</b> salt:
 *         * `salt_ptr` = `NULL`
 *         * `salt_len` = a `size_t` indicating the length of the salt (in number of bytes)
 *         * If `salt_len` is less than 8 or exceeds 2^32 -1, this function will return `NULL`
 *     * To hash with a <b>deterministic</b> salt
 *         * `salt_ptr` = a `uint32_t*` pointing to the salt buffer
 *         * `salt_len` = a `size_t` indicating the number of bytes in the salt buffer
 *         * If `salt_len` is less than 8 or exceeds 2^32 -1, this function will return `NULL`
 *         * This function will <b>not</b> modify the salt buffer
 * * <b>Secret key</b>:
 *     * To hash <b>with</b> a secret key:
 *         * `secret_key_ptr` = a `uint32_t*` pointing to the secret key buffer
 *         * `secret_key_len` = a `size_t` indicating the number of bytes in the secret key buffer
 *         * If `secret_key_len` exceeds 2^32 -1, this function will return `NULL`
 *         * If `secret_key_clearing` = `1` (see below), this function will set the `secret_key_ptr` to `NULL`, set the `secret_key_len` to `0`, and zero out the bytes in the secret key buffer
 *     * To hash <b>without</b> a secret key:
 *         * `secret_key_ptr` = `NULL`
 *         * `secret_key_len` = `0`
 * * <b>Backend</b>
 *     * `backend` = `1` for the C backend
 *     * `backend` = `2` for the Rust backend
 *     * If `backend` is anything else, this function will return `NULL`
 * *<b>Hash length</b>: `hash_length` = a `size_t` indicating the desired length of the hash (in number of bytes)
 * *<b>Iterations</b>: `iterations` = a `size_t` indicating the desired number of iterations
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
 * function does <b>not</b> allocate memory that needs to be freed from C; so there is no need
 * to call `argonautica_free` after using this function
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
