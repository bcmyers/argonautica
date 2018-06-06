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

int argonautica_free(char *string);

const char *argonautica_hash(const uint8_t *additional_data,
                             uint32_t additional_data_len,
                             uint8_t *password,
                             uint32_t password_len,
                             const uint8_t *salt,
                             uint32_t salt_len,
                             uint8_t *secret_key,
                             uint32_t secret_key_len,
                             uint32_t backend,
                             uint32_t hash_len,
                             uint32_t iterations,
                             uint32_t lanes,
                             uint32_t memory_size,
                             int password_clearing,
                             int secret_key_clearing,
                             uint32_t threads,
                             const char *variant,
                             uint32_t version,
                             int *error_code);

int argonautica_verify(const char *hash,
                       const uint8_t *additional_data,
                       uint32_t additional_data_len,
                       uint8_t *password,
                       uint32_t password_len,
                       uint8_t *secret_key,
                       uint32_t secret_key_len,
                       uint32_t backend,
                       int password_clearing,
                       int secret_key_clearing,
                       uint32_t threads);
