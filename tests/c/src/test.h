#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argon2.h"
#include "blake2-impl.h"
#include "core.h"
#include "encoding.h"

typedef struct hash_input {
    uint8_t*    additional_data;
    size_t      additional_data_len;
    uint8_t*    password;
    size_t      password_len;
    uint8_t*    salt;
    size_t      salt_len;
    uint8_t*    secret_key;
    size_t      secret_key_len;
    size_t      hash_len;
    uint32_t    iterations;
    uint32_t    lanes;
    uint32_t    memory_cost;
    uint32_t    threads;
    argon2_type variant;
    uint32_t    version;
} hash_input_t;

typedef struct hash_result {
    char*               encoded;
    argon2_error_codes  err;
    uint8_t*            hash;
    size_t              hash_len;
} hash_result_t;

typedef struct verify_input {
    char*           encoded;
    uint8_t*        additional_data;
    size_t          additional_data_len;
    uint8_t*        password;
    size_t          password_len;
    uint8_t*        secret_key;
    size_t          secret_key_len;
    argon2_type     variant;
} verify_input_t;

typedef struct verify_result {
    argon2_error_codes  err;
    bool                is_valid;
} verify_result_t;

hash_result_t hash_low_level(hash_input_t* input);
hash_result_t hash_high_level(hash_input_t* input);
verify_result_t verify_high_level(verify_input_t* input);
verify_result_t verify_low_level(verify_input_t* input);

int parse_args(int argc, char** argv, bool is_secret_key, hash_input_t* input);
void print_encoded(const char* encoded);
void print_hash(const uint8_t* hash, const size_t hash_len);
