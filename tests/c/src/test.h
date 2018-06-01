#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "argon2.h"
#include "encoding.h"

typedef struct input {
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
} input_t;

typedef struct hash_output {
    char*       encoded;
    int         err;
    uint8_t*    hash;
    size_t      hash_len;
} hash_output_t;

hash_output_t hash_low_level(input_t* input);
hash_output_t hash_high_level(input_t* input);

void print_encoded(char* encoded);
void print_hash(uint8_t* hash, size_t hash_len);
int parse_args(int argc, char** argv, input_t* input);
int validate_input(input_t* input);

///

void clear_internal_memory(void *v, size_t n);
