#include "test.h"

static int validate_hash_input(const hash_input_t* input);

hash_result_t hash_low_level(hash_input_t* input)
{
    hash_result_t output = {};
    int err = validate_hash_input(input);
    if (err != ARGON2_OK) {
        output.err = err;
        return output;
    }

    uint8_t* out = (uint8_t*)malloc(input->hash_len);
    if (out == NULL) {
        output.err = ARGON2_MEMORY_ALLOCATION_ERROR;
        return output;
    }

    argon2_context context = {};
    context.out = (uint8_t*)out;
    context.outlen = (uint32_t)(input->hash_len);
    context.pwd = (uint8_t*)(input->password);
    context.pwdlen = (uint32_t)(input->password_len);
    context.salt = (uint8_t*)(input->salt);
    context.saltlen = (uint32_t)(input->salt_len);
    context.secret = (uint8_t*)(input->secret_key);
    context.secretlen = (uint32_t)(input->secret_key_len);
    context.ad = (uint8_t*)(input->additional_data);
    context.adlen = (uint32_t)(input->additional_data_len);
    context.t_cost = input->iterations;
    context.m_cost = input->memory_cost;
    context.lanes = input->lanes;
    context.threads = input->threads;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = input->flags;
    context.version = input->version;

    err = argon2_ctx(&context, input->variant);
    if (err != ARGON2_OK) {
        clear_internal_memory(out, input->hash_len);
        free(out);
        output.err = err;
        return output;
    }

    size_t encoded_len = argon2_encodedlen(
        /* uint32_t t_cost */       input->iterations,
        /* uint32_t m_cost */       input->memory_cost,
        /* uint32_t parallelism */  input->threads,
        /* uint32_t saltlen */      (uint32_t)(input->salt_len),
        /* uint32_t hashlen */      (uint32_t)(input->hash_len),
        /* argon2_type type */      input->variant
    );
    char* encoded = (char*)malloc(encoded_len * sizeof(char));
    if (encoded == NULL) {
        clear_internal_memory(out, input->hash_len);
        free(out);
        output.err = ARGON2_MEMORY_ALLOCATION_ERROR;
        return output;
    }
    uint8_t* hash = (uint8_t*)malloc(input->hash_len * sizeof(uint8_t));
    if (hash == NULL) {
        clear_internal_memory(encoded, encoded_len);
        clear_internal_memory(out, input->hash_len);
        free(encoded);
        free(out);
        output.err = ARGON2_MEMORY_ALLOCATION_ERROR;
        return output;
    }

    memcpy(hash, out, input->hash_len);

    err = encode_string(encoded, encoded_len, &context, input->variant);
    if (err != ARGON2_OK) {
        clear_internal_memory(encoded, encoded_len);
        clear_internal_memory(hash, input->hash_len);
        clear_internal_memory(out, input->hash_len);
        free(encoded);
        free(hash);
        free(out);
        output.err = err;
        return output;
    }

    clear_internal_memory(out, input->hash_len);
    free(out);

    output.encoded = encoded;
    output.err = ARGON2_OK;
    output.hash = hash;
    output.hash_len = input->hash_len;
    return output;
}

hash_result_t hash_high_level(hash_input_t* input)
{
    hash_result_t output = {};
    size_t encoded_len = argon2_encodedlen(
        /* uint32_t t_cost */       input->iterations,
        /* uint32_t m_cost */       input->memory_cost,
        /* uint32_t parallelism */  input->threads,
        /* uint32_t saltlen */      (uint32_t)(input->salt_len),
        /* uint32_t hashlen */      (uint32_t)(input->hash_len),
        /* argon2_type type */      input->variant
    );
    char* encoded = (char*)malloc(encoded_len * sizeof(char));
    if (encoded == NULL) {
        output.err = ARGON2_MEMORY_ALLOCATION_ERROR;
        return output;
    }
    uint8_t* hash = (uint8_t*)malloc(input->hash_len * sizeof(uint8_t));
    if (hash == NULL) {
        output.err = ARGON2_MEMORY_ALLOCATION_ERROR;
        free(encoded);
        return output;
    }
    int err = argon2_hash(
        /* const uint32_t */        input->iterations,
        /* const uint32_t */        input->memory_cost,
        /* const uint32_t */        input->threads,
        /* const void* */           (void*)(input->password),
        /* const size_t */          input->password_len,
        /* const void* */           (void*)(input->salt),
        /* const size_t */          input->salt_len,
        /* void* */                 (void*)hash,
        /* const size_t */          input->hash_len,
        /* char* */                 encoded,
        /* const size_t */          encoded_len,
        /* argon2_type */           input->variant,
        /* const uint32_t */        input->version
    );
    output.encoded = encoded;
    output.err = err;
    output.hash = hash;
    output.hash_len = input->hash_len;
    return output;
}

static int validate_hash_input(const hash_input_t* input)
{
    if (input->password_len > ARGON2_MAX_PWD_LENGTH) {
        return ARGON2_PWD_TOO_LONG;
    }
    if (input->salt_len > ARGON2_MAX_SALT_LENGTH) {
        return ARGON2_SALT_TOO_LONG;
    }
    if (input->hash_len > ARGON2_MAX_OUTLEN) {
        return ARGON2_OUTPUT_TOO_LONG;
    }
    if (input->hash_len < ARGON2_MIN_OUTLEN) {
        return ARGON2_OUTPUT_TOO_SHORT;
    }
    return ARGON2_OK;
}
