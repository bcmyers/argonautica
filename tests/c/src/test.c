#include "test.h"

int main(int argc, char** argv)
{
    input_t input = {};
    int err = parse_args(argc, argv, &input);
    if (err != 0) {
        exit(1);
    }

    hash_output_t result1 = hash_high_level(&input);
    if(result1.err != ARGON2_OK) {
        fprintf(stdout, "Error: %s\n", argon2_error_message(result1.err));
        exit(1);
    }

    hash_output_t result2 = hash_low_level(&input);
    if(result2.err != ARGON2_OK) {
        fprintf(stdout, "Error: %s\n", argon2_error_message(result2.err));
        exit(1);
    }

    print_encoded(result1.encoded);
    print_encoded(result2.encoded);
    print_hash(result1.hash, result1.hash_len);
    print_hash(result2.hash, result2.hash_len);

    free(result1.encoded);
    free(result1.hash);
    free(result2.encoded);
    free(result2.hash);

    return 0;
}

hash_output_t hash_high_level(input_t* input) {
    hash_output_t output = {};
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

hash_output_t hash_low_level(input_t* input) {
    hash_output_t output = {};
    int err = validate_input(input);
    if (err != ARGON2_OK) {
        output.err = err;
        return output;
    }

    uint8_t* out = malloc(input->hash_len);
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
    context.flags = 0;
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

void print_encoded(char* encoded) {
    fprintf(stderr, "%s\n", encoded);
}

void print_hash(uint8_t* hash, size_t hash_len) {
    int i;
    for (i = 0; i < hash_len; i++) {
        if (i == 0) {
            fprintf(stderr, "[%d,", hash[i]);
        } else if (i == hash_len - 1) {
            fprintf(stderr, "%d]\n", hash[i]);
        } else {
            fprintf(stderr, "%d,", hash[i]);
        }
    }
}

int parse_args(int argc, char** argv, input_t* input)
{
    if (argc != 12) {
        fprintf(stdout,
            "Usage: [bin] [additional data] [password] [salt]"
                   "[secret key] [hash_length] [iterations] [lanes]"
                   "[memory_cost] [threads] [variant] [version]\n"
        );
        return -1;
    }

    char* additional_data_str   = argv[1];
    char* password_str          = argv[2];
    char* salt_str              = argv[3];
    char* secret_key_str        = argv[4];
    char* hash_len_str          = argv[5];
    char* iterations_str        = argv[6];
    char* lanes_str             = argv[7];
    char* memory_cost_str       = argv[8];
    char* threads_str           = argv[9];
    char* variant_str           = argv[10];
    char* version_str           = argv[11];

    uint8_t* additional_data    = (uint8_t*)additional_data_str;
    size_t additional_data_len  = strlen(additional_data_str);
    uint8_t* password           = (uint8_t*)password_str;
    size_t password_len         = strlen(password_str);
    uint8_t* salt               = (uint8_t*)salt_str;
    size_t salt_len             = strlen(salt_str);
    uint8_t* secret_key         = (uint8_t*)secret_key_str;
    size_t secret_key_len       = strlen(secret_key_str);
    size_t hash_len             = (size_t)(atoi(hash_len_str));
    uint32_t iterations         = (uint32_t)(atoi(iterations_str));
    uint32_t lanes              = (uint32_t)(atoi(lanes_str));
    uint32_t memory_cost        = (uint32_t)(atoi(memory_cost_str));
    uint32_t threads            = (uint32_t)(atoi(threads_str));

    argon2_type variant;
    switch (atoi(variant_str)) {
        case 1:
        {
            variant = Argon2_d;
        } break;
        case 2:
        {
            variant = Argon2_i;
        } break;
        case 3:
        {
            variant = Argon2_id;
        } break;
        default:
        {
            fprintf(stdout, "Invalid variant\n");
            return -1;
        }
    }
    uint32_t version = (uint32_t)(atoi(version_str));
    if ((version != 16) && (version != 19)) {
        fprintf(stdout, "Invalid version\n");
        return -1;
    }

    input->additional_data      = additional_data;
    input->additional_data_len  = additional_data_len;
    input->password             = password;
    input->password_len         = password_len;
    input->salt                 = salt;
    input->salt_len             = salt_len;
    input->secret_key           = secret_key;
    input->secret_key_len       = secret_key_len;
    input->hash_len             = hash_len;
    input->iterations           = iterations;
    input->lanes                = lanes;
    input->memory_cost          = memory_cost;
    input->threads              = threads;
    input->variant              = variant;
    input->version              = version;

    return 0;
}

int validate_input(input_t* input) {
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
