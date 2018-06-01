#include "test.h"

int parse_args(int argc, char** argv, bool is_secret_key, hash_input_t* input)
{
    if (argc != 12) {
        fprintf(stdout,
            "Usage: [bin] [additional data] [password] [salt]"
                   "[secret key] [hash_length] [iterations] [lanes]"
                   "[memory_cost] [threads] [variant] [version]\n"
        );
        return -1;
    }

    const char* additional_data_str   = argv[1];
    const char* password_str          = argv[2];
    const char* salt_str              = argv[3];
    const char* secret_key_str        = argv[4];
    const char* hash_len_str          = argv[5];
    const char* iterations_str        = argv[6];
    const char* lanes_str             = argv[7];
    const char* memory_cost_str       = argv[8];
    const char* threads_str           = argv[9];
    const char* variant_str           = argv[10];
    const char* version_str           = argv[11];

    uint8_t* additional_data    = NULL;
    size_t additional_data_len  = 0;
    if (is_secret_key == true) {
        additional_data         = (uint8_t*)additional_data_str;
        additional_data_len     = strlen(additional_data_str);
    }

    uint8_t* password           = (uint8_t*)password_str;
    size_t password_len         = strlen(password_str);
    uint8_t* salt               = (uint8_t*)salt_str;
    size_t salt_len             = strlen(salt_str);

    uint8_t* secret_key         = NULL;
    size_t secret_key_len       = 0;
    if (is_secret_key == true) {
        secret_key              = (uint8_t*)secret_key_str;
        secret_key_len          = strlen(secret_key_str);
    }

    size_t hash_len             = (size_t)(atoi(hash_len_str));
    uint32_t iterations         = (uint32_t)(atoi(iterations_str));
    uint32_t lanes              = (uint32_t)(atoi(lanes_str));
    uint32_t memory_cost        = (uint32_t)(atoi(memory_cost_str));
    uint32_t threads            = (uint32_t)(atoi(threads_str));
    int variant_int = atoi(variant_str);
    if (variant_int != 0 && variant_int != 1 && variant_int != 2) {
        fprintf(stdout, "Invalid version. Variant: %s\n", variant_str);
        return -1;
    }
    argon2_type variant = (argon2_type)variant_int;
    uint32_t version = (uint32_t)(atoi(version_str));
    if (version != 16 && version != 19) {
        fprintf(stdout, "Invalid version. Version: %s\n", version_str);
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

void print_encoded(const char* encoded)
{
    fprintf(stderr, "%s\n", encoded);
}

void print_hash(const uint8_t* hash, const size_t hash_len)
{
    int i;
    for (i = 0; i < (int)hash_len; i++) {
        if (i == 0) {
            fprintf(stderr, "[%d,", hash[i]);
        } else if (i == (int)hash_len - 1) {
            fprintf(stderr, "%d]\n", hash[i]);
        } else {
            fprintf(stderr, "%d,", hash[i]);
        }
    }
}
