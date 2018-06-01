#include "test.h"

static int parse_args(int argc, char** argv, hash_input_t* input);

int main(int argc, char** argv)
{
    hash_input_t input = {};
    int err = parse_args(argc, argv, &input);
    if (err != 0) {
        exit(1);
    }

    hash_output_t result1 = hash_high_level(&input);
    if(result1.err != ARGON2_OK) {
        fprintf(stdout, "Error: %s\n", argon2_error_message(result1.err));
        exit(1);
    }

    bool should_validate = verify_high_level(
        result1.encoded,
        input.password,
        input.password_len,
        input.variant
    );
    if (should_validate == false) {
        fprintf(stdout, "Error: Hash failed when it should have been valid");
        exit(1);
    }

    bool should_fail = verify_high_level(
        "$argon2d$v=19$m=64,t=128,p=2$TTMzYlBCUHo$cNisumCX8KA",
        input.password,
        input.password_len,
        input.variant
    );
    if (should_fail != false) {
        fprintf(stdout, "Error: Hash valid when it should have failed");
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

static int parse_args(int argc, char** argv, hash_input_t* input)
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

