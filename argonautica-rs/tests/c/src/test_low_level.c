#include "test.h"

int main(int argc, char** argv)
{
    // Parse args
    hash_input_t hash_input = {};
    int err = parse_args(argc, argv, true, &hash_input);
    if (err != 0) {
        exit(1);
    }

    uint8_t* password2 = copy_bytes(hash_input.password, hash_input.password_len);
    if (password2 == NULL) {
        fprintf(stdout,"Memory error");
        exit(1);
    }
    uint8_t* secret_key2 = copy_bytes(hash_input.secret_key, hash_input.secret_key_len);
    if (secret_key2 == NULL) {
        fprintf(stdout,"Memory error");
        free(password2);
        exit(1);
    }

    // Hash low level
    hash_result_t hash_result = hash_low_level(&hash_input);
    if(hash_result.err != ARGON2_OK) {
        fprintf(
            stdout,
            "Argon2 error: %s\n",
            argon2_error_message(hash_result.err)
        );
        free(password2);
        free(secret_key2);
        exit(1);
    }

    // Verify low level
    verify_input_t verify_input = {};
    verify_input.encoded                = hash_result.encoded;
    verify_input.additional_data        = hash_input.additional_data;
    verify_input.additional_data_len    = hash_input.additional_data_len;
    verify_input.password               = password2;
    verify_input.password_len           = hash_input.password_len;
    verify_input.secret_key             = secret_key2;
    verify_input.secret_key_len         = hash_input.secret_key_len;
    verify_input.variant                = hash_input.variant;
    verify_result_t verify_result = verify_low_level(&verify_input);
    if (verify_result.err != ARGON2_OK || verify_result.is_valid == false) {
        fprintf(
            stdout,
            "Failed to validate hash when it should have been valid. Hash: %s. Argon2 Error: %s\n",
            verify_input.encoded,
            argon2_error_message(verify_result.err)
        );
        free(hash_result.encoded);
        free(hash_result.hash);
        free(password2);
        free(secret_key2);
        exit(1);
    }

    print_string(stderr, hash_result.encoded);
    print_bytes(stderr, hash_result.hash, hash_result.hash_len);

    free(hash_result.encoded);
    free(hash_result.hash);
    free(password2);
    free(secret_key2);

    return 0;
}


