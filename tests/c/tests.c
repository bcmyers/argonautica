#include <argon2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    if (argc != 3) {
        printf("Usage: TODO");
        exit(1);
    }

    char* password_string = argv[1];
    uint8_t* pwd = (uint8_t*)password_string;
    size_t pwdlen = strlen(password_string);

    char* salt_string = argv[2];
    uint8_t* salt = (uint8_t*)salt_string;
    size_t saltlen = strlen(salt_string);

    uint32_t m_cost = 4096;
    uint32_t parallelism = 2;
    uint32_t t_cost = 128;

    size_t encodedlen = 100;
    size_t hashlen = 32;

    char* encoded = (char*)malloc( encodedlen * sizeof(char) );

    int err = argon2id_hash_encoded(
        t_cost, m_cost, parallelism,
        (void*)pwd, pwdlen,
        (void*)salt, saltlen,
        hashlen, // size_t
        encoded, // char*
        encodedlen // size_t
    );
    if(err != ARGON2_OK) {
        printf("Error: %s\n", argon2_error_message(err));
        free(encoded);
        exit(1);
    }
    fprintf(stderr, "%s", encoded);
    printf("\n");
    free(encoded);
    return 0;
}
