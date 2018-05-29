#include <argon2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    if (argc != 2) {
        exit(1);
    }

    char* password = argv[1];
    uint8_t* pwd = (uint8_t*)strdup(password);
    uint32_t pwdlen = strlen((char *)pwd);

    size_t saltlen = 8;
    uint8_t salt[saltlen];
    memset( salt, 0x00, saltlen );
    salt[0] = (uint8_t)'s';
    salt[1] = (uint8_t)'o';
    salt[2] = (uint8_t)'m';
    salt[3] = (uint8_t)'e';
    salt[4] = (uint8_t)'s';
    salt[5] = (uint8_t)'a';
    salt[6] = (uint8_t)'l';
    salt[7] = (uint8_t)'t';

    uint32_t t_cost = 128;
    uint32_t m_cost = 4096;
    uint32_t parallelism = 2;

    size_t encodedlen = 100;
    size_t hashlen = 32;

    char* encoded = (char*)malloc( encodedlen * sizeof(char) );

    int err = argon2id_hash_encoded(
        t_cost, m_cost, parallelism,
        (void*)pwd, (size_t)pwdlen,
        (void*)salt, (size_t)saltlen,
        hashlen, // size_t
        encoded, // char*
        encodedlen // size_t
    );
    if(err != ARGON2_OK) {
        printf("Error: %s\n", argon2_error_message(err));
        free(encoded);
        free(pwd);
        exit(1);
    }
    fprintf(stderr, "%s", encoded);
    printf("\n");
    free(encoded);
    free(pwd);
    return 0;

    // argon2_context context = {
    //     hash,  /* output array, at least HASHLEN in size */
    //     HASHLEN, /* digest length */
    //     pwd, /* password array */
    //     pwdlen, /* password length */
    //     salt,  /* salt array */
    //     SALTLEN, /* salt length */
    //     NULL, 0, /* optional secret data */
    //     NULL, 0, /* optional associated data */
    //     t_cost, m_cost, parallelism, parallelism,
    //     ARGON2_VERSION_13, /* algorithm version */
    //     NULL, NULL, /* custom memory allocation / deallocation functions */
    //     /* by default only internal memory is cleared (pwd is not wiped) */
    //     ARGON2_DEFAULT_FLAGS
    // };

    // int err = argon2id_ctx( &context );
    // free(pwd);
    // if(err != ARGON2_OK) {
    //     printf("Error: %s\n", argon2_error_message(err));
    //     exit(1);
    // }

    // for( int i=0; i<HASHLEN; ++i ) printf( "%02x", hash[i] ); printf( "\n" );
    // return 0;
}
