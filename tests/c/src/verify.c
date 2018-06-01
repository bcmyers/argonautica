#include "test.h"

bool verify_high_level(
    const char* encoded,
    const uint8_t* password,
    size_t password_len,
    argon2_type variant
) {
    int err = argon2_verify(
        /* const char* encoded */ encoded,
        /* const void* pwd */ (void*)password,
        /* const size_t pwdlen */ password_len,
        /* argon2_type type */ variant
    );
    if (err == ARGON2_OK) {
        return true;
    } else {
        return false;
    }
}
