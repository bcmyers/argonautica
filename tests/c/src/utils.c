#include "test.h"

void print_encoded(const char* encoded) {
    fprintf(stderr, "%s\n", encoded);
}

void print_hash(const uint8_t* hash, const size_t hash_len) {
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
