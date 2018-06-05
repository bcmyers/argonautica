from cffi import FFI

ffi = FFI()
ffi.cdef("""
    void a2_free(char*);

    char* a2_hash(
        uint8_t*    password_ptr,
        size_t      password_len,
        uint32_t    backend,
        uint32_t    hash_length,
        uint32_t    iterations,
        uint32_t    lanes,
        uint32_t    memory_size,
        uint32_t    threads,
        char*       variant_ptr,
        uint32_t    version,
        int*        error_code_ptr
    );

    int a2_verify(
        char*       hash_ptr,
        uint8_t*    password_ptr,
        size_t      password_len,
        uint32_t    backend
    );
""")
