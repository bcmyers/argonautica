from enum import Enum

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

    void a2_test();
""")
a2 = ffi.dlopen("./target/debug/liba2py.dylib")


class Backend(Enum):
    C = 1
    Rust = 2


class Variant(Enum):
    Argon2d = "argon2d"
    Argon2i = "argon2i"
    Argon2id = "argon2id"


class Version(Enum):
    _0x10 = 16
    _0x13 = 19


def hash(
    password: str,
    *,
    backend: Backend = Backend.C,
    hash_length: int = 32,
    iterations: int = 128,
    lanes: int = 2,
    memory_size: int = 4_096,
    threads: int = 2,
    variant: Variant = Variant.Argon2id,
    version: Version = Version._0x13,
) -> str:
    error_code_ptr = ffi.new("int*", init=0)
    password_bytes = password.encode("utf-8")
    hash_ptr = a2.a2_hash(
        password_bytes,
        len(password_bytes),
        backend.value,
        hash_length,
        iterations,
        lanes,
        memory_size,
        threads,
        variant.value.encode("utf-8"),
        version.value,
        error_code_ptr
    )
    encoded = ffi.string(hash_ptr).decode("utf-8")
    a2.a2_free(hash_ptr)
    return encoded


if __name__ == "__main__":
    encoded = hash("P@ssw0rd")
    print(encoded)
