from typing import AnyStr

from a2py import a2, ffi
from a2py.other import Backend, Variant, Version


class Hasher:
    def __init__(self,
                 backend: Backend = Backend.C,
                 hash_length: int = 32,
                 iterations: int = 128,
                 lanes: int = 2,
                 memory_size: int = 4096,
                 threads: int = 2,
                 variant: Variant = Variant.Argon2id,
                 version: Version = Version._0x13,
                 ) -> None:
        self.backend = backend
        self.hash_length = hash_length
        self.iterations = iterations
        self.lanes = lanes
        self.memory_size = memory_size
        self.threads = threads
        self.variant = variant
        self.version = version

    def hash(self, password: AnyStr) -> str:
        return hash(
            password,
            backend=self.backend,
            hash_length=self.hash_length,
            iterations=self.iterations,
            lanes=self.lanes,
            memory_size=self.memory_size,
            threads=self.threads,
            variant=self.variant,
            version=self.version,
        )


def hash(
    password: AnyStr,
    *,
    backend: Backend = Backend.C,
    hash_length: int = 32,
    iterations: int = 128,
    lanes: int = 2,
    memory_size: int = 4096,
    threads: int = 2,
    variant: Variant = Variant.Argon2id,
    version: Version = Version._0x13
) -> str:
    error_code_ptr = ffi.new("int*", init=-1)

    if isinstance(password, bytes):
        password_bytes = password
    elif isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        raise Exception("TODO")

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

    if hash_ptr == ffi.NULL:
        raise Exception("failed with error code {}".format(error_code_ptr[0]))

    encoded = ffi.string(hash_ptr).decode("utf-8")
    a2.a2_free(hash_ptr)

    return encoded
