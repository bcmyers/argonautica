from typing import AnyStr, Optional, Union

from argonautica.config import (
    Backend, DEFAULT_BACKEND, DEFAULT_HASH_LENGTH, DEFAULT_ITERATIONS, DEFAULT_LANES,
    DEFAULT_MEMORY_SIZE, DEFAULT_THREADS, DEFAULT_VARIANT, DEFAULT_VERSION, Variant, Version,
)
from argonautica.data import DEFAULT_SALT, RandomSalt
from argonautica.ffi import ffi, rust


class Hasher:
    def __init__(
        self,
        *,
        additional_data: Optional[AnyStr] = None,
        salt: Union[AnyStr, RandomSalt] = DEFAULT_SALT,
        secret_key: Optional[AnyStr] = None,
        backend: Backend = DEFAULT_BACKEND,
        hash_length: int = DEFAULT_HASH_LENGTH,
        iterations: int = DEFAULT_ITERATIONS,
        lanes: int = DEFAULT_LANES,
        memory_size: int = DEFAULT_MEMORY_SIZE,
        threads: int = DEFAULT_THREADS,
        variant: Variant = DEFAULT_VARIANT,
        version: Version = DEFAULT_VERSION,
    ) -> None:
        self.additional_data = additional_data
        self.salt = salt
        self.secret_key = secret_key
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
            additional_data=self.additional_data,
            salt=self.salt,
            secret_key=self.secret_key,
            backend=self.backend,
            hash_length=self.hash_length,
            iterations=self.iterations,
            lanes=self.lanes,
            memory_size=self.memory_size,
            threads=self.threads,
            variant=self.variant,
            version=self.version,
        )

    def hash_raw(self, password: AnyStr) -> bytes:
        return hash_raw(
            password,
            additional_data=self.additional_data,
            salt=self.salt,
            secret_key=self.secret_key,
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
    secret_key: Optional[AnyStr] = None,
    *,
    additional_data: Optional[AnyStr] = None,
    salt: Union[AnyStr, RandomSalt] = DEFAULT_SALT,
    backend: Backend = DEFAULT_BACKEND,
    hash_length: int = DEFAULT_HASH_LENGTH,
    iterations: int = DEFAULT_ITERATIONS,
    lanes: int = DEFAULT_LANES,
    memory_size: int = DEFAULT_MEMORY_SIZE,
    threads: int = DEFAULT_THREADS,
    variant: Variant = DEFAULT_VARIANT,
    version: Version = DEFAULT_VERSION,
) -> str:
    error_code_ptr = ffi.new("int*", init=-1)

    data = Data(
        additional_data=additional_data,
        password=password,
        salt=salt,
        secret_key=secret_key,
    )

    hash_ptr = rust.argonautica_hash(
        data.additional_data,
        data.additional_data_len,
        data.password,
        data.password_len,
        data.salt,
        data.salt_len,
        data.secret_key,
        data.secret_key_len,
        backend.value,
        hash_length,
        iterations,
        lanes,
        memory_size,
        0,
        0,
        threads,
        variant.value.encode("utf-8"),
        version.value,
        error_code_ptr
    )
    if hash_ptr == ffi.NULL:
        raise Exception("failed with error code {}".format(error_code_ptr[0]))

    encoded = ffi.string(hash_ptr).decode("utf-8")

    err = rust.argonautica_free(hash_ptr)
    if err < 0:
        raise Exception("Error")

    return encoded


def hash_raw(
    password: AnyStr,
    secret_key: Optional[AnyStr] = None,
    *,
    additional_data: Optional[AnyStr] = None,
    salt: Union[AnyStr, RandomSalt] = DEFAULT_SALT,
    backend: Backend = DEFAULT_BACKEND,
    hash_length: int = DEFAULT_HASH_LENGTH,
    iterations: int = DEFAULT_ITERATIONS,
    lanes: int = DEFAULT_LANES,
    memory_size: int = DEFAULT_MEMORY_SIZE,
    threads: int = DEFAULT_THREADS,
    variant: Variant = DEFAULT_VARIANT,
    version: Version = DEFAULT_VERSION,
) -> bytes:
    # TODO:
    return bytes([0])


class Data:
    def __init__(
        self,
        *,
        additional_data: Optional[AnyStr],
        password: AnyStr,
        salt: Union[AnyStr, RandomSalt],
        secret_key: Optional[AnyStr]
    ) -> None:
        if additional_data is None:
            self.additional_data = ffi.NULL
            self.additional_data_len = 0
        elif isinstance(additional_data, bytes):
            self.additional_data = additional_data
            self.additional_data_len = len(self.additional_data)
        elif isinstance(additional_data, str):
            self.additional_data = additional_data.encode('utf-8')
            self.additional_data_len = len(self.additional_data)
        else:
            raise Exception("Error")

        if isinstance(password, bytes):
            self.password = password
            self.password_len = len(self.password)
        elif isinstance(password, str):
            self.password = password.encode("utf-8")
            self.password_len = len(self.password)
        else:
            raise Exception("TODO")

        if isinstance(salt, RandomSalt):
            self.salt = ffi.NULL
            self.salt_len = salt.len
        elif isinstance(salt, bytes):
            self.salt = salt
            self.salt_len = len(self.salt)
        elif isinstance(salt, str):
            self.salt = salt.encode('utf-8')
            self.salt_len = len(self.salt)
        else:
            raise Exception("Error")

        if secret_key is None:
            self.secret_key = ffi.NULL
            self.secret_key_len = 0
        elif isinstance(secret_key, bytes):
            self.secret_key = secret_key
            self.secret_key_len = len(self.secret_key)
        elif isinstance(secret_key, str):
            self.secret_key = secret_key.encode('utf-8')
            self.secret_key_len = len(self.secret_key)
        else:
            raise Exception("Error")
