import base64
from typing import Union

from argonautica.config import Backend, Variant, Version
from argonautica.core.ffi import ffi, lib
from argonautica.data import RandomSalt
from argonautica.defaults import *
from argonautica.utils import Void, VOID


class Hasher:
    """
    A class that knows how to hash
    """

    __slots__ = [
        'additional_data',
        'backend',
        'hash_len',
        'iterations',
        'lanes',
        'memory_size',
        'salt',
        'secret_key',
        'threads',
        'variant',
        'version'
    ]

    def __init__(
        self,
        *,
        secret_key:         Union[bytes, str, None],

        additional_data:    Union[bytes, str, None] = None,
        backend:            Backend = DEFAULT_BACKEND,
        hash_len:           int = DEFAULT_HASH_LEN,
        iterations:         int = DEFAULT_ITERATIONS,
        lanes:              int = DEFAULT_LANES,
        memory_size:        int = DEFAULT_MEMORY_SIZE,
        salt:               Union[bytes, RandomSalt, str] = DEFAULT_SALT,
        threads:            int = DEFAULT_THREADS,
        variant:            Variant = DEFAULT_VARIANT,
        version:            Version = DEFAULT_VERSION
    ) -> None:
        self.additional_data = additional_data
        self.salt = salt
        self.secret_key = secret_key
        self.backend = backend
        self.hash_len = hash_len
        self.iterations = iterations
        self.lanes = lanes
        self.memory_size = memory_size
        self.threads = threads
        self.variant = variant
        self.version = version

    def hash(
        self,
        *,
        password:           Union[bytes, str],

        additional_data:    Union[bytes, str, None, Void] = VOID,
        backend:            Union[Backend, Void] = VOID,
        hash_len:           Union[int, Void] = VOID,
        iterations:         Union[int, Void] = VOID,
        lanes:              Union[int, Void] = VOID,
        memory_size:        Union[int, Void] = VOID,
        salt:               Union[bytes, RandomSalt, str, Void] = VOID,
        secret_key:         Union[bytes, str, None, Void] = VOID,
        threads:            Union[int, Void] = VOID,
        variant:            Union[Variant, Void] = VOID,
        version:            Union[Version, Void] = VOID
    ) -> str:
        if isinstance(additional_data, Void):
            additional_data = self.additional_data
        if isinstance(backend, Void):
            backend = self.backend
        if isinstance(hash_len, Void):
            hash_len = self.hash_len
        if isinstance(iterations, Void):
            iterations = self.iterations
        if isinstance(lanes, Void):
            lanes = self.lanes
        if isinstance(memory_size, Void):
            memory_size = self.memory_size
        if isinstance(salt, Void):
            salt = self.salt
        if isinstance(secret_key, Void):
            secret_key = self.secret_key
        if isinstance(threads, Void):
            threads = self.threads
        if isinstance(variant, Void):
            variant = self.variant
        if isinstance(version, Void):
            version = self.version
        return hash(
            additional_data=additional_data,
            backend=backend,
            hash_len=hash_len,
            iterations=iterations,
            lanes=lanes,
            memory_size=memory_size,
            password=password,
            salt=salt,
            secret_key=secret_key,
            threads=threads,
            variant=variant,
            version=version
        )


def hash(
    *,
    password:           Union[bytes, str],
    secret_key:         Union[bytes, str, None],

    additional_data:    Union[bytes, str, None] = None,
    backend:            Backend = DEFAULT_BACKEND,
    hash_len:           int = DEFAULT_HASH_LEN,
    iterations:         int = DEFAULT_ITERATIONS,
    lanes:              int = DEFAULT_LANES,
    memory_size:        int = DEFAULT_MEMORY_SIZE,
    salt:               Union[bytes, RandomSalt, str] = DEFAULT_SALT,
    threads:            int = DEFAULT_THREADS,
    variant:            Variant = DEFAULT_VARIANT,
    version:            Version = DEFAULT_VERSION
) -> str:
    """
    A standalone hash function
    """
    data = Validator(
        additional_data=additional_data,
        password=password,
        salt=salt,
        secret_key=secret_key,
    )
    encoded_len = lib.argonautica_encoded_len(
        hash_len,
        iterations,
        lanes,
        memory_size,
        data.salt_len,
        variant.value,
    )
    if encoded_len < 0:
        raise Exception("Error calculating length of string-encoded hash")
    encoded = ffi.new("char[]", b'\0'*encoded_len)
    err = lib.argonautica_hash(
        encoded,
        data.additional_data,
        data.additional_data_len,
        data.password,
        data.password_len,
        data.salt,
        data.salt_len,
        data.secret_key,
        data.secret_key_len,
        backend.value,
        hash_len,
        iterations,
        lanes,
        memory_size,
        0,
        0,
        threads,
        variant.value,
        version.value,
    )
    if err != lib.ARGONAUTICA_OK:
        error_msg_ptr = lib.argonautica_error_msg(err)
        error_msg = ffi.string(error_msg_ptr).decode("utf-8")
        raise Exception(error_msg)
    hash = ffi.string(encoded).decode("utf-8")
    return hash


class Validator:
    def __init__(
        self,
        *,
        additional_data:    Union[bytes, str, None],
        password:           Union[bytes, str],
        salt:               Union[bytes, RandomSalt, str],
        secret_key:         Union[bytes, str, None]
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
            raise TypeError("Type of additional_data must be bytes, str, or None")

        if isinstance(password, bytes):
            self.password = password
            self.password_len = len(self.password)
        elif isinstance(password, str):
            self.password = password.encode("utf-8")
            self.password_len = len(self.password)
        else:
            raise TypeError("Type of password must be bytes or str")

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
            raise TypeError("Type of salt must be bytes, RandomSalt, or str")

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
            raise TypeError("Type of secret_key must be bytes, str, or None")

    def __repr__(self) -> str:
        return str(self.__dict__)
