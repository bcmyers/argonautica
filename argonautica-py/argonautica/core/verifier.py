from typing import Union

from argonautica.config import Backend
from argonautica.core.ffi import ffi, lib
from argonautica.defaults import *
from argonautica.utils import Void, VOID


class Verifier:
    """
    A class that knows how to verify
    """
    __slots__ = [
        'additional_data',
        'backend',
        'secret_key',
        'threads'
    ]

    def __init__(
        self,
        *,
        secret_key:         Union[bytes, str, None],

        additional_data:    Union[bytes, str, None] = None,
        backend:            Backend = DEFAULT_BACKEND,
        threads:            int = DEFAULT_THREADS
    ) -> None:
        self.additional_data = additional_data
        self.secret_key = secret_key
        self.backend = backend
        self.threads = threads

    def verify(
        self,
        *,
        hash:               str,
        password:           Union[bytes, str],

        additional_data:    Union[bytes, str, None, Void] = VOID,
        backend:            Union[Backend, Void] = VOID,
        secret_key:         Union[bytes, str, None, Void] = VOID,
        threads:            Union[int, Void] = VOID
    ) -> bool:
        if isinstance(additional_data, Void):
            additional_data = self.additional_data
        if isinstance(backend, Void):
            backend = self.backend
        if isinstance(secret_key, Void):
            secret_key = self.secret_key
        if isinstance(threads, Void):
            threads = self.threads
        return verify(
            additional_data=additional_data,
            backend=backend,
            hash=hash,
            password=password,
            secret_key=secret_key,
            threads=threads
        )


def verify(
    *,
    hash:               str,
    password:           Union[bytes, str],
    secret_key:         Union[bytes, str, None],

    additional_data:    Union[bytes, str, None] = None,
    backend:            Backend = DEFAULT_BACKEND,
    threads:            int = DEFAULT_THREADS
) -> bool:
    """
    A standalone verify function
    """
    # Additional data
    if additional_data is None:
        additional_data = ffi.NULL
        additional_data_len = 0
    elif isinstance(additional_data, bytes):
        additional_data_len = len(additional_data)
    elif isinstance(additional_data, str):
        additional_data = additional_data.encode('utf-8')
        additional_data_len = len(additional_data)
    else:
        raise TypeError("Type of additional_data must be bytes, str, or None")

    # Password
    if isinstance(password, bytes):
        password_len = len(password)
    elif isinstance(password, str):
        password = password.encode('utf-8')
        password_len = len(password)
    else:
        raise TypeError("Type of password must be bytes or str")

    # Secret key
    if secret_key is None:
        secret_key = ffi.NULL
        secret_key_len = 0
    elif isinstance(secret_key, bytes):
        secret_key_len = len(secret_key)
    elif isinstance(secret_key, str):
        secret_key = secret_key.encode('utf-8')
        secret_key_len = len(secret_key)
    else:
        raise TypeError("Type of secret_key must be bytes, str, or None")

    is_valid = ffi.new("int*", 0)
    err = lib.argonautica_verify(
        is_valid,
        additional_data,
        additional_data_len,
        hash.encode('utf-8'),
        password,
        password_len,
        secret_key,
        secret_key_len,
        backend.value,
        0,
        0,
        threads,
    )
    if err != lib.ARGONAUTICA_OK:
        error_msg_ptr = lib.argonautica_error_msg(err)
        error_msg = ffi.string(error_msg_ptr).decode("utf-8")
        raise Exception(error_msg)

    if is_valid[0] == 1:
        return True

    return False
