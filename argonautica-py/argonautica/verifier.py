from typing import AnyStr, Optional

from argonautica.config import Backend, DEFAULT_BACKEND, DEFAULT_THREADS
from argonautica.ffi import ffi, rust


class Verifier:
    def __init__(
        self,
        *,
        additional_data: Optional[AnyStr] = None,
        secret_key: Optional[AnyStr] = None,
        backend: Backend = DEFAULT_BACKEND,
        threads: int = DEFAULT_THREADS,
    ) -> None:
        self.additional_data = additional_data
        self.secret_key = secret_key
        self.backend = backend
        self.threads = threads

    def verify(self, *, hash: str, password: AnyStr) -> bool:
        return verify(
            hash=hash,
            password=password,
            additional_data=self.additional_data,
            secret_key=self.secret_key,
            backend=self.backend,
            threads=self.threads,
        )


def verify(
    *,
    hash: str,
    password: AnyStr,
    additional_data:  Optional[AnyStr] = None,
    secret_key: Optional[AnyStr] = None,
    backend: Backend = DEFAULT_BACKEND,
    threads: int = DEFAULT_THREADS,
) -> bool:
    # Additional data
    if additional_data is None:
        additional_data = ffi.NULL
        additional_data_len = 0
    elif isinstance(additional_data, bytes):
        additional_data = additional_data
        additional_data_len = len(additional_data)
    elif isinstance(additional_data, str):
        additional_data = additional_data.encode('utf-8')
        additional_data_len = len(additional_data)
    else:
        raise Exception("Error")

    # Password
    if isinstance(password, bytes):
        password = password
        password_len = len(password)
    elif isinstance(password, str):
        password = password.encode("utf-8")
        password_len = len(password)
    else:
        raise Exception("Error")

    # Secret key
    if secret_key is None:
        secret_key = ffi.NULL
        secret_key_len = 0
    elif isinstance(secret_key, bytes):
        secret_key = secret_key
        secret_key_len = len(secret_key)
    elif isinstance(secret_key, str):
        secret_key = secret_key.encode('utf-8')
        secret_key_len = len(secret_key)
    else:
        raise Exception("Error")

    result = rust.argonautica_verify(
        hash.encode('utf-8'),
        additional_data,
        additional_data_len,
        password,
        password_len,
        secret_key,
        secret_key_len,
        backend.value,
        0,
        0,
        threads,
    )

    if result < 0:
        raise Exception("Error")
    if result > 1:
        raise Exception("Bug")

    return bool(result)
