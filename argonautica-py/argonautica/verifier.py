from typing import AnyStr

from argonautica.ffi import ffi, rust
from argonautica.other import Backend


class Verifier:
    def __init__(self,
                 backend: Backend = Backend.C,
                 ) -> None:
        self.backend = backend

    def verify(self, password: AnyStr, hash: str) -> bool:
        return verify(
            password,
            hash,
            self.backend,
        )


def verify(
    password: AnyStr,
    hash: str,
    backend: Backend = Backend.C,
) -> bool:
    if isinstance(password, bytes):
        password_bytes = password
    elif isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        raise Exception("Error")

    result = rust.argonautica_verify(
        hash.encode('utf-8'),
        password_bytes,
        len(password_bytes),
        backend.value,
    )

    if result < 0:
        raise Exception("Error")
    if result > 1:
        raise Exception("Bug")

    return bool(result)
