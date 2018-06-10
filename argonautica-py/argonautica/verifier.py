from typing import Union

from argonautica.config import Backend, DEFAULT_BACKEND, DEFAULT_THREADS
from argonautica.ffi import ffi, rust


class Verifier:
    """
    A class that knows how to verify (but not how to hash)

    TODO: Secret key

    To instantiate it, just invoke it's constructor: ``Verifier()``, which will create
    an ``Verifier`` instance with the following default values, which are the same default
    values as those on the ``Argon2`` class (see above):

    * additional_data: ``None``
    * backend: ``Backend.C``
    * secret_key: ``None``
    * threads: ``the number of logical cores on your machine``

    You can change any one of these default values by calling the constructor with
    keyword arguments matching its properties, e.g.

    .. code-block:: python

        from argonautica import Verifier

        verifier = Verifier(secret_key="somesecret", threads=2)

    or by first instantiating a default ``Verifier`` and then modifying it's properties, e.g.

    .. code-block:: python

        from argonautica import Verifier

        verifier = Verifier()
        verifier.secret_key = "somesecret"
        verifier.threads = 2

    Once you have configured a particular ``Verifier`` instance to your liking, you can use
    it to verify a password against a hash by calling the ``verify`` method, e.g.

    .. code-block:: python

        from argonautica import Verifier

        verifier = Verifier(secret_key="somesecret", threads=2)
        encoded = (
            "$argon2i$v=19$m=4096,t=192,p=4"
            "$Sd6QXG+xvnWmNX5G0L+R2JOZ1pHf39+A5hOUGLfdKfE"
            "$QkJUt0XB9Uyuz5ObTmodlqg0tPSz6INL+ZGdwuWN4XA"
        )
        is_valid = verifier.verify(
            hash=encoded,
            password="P@ssw0rd")
        print(is_valid)
    """

    def __init__(
        self,
        secret_key: Union[bytes, str, None],
        *,
        additional_data: Union[bytes, str, None] = None,
        backend: Backend = DEFAULT_BACKEND,
        threads: int = DEFAULT_THREADS
    ) -> None:
        self.additional_data = additional_data
        self.secret_key = secret_key
        self.backend = backend
        self.threads = threads

    def verify(self, *, hash: str, password: Union[bytes, str]) -> bool:
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
    password: Union[bytes, str],
    additional_data:  Union[bytes, str, None] = None,
    secret_key: Union[bytes, str, None] = None,
    backend: Backend = DEFAULT_BACKEND,
    threads: int = DEFAULT_THREADS
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
        raise Exception("Error")

    # Password
    if isinstance(password, bytes):
        password_len = len(password)
    elif isinstance(password, str):
        password = password.encode('utf-8')
        password_len = len(password)
    else:
        raise Exception("Error")

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
        raise Exception("Error")

    result = rust.argonautica_verify(
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

    if result == rust.ARGONAUTICA_OK:
        return True

    # TODO: Check errors
    return False
