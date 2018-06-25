from typing import Union

from argonautica.config import Backend, Variant, Version
from argonautica.core.hasher import Hasher
from argonautica.core.verifier import Verifier
from argonautica.data import RandomSalt
from argonautica.defaults import *
from argonautica.utils import Void, VOID


class Argon2:
    """
    A class that knows how to hash and how to verify.
    """

    __slots__ = [
        'hasher',
        'verifier'
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
        self.hasher = Hasher(
            additional_data=additional_data,
            backend=backend,
            hash_len=hash_len,
            iterations=iterations,
            lanes=lanes,
            memory_size=memory_size,
            salt=salt,
            secret_key=secret_key,
            threads=threads,
            variant=variant,
            version=version
        )
        self.verifier = Verifier(
            additional_data=additional_data,
            backend=backend,
            secret_key=secret_key,
            threads=threads
        )

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
        return self.hasher.hash(
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
        return self.verifier.verify(
            additional_data=additional_data,
            backend=backend,
            hash=hash,
            password=password,
            secret_key=secret_key,
            threads=threads
        )

    @property
    def additional_data(self) -> Union[bytes, str, None]:
        return self.hasher.additional_data

    @additional_data.setter
    def additional_data(self, value: Union[bytes, str, None]) -> None:
        self.hasher.additional_data = value
        self.verifier.additional_data = value

    @property
    def backend(self) -> Backend:
        return self.hasher.backend

    @backend.setter
    def backend(self, value: Backend) -> None:
        self.hasher.backend = value
        self.verifier.backend = value

    @property
    def hash_len(self) -> int:
        return self.hasher.hash_len

    @hash_len.setter
    def hash_len(self, value: int) -> None:
        self.hasher.hash_len = value

    @property
    def iterations(self) -> int:
        return self.hasher.iterations

    @iterations.setter
    def iterations(self, value: int) -> None:
        self.hasher.iterations = value

    @property
    def lanes(self) -> int:
        return self.hasher.lanes

    @lanes.setter
    def lanes(self, value: int) -> None:
        self.hasher.lanes = value

    @property
    def memory_size(self) -> int:
        return self.hasher.memory_size

    @memory_size.setter
    def memory_size(self, value: int) -> None:
        self.hasher.memory_size = value

    @property
    def salt(self) -> Union[bytes, RandomSalt, str]:
        return self.hasher.salt

    @salt.setter
    def salt(self, value: Union[bytes, RandomSalt, str]) -> None:
        self.hasher.salt = value

    @property
    def secret_key(self) -> Union[bytes, str, None]:
        return self.hasher.secret_key

    @secret_key.setter
    def secret_key(self, value: Union[bytes, str, None]) -> None:
        self.hasher.secret_key = value
        self.verifier.secret_key = value

    @property
    def threads(self) -> int:
        return self.hasher.threads

    @threads.setter
    def threads(self, value: int) -> None:
        self.hasher.threads = value
        self.verifier.threads = value

    @property
    def variant(self) -> Variant:
        return self.hasher.variant

    @variant.setter
    def variant(self, value: Variant) -> None:
        self.hasher.variant = value

    @property
    def version(self) -> Version:
        return self.hasher.version

    @version.setter
    def version(self, value: Version) -> None:
        self.hasher.version = value
