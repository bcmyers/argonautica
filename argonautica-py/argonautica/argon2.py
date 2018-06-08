from typing import Union

from argonautica.config import (
    Backend, Variant, Version,
    DEFAULT_BACKEND, DEFAULT_HASH_LENGTH, DEFAULT_ITERATIONS, DEFAULT_LANES,
    DEFAULT_MEMORY_SIZE, DEFAULT_THREADS, DEFAULT_VARIANT, DEFAULT_VERSION,
)
from argonautica.data import RandomSalt, DEFAULT_SALT
from argonautica.hasher import Hasher
from argonautica.verifier import Verifier


class Argon2:
    def __init__(
        self,
        *,
        additional_data: Union[bytes, str, None] = None,
        salt: Union[bytes, RandomSalt, str] = DEFAULT_SALT,
        secret_key: Union[bytes, str, None] = None,
        backend: Backend = DEFAULT_BACKEND,
        hash_length: int = DEFAULT_HASH_LENGTH,
        iterations: int = DEFAULT_ITERATIONS,
        lanes: int = DEFAULT_LANES,
        memory_size: int = DEFAULT_MEMORY_SIZE,
        threads: int = DEFAULT_THREADS,
        variant: Variant = DEFAULT_VARIANT,
        version: Version = DEFAULT_VERSION,
    ) -> None:
        self.hasher = Hasher(
            additional_data=additional_data,
            salt=salt,
            secret_key=secret_key,
            backend=backend,
            hash_length=hash_length,
            iterations=iterations,
            lanes=lanes,
            memory_size=memory_size,
            threads=threads,
            variant=variant,
            version=version,
        )
        self.verifier = Verifier(
            additional_data=additional_data,
            secret_key=secret_key,
            backend=backend,
            threads=threads,
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
    def hash_length(self) -> int:
        return self.hasher.hash_length

    @hash_length.setter
    def hash_length(self, value: int) -> None:
        self.hasher.hash_length = value

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

    def hash(self, password: Union[bytes, str]) -> str:
        return self.hasher.hash(password=password)

    def verify(self, hash: str, password: Union[bytes, str]) -> bool:
        return self.verifier.verify(hash=hash, password=password)
