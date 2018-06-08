from enum import Enum
import multiprocessing

from argonautica.ffi import rust


class Backend(Enum):
    C = rust.ARGONAUTICA_C
    Rust = rust.ARGONAUTICA_RUST


class Variant(Enum):
    Argon2d = rust.ARGONAUTICA_ARGON2D
    Argon2i = rust.ARGONAUTICA_ARGON2I
    Argon2id = rust.ARGONAUTICA_ARGON2ID


class Version(Enum):
    _0x10 = rust.ARGONAUTICA_0x10
    _0x13 = rust.ARGONAUTICA_0x13


cpu_count = multiprocessing.cpu_count()
DEFAULT_BACKEND = Backend.C
DEFAULT_HASH_LENGTH = 32
DEFAULT_ITERATIONS = 192
DEFAULT_LANES = cpu_count
DEFAULT_MEMORY_SIZE = 4096
DEFAULT_THREADS = cpu_count
DEFAULT_VARIANT = Variant.Argon2id
DEFAULT_VERSION = Version._0x13
