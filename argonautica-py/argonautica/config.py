from enum import Enum
import multiprocessing


class Backend(Enum):
    C = 1
    Rust = 2


class Variant(Enum):
    Argon2d = "argon2d"
    Argon2i = "argon2i"
    Argon2id = "argon2id"


class Version(Enum):
    _0x10 = 16
    _0x13 = 19


cpu_count = multiprocessing.cpu_count()
DEFAULT_BACKEND = Backend.C
DEFAULT_HASH_LENGTH = 32
DEFAULT_ITERATIONS = 192
DEFAULT_LANES = cpu_count
DEFAULT_MEMORY_SIZE = 4096
DEFAULT_THREADS = cpu_count
DEFAULT_VARIANT = Variant.Argon2id
DEFAULT_VERSION = Version._0x13
