import multiprocessing

from argonautica.config import Backend, Variant, Version
from argonautica.data import RandomSalt

DEFAULT_BACKEND = Backend.C
DEFAULT_HASH_LEN = 32
DEFAULT_ITERATIONS = 192
DEFAULT_LANES = multiprocessing.cpu_count()
DEFAULT_MEMORY_SIZE = 4096
DEFAULT_SALT_LEN = 32
DEFAULT_SALT = RandomSalt(DEFAULT_SALT_LEN)
DEFAULT_THREADS = multiprocessing.cpu_count()
DEFAULT_VARIANT = Variant.Argon2id
DEFAULT_VERSION = Version._0x13
