from enum import Enum


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
