import base64
import re
from typing import Any, Dict, List

from argonautica.config import Variant, Version


RE_HASH = re.compile(r"\$([^$]+)")
RE_OTHER = re.compile(r"m=([0-9]+),t=([0-9]+),p=([0-9]+)")
RE_VERSION = re.compile(r"v=([0-9]+)")


class HashRaw:
    """
    A class that represents a string-encoded hash that has been decoded into its constituent parts.

    You can obtain an instance of this class by calling the ``decode`` function on
    a string-encoded hash.
    """
    __slots__ = [
        'iterations',
        'lanes',
        'memory_size',
        'raw_hash_bytes',
        'raw_salt_bytes',
        'variant',
        'version'
    ]

    def __init__(
        self,
        *,
        iterations:         int,
        lanes:              int,
        memory_size:        int,
        raw_hash_bytes:     bytes,
        raw_salt_bytes:     bytes,
        variant:            Variant,
        version:            Version
    ) -> None:
        self.iterations = iterations
        self.lanes = lanes
        self.memory_size = memory_size
        self.raw_hash_bytes = raw_hash_bytes
        self.raw_salt_bytes = raw_salt_bytes
        self.variant = variant
        self.version = version

    def encode(self) -> str:
        hash_encoded = base64.b64encode(self.raw_hash_bytes).decode('utf-8').rstrip('=')
        salt_encoded = base64.b64encode(self.raw_salt_bytes).decode('utf-8').rstrip('=')
        encoded = '${}$v={}$m={},t={},p={}${}${}'.format(
            self.variant,
            self.version,
            self.memory_size,
            self.iterations,
            self.lanes,
            salt_encoded,
            hash_encoded
        )
        return encoded


def decode(hash: str) -> HashRaw:
    """
    The ``decode`` function takes a string-encoded hash and decodes it into its component parts

    Every string-encoded hash (the return value of all ``hash`` methods / functions) has
    the following form:

    * \${variant string}
    * \$v={version number}
    * \$m={memory cost},t={iterations},p={lanes}
    * \${standard base64-encoded raw salt bytes (without padding)}
    * \${standard base64-encoded raw hash bytes (without padding)}

    This function accepts a string-encoded hash and returns a ``HashRaw`` instance,
    which give you access to these underlying components.
    """
    l = RE_HASH.findall(hash)
    if len(l) != 5:
        raise ValueError("Invalid hash. Failed to decode hash. Hash: {}".format(hash))

    # Variant
    variant_str = l[0]
    if variant_str == "argon2d":
        variant = Variant.Argon2d
    elif variant_str == "argon2i":
        variant = Variant.Argon2i
    elif variant_str == "argon2id":
        variant = Variant.Argon2id
    else:
        raise ValueError("Invalid hash. Failed to decode hash. Hash: {}".format(hash))

    # Version
    l2 = RE_VERSION.findall(l[1])
    if len(l2) != 1:
        raise ValueError("Invalid hash. Failed to decode hash. Hash: {}".format(hash))
    version_str = l2[0]
    if version_str == "16":
        version = Version._0x10
    elif version_str == "19":
        version = Version._0x13
    else:
        raise ValueError("Invalid hash. Failed to decode hash. Hash: {}".format(hash))

    # Memory size, iterations, lanes
    l3 = RE_OTHER.findall(l[2])
    if len(l3) != 1:
        raise ValueError("Invalid hash. Failed to decode hash. Hash: {}".format(hash))
    if len(l3[0]) != 3:
        raise ValueError("Invalid hash. Failed to decode hash. Hash: {}".format(hash))
    iterations = int(l3[0][1])
    lanes = int(l3[0][2])
    memory_size = int(l3[0][0])

    # Data
    raw_salt_bytes = _base64_decode(l[3])
    raw_hash_bytes = _base64_decode(l[4])

    return HashRaw(
        iterations=iterations,
        lanes=lanes,
        memory_size=memory_size,
        raw_hash_bytes=raw_hash_bytes,
        raw_salt_bytes=raw_salt_bytes,
        variant=variant,
        version=version,
    )


def _base64_decode(base64_encoded: str) -> bytes:
    missing_padding = len(base64_encoded) % 4
    if missing_padding != 0:
        base64_encoded += '=' * (4 - missing_padding)
    try:
        decoded = base64.standard_b64decode(base64_encoded)
    except:
        raise ValueError("Invalid hash. Failed to decode hash. Hash: {}".format(hash))
    return decoded


class Void:
    __slots__ = []  # type: List[str]
    pass


VOID = Void()
