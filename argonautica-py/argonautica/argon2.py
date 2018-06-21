from typing import Union

from argonautica.config import Backend, Variant, Version
from argonautica.data import RandomSalt
from argonautica.defaults import *
from argonautica.hasher import Hasher
from argonautica.verifier import Verifier


class Argon2:
    """
    A class that knows how to hash and how to verify.

    To instantiate it, just invoke it's constructor with a secret key (which can be ``None``), e.g.
    ``Argon2(secret_key=None)``. This will create an ``Argon2`` instance with the
    following default values:

    * additional_data: ``None``
    * backend: ``Backend.C``
    * hash_len: ``32``
    * iterations: ``192``
    * lanes: ``the number of logical cores on your machine``
    * memory_size: ``4096``
    * salt: ``RandomSalt(32)``
    * threads: ``the number of logical cores on your machine``
    * variant: ``Variant.Argon2id``
    * version: ``Version._0x13``

    You can change any one of these default values by calling the constructor with
    keyword arguments matching the names above, e.g.

    .. code-block:: python

        from argonautica import Argon2

        argon2 = Argon2(iterations=256, secret_key="somesecret")

    or by first instantiating a default ``Argon2`` and then modifying it's properties, e.g.

    .. code-block:: python

        from argonautica import Argon2

        argon2 = Argon2(secret_key=None)
        argon2.iterations = 256
        argon2.secret_key = "somesecret"

    Once you have configured a particular ``Argon2`` instance to your liking, you can use
    it to hash by calling the ``hash`` method, e.g.

    .. code-block:: python

        from argonautica import Argon2

        argon2 = Argon2(iterations=256, secret_key="somesecret")
        encoded = argon2.hash("P@ssw0rd")
        print(encoded)

    Once you have a hash, you can use your instance of ``Argon2`` to verify that
    a particular password matches that hash by calling the ``verify`` method, e.g.

    .. code-block:: python

        from argonautica import Argon2

        argon2 = Argon2(iterations=256, secret_key="somesecret")
        encoded = argon2.hash("P@ssw0rd")
        is_valid: bool = argon2.verify(hash=encoded, password="P@ssw0rd")
        print(is_valid)
    """

    def __init__(
        self,
        *,
        secret_key: Union[bytes, str, None],
        additional_data: Union[bytes, str, None] = None,
        salt: Union[bytes, RandomSalt, str] = DEFAULT_SALT,
        backend: Backend = DEFAULT_BACKEND,
        hash_len: int = DEFAULT_HASH_LEN,
        iterations: int = DEFAULT_ITERATIONS,
        lanes: int = DEFAULT_LANES,
        memory_size: int = DEFAULT_MEMORY_SIZE,
        threads: int = DEFAULT_THREADS,
        variant: Variant = DEFAULT_VARIANT,
        version: Version = DEFAULT_VERSION
    ) -> None:
        """
        The Argon2 constructor
        """
        self.hasher = Hasher(
            additional_data=additional_data,
            salt=salt,
            secret_key=secret_key,
            backend=backend,
            hash_len=hash_len,
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
        """
        The ``additional_data`` input, which defaults to ``None`` and has the type
        ``Union[bytes, str, None]``.

        Although typically not used, the argon2 algorithm allows users to provide arbitrary
        "additional data" to the hash function that impacts its result. This additional data,
        however, is not encoded into the resulting hash string (it's kind of like a secondary
        secret key). This means that, later, when you would like to verify a password against
        a hash created with additional data, you will have to provide the same additional data
        that was used to create the hash to the ``verify`` function, ``Verifier.verify`` method,
        or ``Argon2.verify`` method in order to properly validate a valid password / hash pair.
        """
        return self.hasher.additional_data

    @additional_data.setter
    def additional_data(self, value: Union[bytes, str, None]) -> None:
        self.hasher.additional_data = value
        self.verifier.additional_data = value

    @property
    def backend(self) -> Backend:
        """
        The ``backend`` configuration, which defaults to ``Backend.C`` and has the type
        ``Backend``.

        argonautica-py was designed to support multiple backends (meaning multiple
        implementations of the underlying argon2 algorithm). Currently only the C backend
        is supported, which uses the cannonical Argon2 library written in C to actually
        do the work. In the future hopefully a Rust backend will also be supported, but,
        for the moment, you must use ``Backend.C``, which is the default. Using
        ``Backend.Rust`` will result in an exception (again, for the moment).
        """
        return self.hasher.backend

    @backend.setter
    def backend(self, value: Backend) -> None:
        self.hasher.backend = value
        self.verifier.backend = value

    @property
    def hash_len(self) -> int:
        """
        The ``hash_len`` configuration, which defaults to ``32`` and has the type ``int``.

        The hash length in bytes is configurable. The default is ``32``. This is probably
        a good number to use. ``16`` is also probably fine. You probably shouldn't go below ``16``.

        This configuration is only used for hashing (it will be read from the encoded hash
        string during verification as opposed to being provided by the user as during hashing).
        """
        return self.hasher.hash_len

    @hash_len.setter
    def hash_len(self, value: int) -> None:
        self.hasher.hash_len = value

    @property
    def iterations(self) -> int:
        """
        The ``iterations`` configuration, which defaults to ``192`` and has the type ``int``.

        Argon2 has a notion of "iterations" or "time cost". All else equal and generally
        speaking, the greater the number of iterations, the longer it takes to perform the
        hash and the more secure the resulting hash. More iterations basically means more
        CPU load. This and ``memory size`` (see below) are the two primary parameters to
        adjust in order to increase or decrease the security of your hash. The default is
        ``192`` iterations, which was chosen because, along with the default memory size of
        ``4096``, this leads to a hashing time of approximately ``300`` milliseconds on the
        early-2014 Macbook Air that is the developer's machine. If you're going to use
        argonautica in production, you should probably tweak this parameter (and the memory
        size parameter) in order to increase the time it takes to hash to the maximum you
        can reasonably allow for your use-case (e.g. to probably about ``300``-``500``
        milliseconds for the use-case of hashing user passwords for a website).

        This configuration is only used for hashing (it will be read from the encoded hash
        string during verification as opposed to being provided by the user as during hashing).
        """
        return self.hasher.iterations

    @iterations.setter
    def iterations(self, value: int) -> None:
        self.hasher.iterations = value

    @property
    def lanes(self) -> int:
        """
        The ``lanes`` configuration, which defaults to ``the number of logical cores on
        your machine`` and has the type ``int``.

        Argon2 can break up its work into one or more "lanes" during some parts of the hashing
        algorithm. If you configure it with multiple lanes and you also use multiple threads
        (see below) the hashing algorithm will performed its work in parallel in some parts,
        potentially speeding up the time it takes to produce a hash without diminishing the
        security of the result.

        This configuration is only used for hashing (it will be read from the encoded hash
        string during verification as opposed to being provided by the user as during hashing).
        """
        return self.hasher.lanes

    @lanes.setter
    def lanes(self, value: int) -> None:
        self.hasher.lanes = value

    @property
    def memory_size(self) -> int:
        """
        The ``memory_size`` configuration, which defaults to ``4096`` and has the type ``int``.

        Argon2 has a notion of "memory size" or "memory cost" (in kibibytes). All else
        equal and generally speaking, the greater the memory size, the longer it takes to
        perform the hash and the more secure the resulting hash. More memory size basically
        means more memory used. This and ``iterations`` (see above) are, again, generally
        speaking, the two parameters to adjust in order to increase or decrease the
        security of your hash. The default is ``4096`` kibibytes, which was chosen because,
        again, along with the default iterations of ``192``, this leads to a hashing time of
        approximately ``300`` milliseconds on the early-2014 Macbook Air that is the
        developer's machine. If you're going to use argonautica in production, you should
        probably tweak this parameter (and the iterations parameter) in order to increase
        the time it takes to hash to the maximum you can reasonably allow for your use-case
        (e.g. to probably about ``300``-``500`` milliseconds for the use-case of hashing user
        passwords for a website).

        This configuration is only used for hashing (it will be read from the encoded hash
        string during verification as opposed to being provided by the user as during hashing).
        """
        return self.hasher.memory_size

    @memory_size.setter
    def memory_size(self, value: int) -> None:
        self.hasher.memory_size = value

    @property
    def salt(self) -> Union[bytes, RandomSalt, str]:
        """
        The ``salt`` input, which defaults to ``SaltRandom(32)`` and has the type
        ``Union[bytes, SaltRandom, str]``.

        Argon2 requires a salt of at least 8 bytes, which, unlike the secret key, is not sensitive
        data (it is encoded in the resulting hash using base64 encoding; so anyone with the hash
        can easily figure out the salt that was used to create it, which is fine).

        That said, you have two decisions to make when choosing a salt: 1) The length of the salt
        in bytes, and 2) Whether you want a "random" salt, meaning a salt whose byte buffer
        will be filled with new random bytes before each hash, or a "deterministic" salt,
        meaning a salt whose bytes you specify and which can remain the same for each hash.
        Setting ``salt`` to an instance of the ``RandomSalt`` class, which allows you to
        specify a length, will lead to hashing with a "random" salt. Setting ``salt`` to an
        instance of ``bytes`` or ``str`` will lead to hashing with a "deterministic" salt.

        Generally speaking, "random" salts are more secure and longer salts are more secure. It
        is not recommended that you hash with a "deterministic" salt.

        This input is only used for hashing (it will be read from the encoded hash
        string during verification as opposed to being provided by the user as during hashing).
        """
        return self.hasher.salt

    @salt.setter
    def salt(self, value: Union[bytes, RandomSalt, str]) -> None:
        self.hasher.salt = value

    @property
    def secret_key(self) -> Union[bytes, str, None]:
        """
        The ``secret_key`` input, which defaults to ``None`` and has the type
        ``Union[bytes, str, None]``.

        Argon2 allows you to hash with a ``secret_key``. Even though the default ``secret_key``
        is ``None``, it is recommended that you hash with a ``secret_key`` that is not ``None``.

        The ``secret_key`` is not encoded into the resulting hash string. This means that, later,
        when you would like to verify a password against a hash created with additional data,
        you will have to provide the same secret key that was used to create the hash to the
        ``verify`` function, ``Verifier.verify`` method, or ``Argon2.verify`` method in order to
        properly validate a valid password / hash pair.
        """
        return self.hasher.secret_key

    @secret_key.setter
    def secret_key(self, value: Union[bytes, str, None]) -> None:
        self.hasher.secret_key = value
        self.verifier.secret_key = value

    @property
    def threads(self) -> int:
        """
        The ``threads`` configuration, which defaults to ``the numeber of logical cores on
        your machine`` and has the type ``int``.

        If you have configured ``lanes`` (see above) to be more than one, you can get the
        hashing algorithm to run in parallel during some parts of the computation by setting
        the number of threads to be greater than one as well, potentially speeding up the time
        it takes to produce a hash without diminishing the security of the result.
        By default, the number of threads is set to the number of logical cores on your
        machine. If you set the number of ``threads`` to a number greater than the number of
        ``lanes``, the algorithm will automatically reduce the number of ``threads`` to the
        number of ``lanes``.
        """
        return self.hasher.threads

    @threads.setter
    def threads(self, value: int) -> None:
        self.hasher.threads = value
        self.verifier.threads = value

    @property
    def variant(self) -> Variant:
        """
        The ``variant`` configuration, which defaults to ``Variant.Argon2id`` and has the
        type ``Variant``.

        Argon2 has three variants: Argon2d, Argon2i, and Argon2id. Here is how these
        variants are explained in the RFC: "Argon2 has one primary variant: Argon2id,
        and two supplementary variants: Argon2d and Argon2i. Argon2d uses data-dependent
        memory access, which makes it suitable for ... applications with no threats from
        side-channel timing attacks. Argon2i uses data-independent memory access, which
        is preferred for password hashing and password-based key derivation. Argon2id
        works as Argon2i for the first half of the first iteration over the memory, and
        as Argon2d for the rest, thus providing both side-channel attack protection and
        brute-force cost savings due to time-memory tradeoffs." If you do not know which
        variant to use, use the default, which is ``Variant.Argon2id``.

        This configuration is only used for hashing (it will be read from the encoded hash
        string during verification as opposed to being provided by the user as during hashing).
        """
        return self.hasher.variant

    @variant.setter
    def variant(self, value: Variant) -> None:
        self.hasher.variant = value

    @property
    def version(self) -> Version:
        """
        The ``version`` configuration, which defaults to ``Version._0x13`` and has the
        type ``Version``.

        Argon2 has two versions: 0x10 and 0x13. The latest version is 0x13 (as of 5/18).
        Unless you have a very specific reason not to, you should use the latest
        version (0x13), which is also the default.

        This configuration is only used for hashing (it will be read from the encoded hash
        string during verification as opposed to being provided by the user as during hashing).
        """
        return self.hasher.version

    @version.setter
    def version(self, value: Version) -> None:
        self.hasher.version = value

    def hash(self, password: Union[bytes, str]) -> str:
        """
        The ``hash`` method.

        This function accepts a password of type ``bytes`` or ``str`` and returns an
        encoded hash of type ``str``. The hash will be created based on the configuration of the
        ``Argon2`` instance (i.e. based on its ``salt``, ``secret_key``, ``iterations``,
        ``memory_size`` etc.).
        """
        return self.hasher.hash(password=password)

    def verify(self, hash: str, password: Union[bytes, str]) -> bool:
        """
        The ``verify`` method.

        This function accepts a hash of type ``str`` and a  password of type ``bytes`` or ``str``.
        It returns ``True`` if the hash and password match or ``False`` is the hash and
        password do not match.

        If the hash was created with a ``secret_key`` (recommended) and/or ``additional_data``
        (not necessarily recommended), you will need to have set these properties on the
        ``Argon2`` instance before calling ``verify`` in order for a valid hash / password
        pair to return ``True``.
        """
        return self.verifier.verify(hash=hash, password=password)
