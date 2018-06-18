class RandomSalt:
    """
    ``RandomSalt`` is a class representing salt that is updated with random values
    before each hash

    You can set the ``salt`` property of an instance of ``Argon2`` or ``Hasher`` to an
    instance of ``RandomSalt`` in order to ensure that every time you call the ``hash`` method
    a new random salt will be created for you and used.

    To instantiate a ``RandomSalt`` you must provide it with a length that represents the
    length of your desired random salt in bytes.

    The default ``salt`` for both the ``Argon2`` class and the ``Hasher`` class is a
    ``RandomSalt`` with length ``32``.
    """
    __slots__ = ['len']

    def __init__(self, len: int = 32) -> None:
        self.len = len

    def __len__(self) -> int:
        return self.len
