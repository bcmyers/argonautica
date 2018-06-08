class RandomSalt:
    def __init__(self, len: int = 32) -> None:
        self.len = len


DEFAULT_SALT_LEN = 32
DEFAULT_SALT = RandomSalt(DEFAULT_SALT_LEN)
