from argonautica import Hasher
from argonautica.data import RandomSalt

hasher = Hasher(
    salt=RandomSalt(16),
    # 👆 Here we're using a RandomSalt of length of 16 bytes
    # instead of the default, which is a RandomSalt of length 32 bytes
    secret_key="somesecret"
)
hash = hasher.hash(password='P@ssw0rd')
print(hash)
