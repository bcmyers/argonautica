from argonautica import Hasher

hasher = Hasher(secret_key='somesecret', hash_len=16)
hash = hasher.hash(password='P@ssw0rd')
print(hash)
