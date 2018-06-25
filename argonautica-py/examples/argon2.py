from argonautica import Argon2

argon2 = Argon2(secret_key='somesecret')

hash = argon2.hash(password='P@ssw0rd')
print(hash)

is_valid = argon2.verify(hash=hash, password='P@ssw0rd')
assert(is_valid)
