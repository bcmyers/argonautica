from argonautica import Hasher, Verifier
from argonautica.config import Backend, Variant, Version

# This does the came thing as the configuration.py example. Instead of
# configuring a Hasher / Verifier by setting properties, you can pass
# keywork arguments to their constructors...

hasher = Hasher(
    additional_data=None,
    backend=Backend.C,
    hash_len=32,
    iterations=192,
    lanes=2,
    memory_size=4096,
    threads=2,
    salt='somesalt',
    secret_key=None,
    variant=Variant.Argon2id,
    version=Version._0x13
)

hash = hasher.hash(password='P@ssw0rd')
assert(hash == '$argon2id$v=19$m=4096,t=192,p=2$c29tZXNhbHQ$8nD3gRm+NeOcIiIrlnzDAdnK4iD+K0mVqFXowGs13M4')

verifier = Verifier(
    additional_data=None,
    backend=Backend.C,
    secret_key=None,
    threads=2
)

is_valid = verifier.verify(
    hash=hash,
    password='P@ssw0rd'
)
assert(is_valid)
