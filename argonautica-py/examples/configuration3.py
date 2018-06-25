from argonautica import Hasher, Verifier
from argonautica.config import Backend, Variant, Version

# This does the same thing as the configuration2.py example. Instead of
# configuring a Hasher and a Verifier by passing keywork arguments to their
# constructors, however, this example pushes the configuration down to the
# hash method and the verify method, which is also possible.
#
# The only difference is that configuration options passed to the hash method
# of a Hasher or the verify method of a Verifier will will not persist on the
# Hasher / Verifier instances (i.e. they are not stored like in the case of
# passing them as keyword arguments to the constructor or assigning them as
# properties of the instance)...

hasher = Hasher(secret_key=None)

hash = hasher.hash(
    password='P@ssw0rd',

    additional_data=None,
    backend=Backend.C,
    hash_len=32,
    iterations=192,
    lanes=2,
    memory_size=4096,
    threads=2,
    salt='somesalt',
    variant=Variant.Argon2id,
    version=Version._0x13
)
assert(hash == '$argon2id$v=19$m=4096,t=192,p=2$c29tZXNhbHQ$8nD3gRm+NeOcIiIrlnzDAdnK4iD+K0mVqFXowGs13M4')

verifier = Verifier(
    secret_key=None,
)

is_valid = verifier.verify(
    additional_data=None,
    backend=Backend.C,
    hash=hash,
    password='P@ssw0rd',
    threads=2
)
assert(is_valid)
