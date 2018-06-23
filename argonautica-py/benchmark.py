import timeit

from argonautica import Hasher
from argonautica.defaults import *
from passlib.hash import argon2


def argonautica():
    hasher = Hasher(secret_key=None, variant=Variant.Argon2i)
    hasher.hash(password="P@ssw0rd")


def passlib():
    argon2.using(
        memory_cost=DEFAULT_MEMORY_SIZE,
        hash_len=DEFAULT_HASH_LEN,
        max_threads=DEFAULT_THREADS,
        parallelism=DEFAULT_THREADS,
        rounds=DEFAULT_ITERATIONS,
        salt_len=DEFAULT_SALT_LEN,
    ).hash("P@ssw0rd")


if __name__ == "__main__":
    iterations = 10

    print("Running argonautica for {} iterations ...".format(iterations))
    setup = "from __main__ import argonautica"
    seconds = timeit.timeit("argonautica()", number=iterations, setup=setup)
    print("Argonautica ran {} iterations at {:.3f} seconds per iteration".format(
        iterations, seconds / iterations
    ))

    print("Running passlib for {} iterations ...".format(iterations))
    setup = "from __main__ import passlib"
    seconds = timeit.timeit("passlib()", number=iterations, setup=setup)
    print("Passlib ran {} iterations at {:.3f} seconds per iteration".format(
        iterations, seconds / iterations
    ))
