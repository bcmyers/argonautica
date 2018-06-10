import timeit

from argonautica import Hasher
from argonautica.config import (
    DEFAULT_ITERATIONS, DEFAULT_MEMORY_SIZE,
    DEFAULT_THREADS, DEFAULT_HASH_LENGTH, Variant
)
from argonautica.data import DEFAULT_SALT_LEN
from passlib.hash import argon2


def argonautica():
    hasher = Hasher(secret_key=None, variant=Variant.Argon2i)
    hasher.hash("P@ssw0rd")


def passlib():
    argon2.using(
        memory_cost=DEFAULT_MEMORY_SIZE,
        hash_len=DEFAULT_HASH_LENGTH,
        max_threads=DEFAULT_THREADS,
        parallelism=DEFAULT_THREADS,
        rounds=DEFAULT_ITERATIONS,
        salt_len=DEFAULT_SALT_LEN,
    ).hash("P@ssw0rd")


if __name__ == "__main__":
    iterations = 100

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
