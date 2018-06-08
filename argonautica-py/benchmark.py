import timeit

from argonautica import Hasher


def benchmark():
    hasher = Hasher()
    encoded = hasher.hash("P@ssw0rd")


if __name__ == "__main__":
    iterations = 100
    print("Running {} iterations ...".format(iterations))
    setup = "from __main__ import benchmark"
    seconds = timeit.timeit("benchmark()", number=iterations, setup=setup)
    print("Ran {} iterations at {:.3f} iterations per second".format(
        iterations, seconds / iterations
    ))
