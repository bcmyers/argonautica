# argonautica-py

[![Build Status](https://travis-ci.org/bcmyers/argonautica.svg?branch=master)](https://travis-ci.org/bcmyers/argonautica)
[![Github.com](https://img.shields.io/badge/github-bcmyers%2Fargonautica-blue.svg)](http://www.github.com/bcmyers/argonautica)
![License](https://img.shields.io/crates/l/argonautica.svg)
[![PyPI](https://img.shields.io/pypi/v/argonautica.svg)](https://pypi.org/project/argonautica)

## Overview

**argonautica** is a Python package for hashing passwords that uses the cryptographically-secure [argon2](https://en.wikipedia.org/wiki/Argon2) hashing algorithm.

Argon2 won the [Password Hashing Competition](https://password-hashing.net/) in 2015, a several year project to identify a successor to [bcrypt](https://en.wikipedia.org/wiki/Bcrypt), [scrypt](https://en.wikipedia.org/wiki/Scrypt), and other common hashing algorithms.

**argonautica** was built with a simple use-case in mind: hashing passwords for storage in a
website's database. That said, it's also "feature-complete", meaning anything you can do with
the cannonical [C implementation](https://github.com/P-H-C/phc-winner-argon2) of argon2
you can do with argonautica\*.

<i>\* Indeed, argonautica has a feature that even the cannonical C implementation
lacks, i.e. hashing passwords with secret keys (the C implementation implements this, but
does not expose it publicly)</i>

## Alternatives

There are several Python packages that implement argon2, including the excellent [passlib](http://passlib.readthedocs.io/en/stable/), which uses [argon2_cffi](https://github.com/hynek/argon2_cffi), but...

- AFAIK, **argonautica** is the only Python implementation of argon2 that supports hashing with secret keys. Not even the [cannonical C implementation](https://github.com/P-H-C/phc-winner-argon2) of argon2 exposes this feature publicly (it's in the code, but unfortunately not accessable via the public API).

- **argonautica** is the only Python implementation of argon2 to use [SIMD](https://en.wikipedia.org/wiki/SIMD) instructions to peform it's hashing algorithm, which means it can be quite fast. The downside is that you have to compile it for your specific machine (this is why the `pip install argonautica` process takes time). That said, on the developer's early 2014 Macbook Air, which has [SIMD](https://en.wikipedia.org/wiki/SIMD) instruction through [AVX2](https://en.wikipedia.org/wiki/Advanced_Vector_Extensions), argonautica runs ~30% faster than passlib on default settings.

- **argonautica** supports the latest argon2 variant: argon2id, which, unless you have a reason not to, you should be using. A number of Python implementations do not yet support this variant.

- Finally, **argonautica** is the only Python implementation of argon2 written in [Rust](https://www.rust-lang.org/en-US/) (as opposed to C or C++). [Rust](https://www.rust-lang.org/en-US/) is a \"systems programming language that runs blazingly fast, prevents segfaults, and guarantees thread safety.\"

## Requirements

- [Python](https://www.python.org/) version 3.4 or higher (or [PyPy](http://pypy.org/) version 3.5 or higher)
- [Rust](https://www.rust-lang.org/en-US/) version 1.26 or higher
- [LLVM](https://llvm.org/) version 3.9 or higher

## Installation

- **Rust:**
  - Follow the instructions [here](https://www.rust-lang.org/en-US/install.html), which will just tell you to run the following command in your terminal and follow the on-screen instructions: `curl https://sh.rustup.rs -sSf \| sh`
- **LLVM:**
  - macOS: `brew install llvm`, which requires [Homebrew](https://brew.sh/)
  - Debian-based linux: `apt-get install llvm-dev libclang-dev clang`
  - Arch linux: `pacman -S clang`
  - Other linux: Use your distribution's package manager
  - Windows: Download a pre-built binary [here](http://releases.llvm.org/download.html)
- **argonautica:**
  - `pip install --upgrade pip` or `pip install setuptools-rust`. Note: setuptool-rust is not required if you have pip version 10.0 or above
  - `pip install argonautica`. Unfortunately, this step may take several minutes, as argonautica needs to compile it's Rust code for your specific CPU (due to its use of SIMD instructions). The upside, however, is that once compiled, argonautica should run blazingly fast

## Usage

### Hashing

```python3
from argonautica import Hasher

hasher = Hasher(secret_key='somesecret')
hash = hasher.hash(password='P@ssw0rd')
print(hash)
# 👆 prints a random hash as the defeault `Hasher` uses a random salt by default
```

### Verifying

```python3
from argonautica import Verifier

verifier = Verifier(secret_key='somesecret')
is_valid = verifier.verify(
    hash='$argon2id$v=19$m=4096,t=192,p=2$ULwasg5z5byOAork0UEhoTBVxIvAafKuceNz9NdCVXU$YxhaPnqRDys',
    password='P@ssw0rd',
)
assert(is_valid)
```

### Configuration

```python3
from argonautica import Hasher, Verifier
from argonautica.config import Backend, Variant, Version

hasher = Hasher(secret_key=None)
# 👆 A secret key (passed as a keyword argument) is required to instantiate a
# Hasher, a Verifier, or an Argon2, but you are allowed to pass `None`
# in order to forgo using a secret key (this is not recommended)

hasher.additional_data = None  # Default is None
# 👆 Although rarely used, argon2 allows you to hash a password
# with not only salt and a secret key, but also with "additional data",
# which acts as a kind of secondary secret key. Like a secret key, it affects
# the outcome of the hash and is not stored in the string-encoded output, meaning
# later, to verify against a hash created with additional data, you will need to
# supply the same additional data manually to the Verifier (just like you have to
# do with a secret key). Again, this is rarely used.

hasher.backend = Backend.C  # Default is Backend.C
# 👆 argonautica was designed to support multiple backends (meaning multiple
# implementations of the underlying argon2 algorithm). Currently only the
# C backend is supported, which uses the cannonical argon2 library written
# in C to actually do the work. In the future a Rust backend will also be
# supported, but, for the moment, you must use Backend.C, which is the
# default. Using Backend.Rust will result in an error (again, for the
# moment).

hasher.hash_len = 32  # Default is 32
# 👆 The hash length in bytes is configurable. The default is 32.
# This is probably a good number to use. 16 is also probably fine.
# You probably shouldn't go below 16

hasher.iterations = 192  # Default is 192
# 👆 Argon2 has a notion of "iterations" or "time cost". All else equal
# and generally speaking, the greater the number of iterations, the
# longer it takes to perform the hash and the more secure the resulting
# hash. More iterations basically means more CPU load. This and "memory
# size" (see below) are the two primary parameters to adjust in order
# to increase or decrease the security of your hash. The default is
# 192 iterations, which was chosen because, along with the default
# memory size of 4096, this leads to a hashing time of approximately
# 300 milliseconds on the early-2014 Macbook Air that is the developer's
# machine. If you're going to use argonautica in production, you should
# probably tweak this parameter (and the memory size parameter) in order
# to increase the time it takes to hash to the maximum you can
# reasonably allow for your use-case (e.g. to probably about 300-500
# milliseconds for the use-case of hashing user passwords for a website)

hasher.lanes = 2  # Default is multiprocessing.cpu_count()
# 👆 Argon2 can break up its work into one or more "lanes" during some parts of
# the hashing algorithm. If you configure it with multiple lanes and you also
# use multiple threads (see below) the hashing algorithm will performed its
# work in parallel in some parts, potentially speeding up the time it takes to
# produce a hash without diminishing the security of the result. By default,
# the number of lanes is set to the number of logical cores on your machine

hasher.memory_size = 4096  # Default is 4096
# 👆 Argon2 has a notion of "memory size" or "memory cost" (in kibibytes). All else
# equal and generally speaking, the greater the memory size, the longer it takes to
# perform the hash and the more secure the resulting hash. More memory size basically
# means more memory used. This and "iterations" (see above) are, again, generally
# speaking, the two parameters to adjust in order to increase or decrease the
# security of your hash. The default is 4096 kibibytes, which was chosen because,
# again, along with the default iterations of 192, this leads to a hashing time of
# approximately 300 milliseconds on the early-2014 Macbook Air that is the
# developer's machine. If you're going to use argonautica in production, you should
# probably tweak this parameter (and the iterations parameter) in order to increase
# the time it takes to hash to the maximum you can reasonably allow for your use-case
# (e.g. to probably about 300-500 milliseconds for the use-case of hashing user
# passwords for a website)

hasher.threads = 2  # Default is multiprocessing.cpu_count()
# 👆 If you have configured a Hasher to use more than one lane (see above), you
# can get the hashing algorithm to run in parallel during some parts of the
# computation by setting the number of threads to be greater than one as well,
# potentially speeding up the time it takes to produce a hash without diminishing
# the security of the result. By default, the number of threads is set to the number
# of logical cores on your machine. If you set the number of threads to a number
# greater than the number of lanes, `Hasher` will automatically reduce the number
# of threads to the number of lanes

hasher.variant = Variant.Argon2id  # Default is Variant.Argon2id
# 👆 Argon2 has three variants: Argon2d, Argon2i, and Argon2id. Here is how these
# variants are explained in the RFC: "Argon2 has one primary variant: Argon2id,
# and two supplementary variants: Argon2d and Argon2i. Argon2d uses data-dependent
# memory access, which makes it suitable for ... applications with no threats from
# side-channel timing attacks. Argon2i uses data-independent memory access, which
# is preferred for password hashing and password-based key derivation. Argon2id
# works as Argon2i for the first half of the first iteration over the memory, and
# as Argon2d for the rest, thus providing both side-channel attack protection and
# brute-force cost savings due to time-memory tradeoffs." If you do not know which
# variant to use, use the default, which is Argon2id

hasher.version = Version._0x13  # Default is Version._0x13
# 👆 Argon2 has two versions: 0x10 and 0x13. The latest version is 0x13 (as of 5/18).
# Unless you have a very specific reason not to, you should use the latest
# version (0x13), which is also the default

hash = hasher.hash(
    password='P@ssw0rd',
    salt='somesalt',       # You can set your own salt, or use the default: RandomSalt(32)
)
assert(hash == '$argon2id$v=19$m=4096,t=192,p=2$c29tZXNhbHQ$8nD3gRm+NeOcIiIrlnzDAdnK4iD+K0mVqFXowGs13M4')

verifier = Verifier(secret_key=None)
verifier.additional_data = None  # As with Hasher, you can configure a Verifier's additional data
verifier.backend = Backend.C     # As with Hasher, you can configure a Verifier's backend
verifier.threads = 2             # As with Hasher, you can configure a Verifier's threads

is_valid = verifier.verify(
    hash=hash,
    password='P@ssw0rd'
)
assert(is_valid)
```

### Miscellaneous

**mypy**

- **argonautica** uses [mypy](http://mypy-lang.org/) type annotations everywhere in the code, which, in the author's humble opinion, is a very useful form of documentation; so if you're ever confused about what types to use for arguments, just pop open the code and take a look at the function signatures.

**Argon2**

`Argon2` is a convenience class that holds both a `Hasher` and a `Verifier`. If you'd like to use just one class that knows how both to hash and to verify, instantiate an `Argon2`. It works essentially the same way as `Hasher` and `Verifier` do.

```python3
from argonautica import Argon2

argon2 = Argon2(secret_key='somesecret')

hash = argon2.hash(password='P@ssw0rd')
print(hash)

is_valid = argon2.verify(hash=hash, password='P@ssw0rd')
assert(is_valid)
```

**RandomSalt**

- `RandomSalt` is a special kind of salt that will create new random salt bytes before each hash. A RandomSalt knows its length (in number of bytes). The default `Hasher` uses a `RandomSalt` with length of 32 bytes, but you can use your own `RandomSalt` of custom length. When you instantiate a `RandomSalt`, the constructor takes a length, e.g. `my_random_salt = RandomSalt(16)`

```python3
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
```

**HashRaw**

- Hashing with **argonautica** produces a string-encoded hash, but sometimes you might want the "raw material" behind this hash, i.e. the raw hash bytes, the raw salt bytes, or raw parameters, which are the three component parts of a string-encoded hash. To obtain these raw parts...

```python3
from argonautica.utils import decode, HashRaw

hash = '$argon2id$v=19$m=4096,t=128,p=2$c29tZXNhbHQ$WwD2/wGGTuw7u4BW8sLM0Q'

# Create a `HashRaw` using the `decode` function
hash_raw = decode(hash)

# Pull out the raw parameters
iterations = hash_raw.iterations     # 128
lanes = hash_raw.lanes               # 2
memory_size = hash_raw.memory_size   # 4096
variant = hash_raw.variant           # Variant.Argon2id
version = hash_raw.version           # Version._0x13

# Pull out the raw bytes
raw_hash_bytes = hash_raw.raw_hash_bytes  # b'[\x00\xf6\xff\x01\x86N\xec;\xbb\x80V\xf2\xc2\xcc\xd1'
raw_salt_bytes = hash_raw.raw_salt_bytes  # b'somesalt'

# Turn a `HashRaw` back into a string-encoded hash using the `encode` method
hash2 = hash_raw.encode()
assert(hash == hash2)
```

## License

**argonautica** is licensed under either of:

- [The Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0), or
- [The MIT license](http://opensource.org/licenses/MIT)

at your option.
