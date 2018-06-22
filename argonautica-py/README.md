# [argonautica](https://en.wikipedia.org/wiki/Argonautica)

[![Build Status](https://travis-ci.org/bcmyers/argonautica.svg?branch=master)](https://travis-ci.org/bcmyers/argonautica)
[![Github.com](https://img.shields.io/badge/github-bcmyers%2Fargonautica-blue.svg)](http://www.github.com/bcmyers/argonautica)
![License](https://img.shields.io/crates/l/argonautica.svg)

## Overview

**argonautica** is a Python package for hashing passwords that uses the cryptographically-secure [argon2](https://en.wikipedia.org/wiki/Argon2) hashing algorithm.

Argon2 won the [Password Hashing Competition](https://password-hashing.net/) in 2015, a several year project to identify a successor to [bcrypt](https://en.wikipedia.org/wiki/Bcrypt), [scrypt](https://en.wikipedia.org/wiki/Scrypt), and other common hashing algorithms.

## Alternatives

There are several Python packages that implement argon2, including the excellent [passlib](http://passlib.readthedocs.io/en/stable/), but...

* AFAIK, **argonautica** is the only Python implementation of argon2 that supports hashing with secret keys. Not even the [cannonical C implementation](https://github.com/P-H-C/phc-winner-argon2) of argon2 exposes this feature publicly (it's in the code, but unfortunately not accessable via the public API).

* **argonautica** is the only Python implementation of argon2 to use [SIMD](https://en.wikipedia.org/wiki/SIMD) instructions to peform it's hashing algorithm, which means it can be quite fast. The downside is that you have to compile it for your specific machine (this is why the `pip install argonautica` process takes time). That said, on the developer's early 2014 Macbook Air, which has [SIMD](https://en.wikipedia.org/wiki/SIMD) instruction through [AVX2](https://en.wikipedia.org/wiki/Advanced_Vector_Extensions), argonautica runs ~30% faster than passlib on default settings.

* **argonautica** supports the latest argon2 variant: argon2id, which, unless you have a reason not to, you should be using. A number of Python implementations do not yet support this variant.

* Finally, **argonautica** is the only Python implementation of argon2 written in [Rust](https://www.rust-lang.org/en-US/) (as opposed to C or C++). [Rust](https://www.rust-lang.org/en-US/) is a \"systems programming language that runs blazingly fast, prevents segfaults, and guarantees thread safety.\"


## Requirements

- [Python](https://www.python.org/) version 3.4 or higher (or [PyPy](http://pypy.org/) version 3.5 or higher)
- [Rust](https://www.rust-lang.org/en-US/) version 1.26 or higher
- [LLVM](https://llvm.org/) version 3.9 or higher

## Installation

- Rust:
  - Follow the instructions [here](https://www.rust-lang.org/en-US/install.html), which will just tell you to run the following command in your terminal and follow the on-screen instructions: `curl https://sh.rustup.rs -sSf \| sh`
- LLVM:
  - macOS: `brew install llvm`, which requires [Homebrew](https://brew.sh/)
  - Debian-based linux: `apt-get install llvm-dev libclang-dev clang`
  - Arch linux: `pacman -S clang`
  - Other linux: Use your distribution's package manager
  - Windows: Download a pre-built binary [here](http://releases.llvm.org/download.html)
- argonautica:
  - `pip install --upgrade pip` or `pip install setuptools-rust`. Note: setuptool-rust is not required if you have pip version 10.0 or above
  - `pip install argonautica -v` once you have completed the steps above. Unfortunately, this step may take several minutes, as argonautica needs to compile it's Rust code for your specific CPU (due to its use of SIMD instructions). The upside, however, is that once compiled, argonautica should run blazingly fast

## Usage

### Hashing

```python3
from argonautica import Hasher             # or ... from argonautica import Argon2

hasher = Hasher(secret_key='somesecret')   # or ... argon2 = Argon2(secret_key='somesecret')
hash = hasher.hash(password='P@ssw0rd')    # or ... hash = argon2.hash(password='P@ssw0rd')
print(hash)
```

### Verifying

```python3
from argonautica import Verifier              # or ... from argonautica import Argon2

verifier = Verifier(secret_key='somesecret')  # or ... argon2 = Argon2(secret_key='somesecret')
is_valid = verifier.verify(                   # or ... is_valid = argon2.verify(...
    hash='$argon2id$v=19$m=4096,t=128,p=2$c29tZXNhbHQ$WwD2/wGGTuw7u4BW8sLM0Q',
    password='P@ssw0rd',
)
print(is_valid)
```

### Configuration

```python3
todo
```
