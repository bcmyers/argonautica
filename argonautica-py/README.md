# Overview

[argonautica](https://github.com/bcmyers/argonautica/tree/master/argonautica-py/)
is a Python package for hashing passwords that uses the
cryptographically-secure [argon2](https://en.wikipedia.org/wiki/Argon2)
hashing algorithm.

[argon2](https://en.wikipedia.org/wiki/Argon2) won the [Password Hashing
Competition](https://password-hashing.net/) in 2015, a several year
project to identify a successor to
[bcrypt](https://en.wikipedia.org/wiki/Bcrypt),
[scrypt](https://en.wikipedia.org/wiki/Scrypt), and other common hashing
algorithms.

There are several Python packages that implement argon2, but
[argonautica](https://github.com/bcmyers/argonautica/tree/master/argonautica-py/)
is the only one written in [Rust](https://www.rust-lang.org/en-US/) (as
opposed to C or C++). Rust \<https://www.rust-lang.org/en-US/\>\_ is a
\"systems programming language that runs blazingly fast, prevents
segfaults, and guarantees thread safety.\"

AFAIK,
[argonautica](https://github.com/bcmyers/argonautica/tree/master/argonautica-py/)
is the only implementation of the argon2 hashing algorithm available in
Python that supports password hashing with secret keys. Not even the
[cannonical C
implementation](https://github.com/P-H-C/phc-winner-argon2) of argon2
exposes this feature publicly (it\'s in the code, but unfortunately not
accessable via the public API).

Another feature of
[argonautica](https://github.com/bcmyers/argonautica/tree/master/argonautica-py/)
is that it uses [SIMD](https://en.wikipedia.org/wiki/SIMD) instructions
to peform it\'s hashing algorithm (if they are available on your CPU),
which means it\'s taking full advantage of modern CPUs to run as fast as
possible. The downside is that you have to compile it for your specific
machine (this is why the pip install argonautica process takes a bit of
time).

# Requirements

- [Python](https://www.python.org/) version 3.4.0 or higher (or
  [PyPy](http://pypy.org/) version 3.5 or higher)
- Rust \<https://www.rust-lang.org/en-US/\>\_ version 1.26.0 or higher
- LLVM \<https://llvm.org/\>\_ version 3.9.0 or higher

# Installation

- Python \<https://www.python.org/\>\_:
  - macOS: brew install python3, which requires
    Homebrew \<https://brew.sh/\>\_
  - Linux: Use your distribution\'s package manager or follow the
    instructions here \<https://www.python.org/downloads/\>\_
  - Windows: Follow the instructions
    here \<https://www.python.org/downloads/\>\_
- Rust \<https://www.rust-lang.org/en-US/\>\_:
  - Run the following command in your terminal, then follow the
    onscreen instructions: curl https://sh.rustup.rs -sSf \| sh
- LLVM \<https://llvm.org/\>\_:
  - macOS: brew install llvm, which requires
    Homebrew \<https://brew.sh/\>\_
  - Debian-based linux: apt-get install llvm-dev libclang-dev clang
  - Arch linux: pacman -S clang
  - Other linux: Use your distribution\'s package manager
  - Windows: Download a pre-built binary
    here \<http://releases.llvm.org/download.html\>\_
- argonautica:
  - pip install argonautica -v once you have completed the steps
    above
  - Unfortunately, this step may take several minutes, as
    [argonautica](https://github.com/bcmyers/argonautica/tree/master/argonautica-py/)
    needs to compile it\'s Rust code for your specific CPU (due to
    its use of SIMD instructions). The upside, however, is that once
    compiled,
    [argonautica](https://github.com/bcmyers/argonautica/tree/master/argonautica-py/)
    should run blazingly fast
  - For those of you who are wondering why
    [argonautica](https://github.com/bcmyers/argonautica/tree/master/argonautica-py/)
    doesn\'t offer pre-compiled wheels like most other native
    libraries, it\'s precisely because of the SIMD instructions.
    Other native libraries can pre-compile a small number of
    libraries that work pretty much everywhere (e.g. 64bit macOS,
    32bit linux, 64bit linux, 32bit Windows, 64bit Windows), but
    [argonautica](https://github.com/bcmyers/argonautica/tree/master/argonautica-py/)
    compiles code that\'s not just specific to a
    platform/architecture combination. Rather it\'s specific to a
    platform/architecture/cpu combination; so 64bit macOS code on a
    Haswell processor will be different than 64bit macOS code on a
    Skylake processor.

# Usage

### Hashing

```{.sourceCode .python3}
from argonautica import Hasher             # or ... from argonautica import Argon2

hasher = Hasher(secret_key='somesecret')   # or ... argon2 = Argon2(secret_key='somesecret')
hash = hasher.hash(password='P@ssw0rd')    # or ... hash = argon2.hash(password='P@ssw0rd')
print(hash)
```

### Verifying

```{.sourceCode .python3}
from argonautica import Verifier              # or ... from argonautica import Argon2

verifier = Verifier(secret_key='somesecret')  # or ... argon2 = Argon2(secret_key='somesecret')
is_valid = verifier.verify(                   # or ... is_valid = argon2.verify(...
    hash='$argon2id$v=19$m=4096,t=128,p=2$c29tZXNhbHQ$WwD2/wGGTuw7u4BW8sLM0Q',
    password='P@ssw0rd',
)
print(is_valid)
```
