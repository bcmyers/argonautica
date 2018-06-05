argonautica-py
========

.. toctree::
   :maxdepth: 3
   :caption: Contents:

argonautica-py_ is a Python package for password hashing that uses the cryptographically-secure argon2_ hashing algorithm.

In 2015, argon2_ won the `Password Hashing Competition <https://password-hashing.net/>`_, a several year project to identify a successor to bcrypt_, scrypt_, and other common hashing algorithms.

There are several Python packages that implement argon2, but argonautica-py_ is the only one written in Rust_ (as opposed to C or C++). Rust_ is a "systems programming language that runs blazingly fast, prevents segfaults, and guarantees thread safety."

AFAIK, argonautica-py_ is the only implementation of the argon2 hashing algorithm available in Python that supports password hashing with secret keys. Not even the `cannonical C implementation <https://github.com/P-H-C/phc-winner-argon2>`_ of argon2 exposes this feature publicly (it's in the code, but unfortunately not accessable via the public API).

Another feature of argonautica-py_ is that it uses `SIMD <https://en.wikipedia.org/wiki/SIMD>`_ instructions to peform it's hashing algorithm (if they are available), which means it's taking full advantage of modern CPUs to run as fast as possible. The downside is that you have to compile it for your specific machine (so this is why the ``pip install argonautica-py`` process takes a bit of time).

Requirements
============

  * Python3_
  * Rust_ version 1.26.0 or higher
  * LLVM_ version 3.9.0 or higher

Installation
============

  * Python3_:
      - macOS: ``brew install python3``, which requires Homebrew_
      - Linux or Windows: Follow the instructions `here <https://www.python.org/downloads/>`_
  * Rust_:
      - Run the following command in your terminal, then follow the onscreen instructions: ``curl https://sh.rustup.rs -sSf | sh``
  * LLVM_:
      - macOS: ``brew install llvm``, which requires Homebrew_
      - Debian-based linux: ``apt-get install llvm-dev libclang-dev clang``
      - Arch linux: ``pacman -S clang``
      - Windows: Download a pre-built binary `here <http://releases.llvm.org/download.html>`_
  * argonautica-py:
      - ``pip install argonautica-py`` once you have completed the steps above

Usage
=====

Hashing
^^^^^^^

.. code-block:: python3

    from argonautica import Hasher

    hasher = Hasher()
    hash = hasher.hash(password='P@ssw0rd', secret_key='mysecret')
    print(hash)

Verifying
^^^^^^^^^

.. code-block:: python3

    from argonautica import Verifier

    verifier = Verifier()
    is_valid = verifier.verify(
        hash='$argon2id$v=19$m=4096,t=128,p=2$c29tZXNhbHQ$WwD2/wGGTuw7u4BW8sLM0Q',
        password='P@ssw0rd',
        secret_key='mysecret'
    )
    print(is_valid)

A more "real world" example
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Stuff and things.

Configuration details
^^^^^^^^^^^^^^^^^^^^^

argon2 has many configuration options...

Addendum
========

For the curious, argonautica-py gets it's name from the Argonautica, a greek epic which tells the tale of `Jason <https://en.wikipedia.org/wiki/Jason>`_ and his `Argonauts <https://en.wikipedia.org/wiki/Argonauts>`_ on their quest for the `Golden Fleece <https://en.wikipedia.org/wiki/Golden_Fleece>`_.

.. _argon2: https://en.wikipedia.org/wiki/Argon2
.. _argonautica-rs: https://github.com/bcmyers/argonautica
.. _argonautica-py: https://github.com/bcmyers/argonautica/tree/master/argonautica-py
.. _bcrypt: https://en.wikipedia.org/wiki/Bcrypt
.. _Homebrew: https://brew.sh/
.. _LLVM: https://llvm.org/
.. _Python3: https://www.python.org/
.. _Rust: https://www.rust-lang.org/en-US/
.. _scrypt: https://en.wikipedia.org/wiki/Scrypt

