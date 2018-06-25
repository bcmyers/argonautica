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
