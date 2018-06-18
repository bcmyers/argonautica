# [argonautica](https://en.wikipedia.org/wiki/Argonautica)

[![Build Status](https://travis-ci.org/bcmyers/argonautica.svg?branch=master)](https://travis-ci.org/bcmyers/argonautica)
[![Crates.io](https://img.shields.io/crates/v/argonautica.svg)](https://crates.io/crates/argonautica)
[![Documentation](https://docs.rs/argonautica/badge.svg)](https://docs.rs/argonautica/)
[![Github.com](https://img.shields.io/badge/github-bcmyers%2Fargonautica-blue.svg)](http://www.github.com/bcmyers/argonautica)
![License](https://img.shields.io/crates/l/argonautica.svg)

## Overview

<b>argonautica</b> is a series of libraries for hashing passwords using the cryptographically-secure
[Argon2 hashing algorithm](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03).

[Argon2](<(https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03)>) won the
[Password Hashing Competition](https://password-hashing.net/) in 2015, a several
year project to identify a successor to [bcrypt](https://en.wikipedia.org/wiki/Bcrypt),
[scrypt](https://en.wikipedia.org/wiki/Scrypt), and other common cryptographically-secure
hashing algorithms.

The libraries are:

| Language          | Library                                                                             | Status |
| ----------------- | ----------------------------------------------------------------------------------- | :----: |
| C / C++           | [argonautica-c](https://github.com/bcmyers/argonautica/tree/master/argonautica-c)   |   👍   |
| Javascript (Node) | [argonautica-js](https://github.com/bcmyers/argonautica/tree/master/argonautica-js) |  WIP   |
| Python3 / PyPy3   | [argonautica-py](https://github.com/bcmyers/argonautica/tree/master/argonautica-py) |   👍   |
| Rust              | [argonautica-rs](https://github.com/bcmyers/argonautica/tree/master/argonautica-rs) |   👍   |

All of the libraries use the <b>Rust implemenation</b> [argonautica-rs](https://github.com/bcmyers/argonautica/tree/master/argonautica-rs) at their core.

## License

<b>argonautica</b> is licensed under either of:

- [The Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0), or
- [The MIT license](http://opensource.org/licenses/MIT)

at your option.
