# argonautica-c

[![Build Status](https://travis-ci.org/bcmyers/argonautica.svg?branch=master)](https://travis-ci.org/bcmyers/argonautica)
[![Crates.io](https://img.shields.io/crates/v/argonautica-c.svg)](https://crates.io/crates/argonautica-c)
[![Documentation](https://docs.rs/argonautica-c/badge.svg)](https://docs.rs/argonautica-c/)
[![Github.com](https://img.shields.io/badge/github-bcmyers%2Fargonautica-blue.svg)](http://www.github.com/bcmyers/argonautica)
![License](https://img.shields.io/crates/l/argonautica-c.svg)

## Overview

[argonautica-c](https://github.com/bcmyers/argonautica/tree/master/argonautica-c)
is a C/C++ wrapper for
[argonautica](https://crates.io/crates/argonautica).

## Installation

* Install [Rust](https://www.rust-lang.org/en-US/) (version 1.26.0 or higher)
    * See [here](https://rustup.rs/) for instructions
* Install [LLVM/Clang](https://llvm.org/) (version 3.9 or higher)
    * Mac OS: `brew install llvm`, which requires [Homebrew](https://brew.sh/)
    * Debian-based linux: `apt-get install clang llvm-dev libclang-dev`
    * Arch linux: `pacman -S clang`
    * Windows: Download a pre-built binary [here](http://releases.llvm.org/download.html)
* Clone the [argonautica repository](https://github.com/bcmyers/argonautica)
    * `git clone https://github.com/bcmyers/argonautica.git`
    * `cd argonautica`
    * `git submodule init`
    * `git submodule update`
* Build the library using [Cargo](https://github.com/rust-lang/cargo)
    * `cargo build --release --features="simd"`, or
    * `cargo build --release`
* Use the library
    * The library, which will be called `libargonautica_c.dylib` or something similar (depending on your OS), will be in the `./target/release` directory
    * The header file, which will be called `argonautica.h`, will be in the `./argonautica-c/include` directory

## License

<b>argonautica-c</b> is licensed under either of:
* [The Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0), or
* [The MIT license](http://opensource.org/licenses/MIT)

at your option.
