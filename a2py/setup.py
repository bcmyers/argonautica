import os
from setuptools import setup, find_packages
from setuptools_rust import Binding, RustExtension

import pypandoc

here = os.path.abspath(os.path.dirname(__file__))


def long_description() -> str:
    return pypandoc.convert('README.md', 'rst').replace("\r", "")


setup(
    name="a2py",
    version="0.1.0",

    author="Brian Myers",
    author_email="brian.carl.myers@gmail.com",
    description="Idiomatic Argon2 password hashing for Python based on the Rust a2 crate",
    license="MIT/Apache-2.0",
    long_description=long_description(),
    url="https://github.com/bcmyers/a2",

    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Security :: Cryptography",
    ],

    install_requires=['cffi'],

    keywords="argon2 argon2d argon2i argon2id crypto cryptography hash hashing password security",

    packages=find_packages(),

    project_urls={
        "Documentation": "TODO",
        "Source Code": "https://github.com/bcmyers/a2",
    },

    rust_extensions=[RustExtension(
        'a2py.a2',
        'Cargo.toml',
        binding=Binding.NoBinding,
        debug=False,
        native=True,
        rust_version=">=1.26.0",
    )],

    zip_safe=False
)
