import os
from setuptools import setup
from setuptools_rust import Binding, RustExtension

here = os.path.abspath(os.path.dirname(__file__))


def long_description():
    with open(os.path.join(here, "argonautica-py", "README.md"), "r") as f:
        output = f.read()
    return output


setup(
    name="argonautica",
    version="0.1.5",

    author="Brian Myers",
    author_email="brian.carl.myers@gmail.com",
    description="Idiomatic Argon2 password hashing for Python",
    keywords="argon2 argon2d argon2i argon2id crypto cryptography hash hashing password security",
    license="MIT/Apache-2.0",
    long_description=long_description(),
    long_description_content_type="text/markdown",
    project_urls={
        "Docs": "https://github.com/bcmyers/argonautica/tree/master/argonautica-py",
        "Github": "https://github.com/bcmyers/argonautica/tree/master/argonautica-py",
    },
    url="https://github.com/bcmyers/argonautica/tree/master/argonautica-py",

    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Rust",
        "Topic :: Security :: Cryptography",
    ],

    install_requires=['cffi>=1.11.5', 'typing>=3.6.4'],
    packages=['argonautica', 'argonautica.core'],
    package_dir={'': 'argonautica-py'},
    package_data={'argonautica': ['*.h']},
    python_requires='>=3.4',
    rust_extensions=[RustExtension(
        'argonautica.rust',
        'argonautica-c/Cargo.toml',
        binding=Binding.NoBinding,
        debug=False,
        features=["simd"],
        native=True,
        rust_version=">=1.26.0",
    )],
    setup_requires=['setuptools-rust>=0.10.1'],
    zip_safe=False,
)
