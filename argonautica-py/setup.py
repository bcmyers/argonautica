import os
from setuptools import setup, find_packages
import subprocess
import sys

here = os.path.abspath(os.path.dirname(__file__))

try:
    from setuptools_rust import Binding, RustExtension
except ImportError:
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "setuptools-rust",
        ])
        os.execvp(sys.executable, [sys.executable] + sys.argv)
    except subprocess.CalledProcessError as e:
        print("Please install the setuptools-rust package")
        raise SystemExit(e.returncode)


def long_description() -> str:
    try:
        import pypandoc
        return pypandoc.convert('README.md', 'rst').replace("\r", "")
    except ImportError:
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "pypandoc",
            ])
            os.execvp(sys.executable, [sys.executable] + sys.argv)
            return pypandoc.convert('README.md', 'rst').replace("\r", "")
        except:
            return ""


setup(
    name="argonautica-py",
    version="0.1.0",

    author="Brian Myers",
    author_email="brian.carl.myers@gmail.com",
    description="Idiomatic Argon2 password hashing for Python but written in Rust",
    license="MIT/Apache-2.0",
    long_description=long_description(),
    url="https://github.com/bcmyers/argonautica",

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
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security :: Cryptography",
    ],

    include_package_data=True,
    install_requires=['cffi>=1.11.5'],

    keywords="argon2 argon2d argon2i argon2id crypto cryptography hash hashing password security",

    packages=find_packages(exclude=["docs.*", "tests.*"]),

    project_urls={
        "Documentation": "TODO",
        "Source Code": "https://github.com/bcmyers/argonautica",
    },

    rust_extensions=[RustExtension(
        'argonautica.rust',
        'Cargo.toml',
        binding=Binding.NoBinding,
        debug=False,
        native=True,
        rust_version=">=1.26.0",
    )],

    setup_requires=["setuptools-rust>=0.9.2"],

    zip_safe=False
)
