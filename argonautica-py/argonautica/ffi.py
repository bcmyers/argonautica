from glob import glob
import os
import site

from cffi import FFI

ffi = FFI()

header_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "argonautica.h")
with open(header_path, 'r') as f:
    contents = f.read()
    ffi.cdef(contents)

try:
    site_dir = site.getsitepackages()[0]
    rust_glob = os.path.join(site_dir, "argonautica", "rust.*")
    rust_path = glob(rust_glob)[0]

except:
    # TODO: Development only
    try:
        here = os.path.abspath(os.path.dirname(__file__))
        rust_glob = os.path.join(here, "rust.*")
        rust_path = glob(rust_glob)[0]
    except:
        raise Exception("Error")

rust = ffi.dlopen(rust_path)
