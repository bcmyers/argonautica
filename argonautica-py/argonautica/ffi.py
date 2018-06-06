from glob import glob
import os
import site

from cffi import FFI

ffi = FFI()

here = os.path.abspath(os.path.dirname(__file__))
header_path = os.path.join(here, "argonautica.h")
with open(header_path, 'r') as f:
    contents = f.read()
    ffi.cdef(contents)

try:
    site_dir = site.getsitepackages()[0]
    rust_glob = os.path.join(site_dir, "argonautica", "rust.*")
    rust_path = glob(rust_glob)[0]
except:
    raise Exception("Error")

rust = ffi.dlopen(rust_path)
