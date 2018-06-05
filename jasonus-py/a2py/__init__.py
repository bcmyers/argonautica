from glob import glob
import os
import site

from a2py.ffi import ffi

try:
    site_dir = site.getsitepackages()[0]
    a2_glob = os.path.join(site_dir, "a2py", "a2.*")
    a2_path = glob(a2_glob)[0]
except:
    # TODO: Development only
    try:
        here = os.path.abspath(os.path.dirname(__file__))
        a2_glob = os.path.join(here, "a2.*")
        a2_path = glob(a2_glob)[0]
    except:
        raise Exception("Error")

a2 = ffi.dlopen(a2_path)

from a2py.hasher import hash, Hasher
from a2py.other import Backend, Variant, Version
from a2py.verifier import verify, Verifier
