from glob import glob
import os

from a2py.ffi import ffi

here = os.path.abspath(os.path.dirname(__file__))
try:
    a2_path = glob(os.path.join(here, "a2.*"))[0]
except:
    raise Exception("Error")

a2 = ffi.dlopen(a2_path)

from a2py.hasher import hash, Hasher
from a2py.other import Backend, Variant, Version
from a2py.verifier import verify, Verifier
