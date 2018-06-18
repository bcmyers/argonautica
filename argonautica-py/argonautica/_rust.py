# auto-generated file
__all__ = ['lib', 'ffi']

import os
from argonautica._rust__ffi import ffi

lib = ffi.dlopen(os.path.join(os.path.dirname(__file__), '_rust__lib.so'), 130)
del os
