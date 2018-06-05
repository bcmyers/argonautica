from glob import glob
import os
import site

from cffi import FFI

ffi = FFI()
ffi.cdef("""
int argonautica_free(char *string);

const char *argonautica_hash(const uint8_t *additional_data,
                             size_t additional_data_len,
                             uint8_t *password,
                             size_t password_len,
                             const uint8_t *salt,
                             size_t salt_len,
                             const uint8_t *secret_key,
                             size_t secret_key_len,
                             uint32_t backend,
                             uint32_t hash_len,
                             uint32_t iterations,
                             uint32_t lanes,
                             uint32_t memory_size,
                             int password_clearing,
                             int secret_key_clearing,
                             uint32_t threads,
                             const char *variant,
                             uint32_t version,
                             int *error_code);

int argonautica_verify(const char *hash,
                       const uint8_t *password,
                       size_t password_len,
                       uint32_t backend);
""")

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
