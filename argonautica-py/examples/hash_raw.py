from argonautica.utils import decode, HashRaw

hash = '$argon2id$v=19$m=4096,t=128,p=2$c29tZXNhbHQ$WwD2/wGGTuw7u4BW8sLM0Q'

# Create a `HashRaw` using the `decode` function
hash_raw = decode(hash)

# Pull out the raw parameters
iterations = hash_raw.iterations     # 128
lanes = hash_raw.lanes               # 2
memory_size = hash_raw.memory_size   # 4096
variant = hash_raw.variant           # Variant.Argon2id
version = hash_raw.version           # Version._0x13

# Pull out the raw bytes
raw_hash_bytes = hash_raw.raw_hash_bytes  # b'[\x00\xf6\xff\x01\x86N\xec;\xbb\x80V\xf2\xc2\xcc\xd1'
raw_salt_bytes = hash_raw.raw_salt_bytes  # b'somesalt'

# Turn a `HashRaw` back into a string-encoded hash using the `encode` method
hash2 = hash_raw.encode()
assert(hash == hash2)
