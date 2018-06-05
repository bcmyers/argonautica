from argonautica import Hasher, Verifier

if __name__ == "__main__":
    password = "P@ssw0rd"

    hasher = Hasher(hash_length=16)
    encoded = hasher.hash(password)
    print(encoded)

    verifier = Verifier()
    is_valid = verifier.verify(password, encoded)
    print(is_valid)
