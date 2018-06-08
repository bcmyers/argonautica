from argonautica import Hasher, Verifier

if __name__ == "__main__":
    hasher = Hasher()
    encoded = hasher.hash("P@ssw0rd")
    print(encoded)
    # verifier = Verifier(additional_data=b"1234567890")
    # is_valid = verifier.verify(hash=encoded, password="P@ssw0rd")
    # print(is_valid)
