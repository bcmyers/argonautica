import unittest

from cffi import FFI

from argonautica import Hasher, Verifier


class TestHash1(unittest.TestCase):
    def setUp(self):
        self.password = "P@ssw0rd"

    def test_hash1(self):
        hasher = Hasher()
        encoded = hasher.hash(self.password)

        verifier = Verifier()
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertTrue(is_valid)

    def test_hash2(self):
        hasher = Hasher(additional_data="additional data")
        encoded = hasher.hash(self.password)

        verifier = Verifier(additional_data="additional data")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertTrue(is_valid)

        verifier = Verifier()
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

    def test_hash3(self):
        hasher = Hasher(secret_key="secret key")
        encoded = hasher.hash(self.password)

        # TODO: Failing
        verifier = Verifier(secret_key="secret key")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertTrue(is_valid)

        verifier = Verifier()
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

    def test_hash4(self):
        hasher = Hasher(additional_data="additional data", secret_key="secret key")
        encoded = hasher.hash(self.password)

        # TODO: Failing
        verifier = Verifier(additional_data="additional data", secret_key="secret key")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertTrue(is_valid)

        verifier = Verifier()
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

        verifier = Verifier(additional_data="additional data")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

        verifier = Verifier(secret_key="secret key")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

    def test_overflow(self):
        hasher = Hasher(hash_length=0x1000000000)
        try:
            encoded = hasher.hash(self.password)
        except OverflowError:
            pass


if __name__ == '__main__':
    unittest.main()
