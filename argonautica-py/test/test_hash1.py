import unittest

from cffi import FFI

from argonautica import Hasher, Verifier


class TestHash1(unittest.TestCase):
    def setUp(self):
        self.password = "P@ssw0rd"

    def test_hash1(self):
        hasher = Hasher(None)
        encoded = hasher.hash(self.password)

        verifier = Verifier(None)
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertTrue(is_valid)

        verifier = Verifier(None, additional_data="data")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

        verifier = Verifier("secret")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

        verifier = Verifier("secret", additional_data="data")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

    def test_hash2(self):
        hasher = Hasher(None, additional_data="data")
        encoded = hasher.hash(self.password)

        verifier = Verifier(None)
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

        verifier = Verifier(None, additional_data="data")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertTrue(is_valid)

        verifier = Verifier("secret")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

        verifier = Verifier("secret", additional_data="data")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

    def test_hash3(self):
        hasher = Hasher("secret")
        encoded = hasher.hash(self.password)

        verifier = Verifier(None)
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

        verifier = Verifier(None, additional_data="data")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

        verifier = Verifier("secret")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertTrue(is_valid)

        verifier = Verifier("secret", additional_data="data")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

    def test_hash4(self):
        hasher = Hasher("secret", additional_data="data")
        encoded = hasher.hash(self.password)

        verifier = Verifier(None)
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

        verifier = Verifier(None, additional_data="data")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

        verifier = Verifier("secret")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertFalse(is_valid)

        verifier = Verifier("secret", additional_data="data")
        is_valid = verifier.verify(password=self.password, hash=encoded)
        self.assertTrue(is_valid)

    def test_overflow(self):
        hasher = Hasher(None, hash_length=0x1000000000)
        try:
            encoded = hasher.hash(self.password)
        except OverflowError:
            pass


if __name__ == '__main__':
    unittest.main()
