import unittest

from argonautica import Hasher
from argonautica.config import Variant, Version
from argonautica.utils import decode


class TestHash2(unittest.TestCase):
    def setUp(self):
        self.password = bytes([
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
        ])
        self.hasher = Hasher(
            additional_data=bytes([
                4, 4, 4, 4, 4, 4, 4, 4,
                4, 4, 4, 4
            ]),
            salt=bytes([
                2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2
            ]),
            secret_key=bytes([
                3, 3, 3, 3, 3, 3, 3, 3
            ]),
            hash_len=32,
            iterations=3,
            lanes=4,
            memory_size=32,
            threads=4,
        )

    def test_hash_0x10_2d(self):
        self.hasher.variant = Variant.Argon2d
        self.hasher.version = Version._0x10
        encoded = self.hasher.hash(password=self.password)
        decoded = decode(encoded)
        obtained = decoded.raw_hash_bytes
        expected = bytes([
            0x96, 0xa9, 0xd4, 0xe5, 0xa1, 0x73, 0x40, 0x92, 0xc8, 0x5e, 0x29, 0xf4, 0x10, 0xa4,
            0x59, 0x14, 0xa5, 0xdd, 0x1f, 0x5c, 0xbf, 0x08, 0xb2, 0x67, 0x0d, 0xa6, 0x8a, 0x02,
            0x85, 0xab, 0xf3, 0x2b,
        ])
        self.assertEqual(expected, obtained)

    def test_hash_0x10_2i(self):
        self.hasher.variant = Variant.Argon2i
        self.hasher.version = Version._0x10
        encoded = self.hasher.hash(password=self.password)
        decoded = decode(encoded)
        obtained = decoded.raw_hash_bytes
        expected = bytes([
            0x87, 0xae, 0xed, 0xd6, 0x51, 0x7a, 0xb8, 0x30, 0xcd, 0x97, 0x65, 0xcd, 0x82, 0x31,
            0xab, 0xb2, 0xe6, 0x47, 0xa5, 0xde, 0xe0, 0x8f, 0x7c, 0x05, 0xe0, 0x2f, 0xcb, 0x76,
            0x33, 0x35, 0xd0, 0xfd,
        ])
        self.assertEqual(expected, obtained)

    def test_hash_0x10_2id(self):
        self.hasher.variant = Variant.Argon2id
        self.hasher.version = Version._0x10
        encoded = self.hasher.hash(password=self.password)
        decoded = decode(encoded)
        obtained = decoded.raw_hash_bytes
        expected = bytes([
            0xb6, 0x46, 0x15, 0xf0, 0x77, 0x89, 0xb6, 0x6b, 0x64, 0x5b, 0x67, 0xee, 0x9e, 0xd3,
            0xb3, 0x77, 0xae, 0x35, 0x0b, 0x6b, 0xfc, 0xbb, 0x0f, 0xc9, 0x51, 0x41, 0xea, 0x8f,
            0x32, 0x26, 0x13, 0xc0,
        ])
        self.assertEqual(expected, obtained)

    def test_hash_0x13_2d(self):
        self.hasher.variant = Variant.Argon2d
        self.hasher.version = Version._0x13
        encoded = self.hasher.hash(password=self.password)
        decoded = decode(encoded)
        obtained = decoded.raw_hash_bytes
        expected = bytes([
            0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97, 0x53, 0x71, 0xd3, 0x09, 0x19, 0x73,
            0x42, 0x94, 0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1, 0xa1, 0x3a, 0x4d, 0xb9,
            0xfa, 0xbe, 0x4a, 0xcb,
        ])
        self.assertEqual(expected, obtained)

    def test_hash_0x13_2i(self):
        self.hasher.variant = Variant.Argon2i
        self.hasher.version = Version._0x13
        encoded = self.hasher.hash(password=self.password)
        decoded = decode(encoded)
        obtained = decoded.raw_hash_bytes
        expected = bytes([
            0xc8, 0x14, 0xd9, 0xd1, 0xdc, 0x7f, 0x37, 0xaa, 0x13, 0xf0, 0xd7, 0x7f, 0x24, 0x94,
            0xbd, 0xa1, 0xc8, 0xde, 0x6b, 0x01, 0x6d, 0xd3, 0x88, 0xd2, 0x99, 0x52, 0xa4, 0xc4,
            0x67, 0x2b, 0x6c, 0xe8,
        ])
        self.assertEqual(expected, obtained)

    def test_hash_0x13_2id(self):
        self.hasher.variant = Variant.Argon2id
        self.hasher.version = Version._0x13
        encoded = self.hasher.hash(password=self.password)
        decoded = decode(encoded)
        obtained = decoded.raw_hash_bytes
        expected = bytes([
            0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
            0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
            0x6b, 0x01, 0xe6, 0x59,
        ])
        self.assertEqual(expected, obtained)


if __name__ == '__main__':
    unittest.main()
