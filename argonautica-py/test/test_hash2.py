import unittest

from argonautica import Hasher


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
            hash_length=32,
            iterations=3,
            lanes=4,
            memory_size=32,
            threads=4,
        )

    def test_hash_0x10_2d(self):
        self.hasher.variant = "argon2d"
        self.hasher.version = 16
        b = self.hasher.hash_raw(self.password)
        expected = bytes([
            0x96, 0xa9, 0xd4, 0xe5, 0xa1, 0x73, 0x40, 0x92, 0xc8, 0x5e, 0x29, 0xf4, 0x10, 0xa4,
            0x59, 0x14, 0xa5, 0xdd, 0x1f, 0x5c, 0xbf, 0x08, 0xb2, 0x67, 0x0d, 0xa6, 0x8a, 0x02,
            0x85, 0xab, 0xf3, 0x2b,
        ])
        self.assertEqual(b, expected)


if __name__ == '__main__':
    unittest.main()
