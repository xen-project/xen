import unittest

from xen.xend import uuid


class test_uuid(unittest.TestCase):

    def testStringRoundtrip(self):
        def t(inp):
            self.assertEqual(uuid.fromString(uuid.toString(inp)), inp)

        t(uuid.create())
        t(uuid.create())
        t(uuid.create())
        t(uuid.create())
        t(uuid.create())


    def testToFromString(self):
        def t(inp, expected):
            self.assertEqual(uuid.toString(inp), expected)
            self.assertEqual(uuid.fromString(expected), inp)

        t([0 for _ in range(0, 16)], "00000000-0000-0000-0000-000000000000")
        t([185, 158, 125, 206, 250, 178, 125, 57, 2, 6, 162, 74, 178, 236,
           196, 5], "b99e7dce-fab2-7d39-0206-a24ab2ecc405")


def test_suite():
    return unittest.makeSuite(test_uuid)
