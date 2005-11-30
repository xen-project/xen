import unittest

import xen.xend.sxp


class test_sxp(unittest.TestCase):

    def testAllFromString(self):
        def t(inp, expected):
            self.assertEqual(xen.xend.sxp.all_from_string(inp), expected)

        t('String',           ['String'])
        t('(String Thing)',   [['String', 'Thing']])
        t('(String) (Thing)', [['String'], ['Thing']])


def test_suite():
    return unittest.makeSuite(test_sxp)
