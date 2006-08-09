import unittest

import xen.xend.sxp


class test_sxp(unittest.TestCase):

    def testAllFromString(self):
        def t(inp, expected):
            self.assertEqual(xen.xend.sxp.all_from_string(inp), expected)

        t('String',           ['String'])
        t('(String Thing)',   [['String', 'Thing']])
        t('(String) (Thing)', [['String'], ['Thing']])


    def testParseFixed(self):
        fin = file('../xen/xend/tests/xend-config.sxp', 'rb')
        try:
            config = xen.xend.sxp.parse(fin)
            self.assertEqual(
                xen.xend.sxp.child_value(
                config,
                'xend-relocation-hosts-allow'),
                '^localhost$ ^localhost\\.localdomain$')
        finally:
            fin.close()


    def testParseConfigExample(self):
        fin = file('../../examples/xend-config.sxp', 'rb')
        try:
            config = xen.xend.sxp.parse(fin)
        finally:
            fin.close()


def test_suite():
    return unittest.makeSuite(test_sxp)
