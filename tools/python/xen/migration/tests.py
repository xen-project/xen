#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Unit tests for migration v2 streams
"""

import unittest

from struct import calcsize

from xen.migration import libxc, libxl

class TestLibxc(unittest.TestCase):

    def test_format_sizes(self):

        for fmt, sz in ( (libxc.IHDR_FORMAT, 24),
                         (libxc.DHDR_FORMAT, 16),
                         (libxc.RH_FORMAT, 8),

                         (libxc.PAGE_DATA_FORMAT, 8),
                         (libxc.X86_PV_INFO_FORMAT, 8),
                         (libxc.X86_PV_P2M_FRAMES_FORMAT, 8),
                         (libxc.X86_PV_VCPU_HDR_FORMAT, 8),
                         (libxc.TSC_INFO_FORMAT, 24),
                         (libxc.HVM_PARAMS_ENTRY_FORMAT, 16),
                         (libxc.HVM_PARAMS_FORMAT, 8),
                         ):
            self.assertEqual(calcsize(fmt), sz)


class TestLibxl(unittest.TestCase):

    def test_format_sizes(self):

        for fmt, sz in ( (libxl.HDR_FORMAT, 16),
                         (libxl.RH_FORMAT, 8),

                         (libxl.EMULATOR_HEADER_FORMAT, 8),
                         ):
            self.assertEqual(calcsize(fmt), sz)


def test_suite():
    suite = unittest.TestSuite()

    suite.addTest(unittest.makeSuite(TestLibxc))
    suite.addTest(unittest.makeSuite(TestLibxl))

    return suite

if __name__ == "__main__":
    unittest.main()
