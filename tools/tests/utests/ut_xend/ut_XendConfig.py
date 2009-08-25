#===========================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2009 flonatel GmbH & Co. KG
#============================================================================

import os
import unittest

# This does not work because of a cyclic import loop
#from xen.xend.XendConfig import XendConfig
import xen.xend.XendDomain

class XendConfigUnitTest(unittest.TestCase):

    def minimal_vmconf(self):
        return {
            'memory_dynamic_min': 64,
            'memory_dynamic_max': 128,
            'memory_static_max': 128,
            }

    def check_hf_01(self):
        "xend.XendConfig.handle_fileutils - PV_kernel/ramdisk not set"
        vmconf = self.minimal_vmconf()
        xc = xen.xend.XendConfig.XendConfig(xapi = vmconf)

        self.assert_(not xc.has_key('use_tmp_kernel'))
        self.assert_(not xc.has_key('use_tmp_ramdisk'))

    def check_hf_02(self):
        "xend.XendConfig.handle_fileutils - PV_kernel/ramdisk set to some path"
        vmconf = self.minimal_vmconf()
        vmconf['PV_kernel'] = '/some/where/under/the/rainbow-kernel'
        vmconf['PV_ramdisk'] = '/some/where/under/the/rainbow-ramdisk'
        xc = xen.xend.XendConfig.XendConfig(xapi = vmconf)

        self.assert_(xc.has_key('use_tmp_kernel'))
        self.assert_(xc.has_key('use_tmp_ramdisk'))

        self.assert_(not xc['use_tmp_kernel'])
        self.assert_(not xc['use_tmp_ramdisk'])

    def check_hf_03(self):
        "xend.XendConfig.handle_fileutils - PV_kernel/ramdisk using file: scheme"
        vmconf = self.minimal_vmconf()
        vmconf['PV_kernel'] = 'file:///some/where/under/the/rainbow-kernel'
        vmconf['PV_ramdisk'] = 'file:///some/where/under/the/rainbow-ramdisk'
        xc = xen.xend.XendConfig.XendConfig(xapi = vmconf)

        self.assert_(xc.has_key('use_tmp_kernel'))
        self.assert_(xc.has_key('use_tmp_ramdisk'))

        self.assert_(not xc['use_tmp_kernel'])
        self.assert_(not xc['use_tmp_ramdisk'])

        self.assert_('PV_kernel' in xc)
        self.assert_('PV_ramdisk' in xc)

        self.assertEqual("/some/where/under/the/rainbow-kernel",
                         xc['PV_kernel'])
        self.assertEqual("/some/where/under/the/rainbow-ramdisk",
                         xc['PV_ramdisk'])

    def check_hf_04(self):
        "xend.XendConfig.handle_fileutils - PV_kernel/ramdisk using data: scheme"
        vmconf = self.minimal_vmconf()
        vmconf['PV_kernel'] = 'data:application/octet-stream;base64,VGhpcyBpcyB0aGUga2VybmVsCg=='
        vmconf['PV_ramdisk'] = 'data:application/octet-stream;base64,TXkgZ3JlYXQgcmFtZGlzawo='
        xc = xen.xend.XendConfig.XendConfig(xapi = vmconf)

        self.assert_(xc.has_key('use_tmp_kernel'))
        self.assert_(xc.has_key('use_tmp_ramdisk'))

        self.assert_(xc['use_tmp_kernel'])
        self.assert_(xc['use_tmp_ramdisk'])

        self.assert_('PV_kernel' in xc)
        self.assert_('PV_ramdisk' in xc)

        self.assert_(xc['PV_kernel'].startswith(
                "/var/run/xend/boot/data_uri_file."))
        self.assert_(xc['PV_ramdisk'].startswith(
                "/var/run/xend/boot/data_uri_file."))

        f = file(xc['PV_kernel'])
        kc = f.read()
        f.close()

        f = file(xc['PV_ramdisk'])
        rc = f.read()
        f.close()

        os.unlink(xc['PV_kernel'])
        os.unlink(xc['PV_ramdisk'])

        self.assertEqual(kc, "This is the kernel\n")
        self.assertEqual(rc, "My great ramdisk\n")

def suite():
    return unittest.TestSuite(
        [unittest.makeSuite(XendConfigUnitTest, 'check_'),])

if __name__ == "__main__":
    testresult = unittest.TextTestRunner(verbosity=3).run(suite())

