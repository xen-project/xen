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

import unittest
import tempfile
import os

import xen.xend.image

class ImageHandlerUnitTests(unittest.TestCase):

    class ImageHandlerUnitTestsVirtualMachine:

        def __init__(self):
            self.info = {
                'name_label': 'ItsMyParty',
                }

        def storeVm(self, *args):
            pass

        def permissionsVm(self, *args):
            pass

        def getDomid(self):
            return 7

    # Sets up a vm_config with no bootloader.
    def vm_config_no_bootloader(self):
        return {
            'PV_kernel': 'value_of_PV_kernel',
            'PV_args': 'value_of_PV_args',
            'PV_ramdisk': 'value_of_PV_ramdisk',
            'platform': {},
            'console_refs': [],
            }

    def check_configure_01(self):
        # This retests the problem reported by Jun Koi on 24.07.2009
        # see http://lists.xensource.com/archives/html/xen-devel/2009-07/msg01006.html
        "ImageHandler - call configure with mostly empty vmConfig"

        vmConfig = self.vm_config_no_bootloader()
        vm = self.ImageHandlerUnitTestsVirtualMachine()
        ih = xen.xend.image.ImageHandler(vm, vmConfig)

        self.assertEqual(ih.use_tmp_kernel, False)
        self.assertEqual(ih.use_tmp_ramdisk, False)

    def check_configure_02(self):
        "ImageHandler - call configure with use_tmp_xxx set to false"

        vmConfig = self.vm_config_no_bootloader()
        vmConfig['use_tmp_kernel'] = False
        vmConfig['use_tmp_ramdisk'] = False
        vm = self.ImageHandlerUnitTestsVirtualMachine()
        ih = xen.xend.image.ImageHandler(vm, vmConfig)

        self.assertEqual(ih.use_tmp_kernel, False)
        self.assertEqual(ih.use_tmp_ramdisk, False)


    def check_configure_03(self):
        "ImageHandler - call configure with use_tmp_xxx set to true"

        vmConfig = self.vm_config_no_bootloader()
        vmConfig['use_tmp_kernel'] = True
        vmConfig['use_tmp_ramdisk'] = True
        vm = self.ImageHandlerUnitTestsVirtualMachine()
        ih = xen.xend.image.ImageHandler(vm, vmConfig)

        self.assertEqual(ih.use_tmp_kernel, True)
        self.assertEqual(ih.use_tmp_ramdisk, True)

    def cleanup_tmp_images_base(self, vmConfig):
        vm = self.ImageHandlerUnitTestsVirtualMachine()
        ih = xen.xend.image.ImageHandler(vm, vmConfig)

        k, ih.kernel = tempfile.mkstemp(
            prefix = "ImageHandler-cleanupTmpImages-k", dir = "/tmp")
        r, ih.ramdisk = tempfile.mkstemp(
            prefix = "ImageHandler-cleanupTmpImages-r", dir = "/tmp")

        ih.cleanupTmpImages()

        kres = os.path.exists(ih.kernel)
        rres = os.path.exists(ih.ramdisk)

        if not ih.use_tmp_kernel:
            os.unlink(ih.kernel)
        if not ih.use_tmp_ramdisk:
            os.unlink(ih.ramdisk)

        return kres, rres

    def check_cleanup_tmp_images_01(self):
        "ImageHandler - cleanupTmpImages with use_tmp_xxx unset"

        vmConfig = self.vm_config_no_bootloader()
        kres, rres = self.cleanup_tmp_images_base(vmConfig)

        self.assertEqual(kres, True)
        self.assertEqual(rres, True)

    def check_cleanup_tmp_images_02(self):
        "ImageHandler - cleanupTmpImages with use_tmp_xxx set to false"

        vmConfig = self.vm_config_no_bootloader()
        vmConfig['use_tmp_kernel'] = False
        vmConfig['use_tmp_ramdisk'] = False
        kres, rres = self.cleanup_tmp_images_base(vmConfig)

        self.assertEqual(kres, True)
        self.assertEqual(rres, True)

    def check_cleanup_tmp_images_03(self):
        "ImageHandler - cleanupTmpImages with use_tmp_xxx set to true"

        vmConfig = self.vm_config_no_bootloader()
        vmConfig['use_tmp_kernel'] = True
        vmConfig['use_tmp_ramdisk'] = True
        kres, rres = self.cleanup_tmp_images_base(vmConfig)

        self.assertEqual(kres, False)
        self.assertEqual(rres, False)

def suite():
    return unittest.TestSuite(
        [unittest.makeSuite(ImageHandlerUnitTests, 'check_'),])

if __name__ == "__main__":
    testresult = unittest.TextTestRunner(verbosity=3).run(suite())

