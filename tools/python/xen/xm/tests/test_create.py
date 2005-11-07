import os
import os.path
import tempfile
import unittest

import xen.xend.XendRoot

xen.xend.XendRoot.XendRoot.config_default = '/dev/null'

import xen.xm.create


class test_create(unittest.TestCase):

    def assertEqualModuloNulls_(self, a, b):
        for k, v in a.iteritems():
            if v:
                self.failUnless(k in b, '%s not in b' % k)
                self.assertEqual(v, b[k])
            else:
                self.assert_(k not in b or not b[k], '%s in b' % k)


    def assertEqualModuloNulls(self, a, b):
        self.assertEqualModuloNulls_(a, b)
        self.assertEqualModuloNulls_(b, a)


    def t(self, args, expected):
        self.assertEqualModuloNulls(
            xen.xm.create.parseCommandLine(args.split(' '))[0].vals.__dict__,
            expected)


    def testCommandLine(self):
        (fd, fname) = tempfile.mkstemp()
        try:
            self.t('-f %s kernel=/mykernel display=fakedisplay '
                   'macaddr=ab:cd:ef:ed nics=0' % fname,
                   { 'name'      : os.path.basename(fname),
                     'xm_file'   : fname,
                     'defconfig' : fname,
                     'kernel'    : '/mykernel',
                     'display'   : 'fakedisplay',
                     'macaddr'   : 'ab:cd:ef:ed',
                     'memory'    : 128,
                     'vcpus'     : 1,
                     'boot'      : 'c',
                     'dhcp'      : 'off',
                     'interface' : 'eth0',
                     'path'      : '.:/etc/xen',
                     'builder'   : 'linux',
                     })
        finally:
            os.close(fd)


    def testConfigFileAndCommandLine(self):
        (fd, fname) = tempfile.mkstemp()
        os.write(fd,
                 '''
name       = "testname"
memory     = 256
ssidref    = 1
kernel     = "/mykernel"
maxmem     = 1024
cpu        = 2
cpu_weight = 0.75
                 ''')
        try:
            self.t('-f %s display=fakedisplay macaddr=ab:cd:ef:ed nics=0' %
              fname,
                   { 'name'       : 'testname',
                     'xm_file'    : fname,
                     'defconfig'  : fname,
                     'kernel'     : '/mykernel',
                     'display'    : 'fakedisplay',
                     'macaddr'    : 'ab:cd:ef:ed',
                     'memory'     : 256,
                     'maxmem'     : 1024,
                     'cpu'        : 2,
                     'ssidref'    : 1,
                     'cpu_weight' : 0.75,
                     'vcpus'      : 1,
                     'boot'       : 'c',
                     'dhcp'       : 'off',
                     'interface'  : 'eth0',
                     'path'       : '.:/etc/xen',
                     'builder'    : 'linux',
                     })
        finally:
            os.close(fd)
            

def test_suite():
    return unittest.makeSuite(test_create)
