import os
import os.path
import tempfile
import unittest

import xen.xend.XendOptions

xen.xend.XendOptions.XendOptions.config_default = '/dev/null'

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
        os.close(fd)
        self.t('-f %s kernel=/mykernel display=fakedisplay '
               'macaddr=ab:cd:ef:ed' % fname,
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
                 'nics'      : -1,
                 'vncunused' : 1,
                 'xauthority': xen.xm.create.get_xauthority(),
                 })


    def testConfigFile(self):
        (fd, fname) = tempfile.mkstemp()
        try:
            os.write(fd,
                     '''
kernel = "/boot/vmlinuz-xenU-smp"
memory = 768
name = "dom1"
vcpus = 4
disk = ['phy:/dev/virt-blkdev-backend/dom1,sda1,w',
'phy:/dev/virt-blkdev-backend/usr,sda2,r']
root = "/dev/sda1 ro"
extra = " profile=1 GATEWAY=10.0.1.254 NETMASK=255.255.0.0 IPADDR=10.0.134.1 HOSTNAME=dom1"
on_poweroff = 'destroy'
on_reboot   = 'destroy'
on_crash    = 'destroy'
                     ''')
        finally:
            os.close(fd)

        self.t('-f %s display=fakedisplay' % fname,
               { 'kernel'      : '/boot/vmlinuz-xenU-smp',
                 'memory'      : 768,
                 'name'        : 'dom1',
                 'vcpus'       : 4,
                 'nics'        : -1,
                 'root'        : '/dev/sda1 ro',
                 'extra'       : ' profile=1 GATEWAY=10.0.1.254 NETMASK=255.255.0.0 IPADDR=10.0.134.1 HOSTNAME=dom1',
                 'on_poweroff' : 'destroy',
                 'on_reboot'   : 'destroy',
                 'on_crash'    : 'destroy',
                 'disk'        : [['phy:/dev/virt-blkdev-backend/dom1',
                                   'sda1', 'w', None],
                                  ['phy:/dev/virt-blkdev-backend/usr',
                                   'sda2', 'r', None]],

                 'xm_file'     : fname,
                 'defconfig'   : fname,
                 'display'     : 'fakedisplay',

                 'boot'        : 'c',
                 'dhcp'        : 'off',
                 'interface'   : 'eth0',
                 'path'        : '.:/etc/xen',
                 'builder'     : 'linux',

                 'vncunused'   : 1,
                 'xauthority'  : xen.xm.create.get_xauthority(),
               })


    def testConfigFileAndCommandLine(self):
        (fd, fname) = tempfile.mkstemp()
        try:
            os.write(fd,
                     '''
name       = "testname"
memory     = 256
kernel     = "/mykernel"
maxmem     = 1024
cpu        = 2
cpu_weight = 0.75
                     ''')
        finally:
            os.close(fd)

        self.t('-f %s display=fakedisplay macaddr=ab:cd:ef:ed' %
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
                 'cpu_weight' : 0.75,
                 'vcpus'      : 1,
                 'boot'       : 'c',
                 'dhcp'       : 'off',
                 'interface'  : 'eth0',
                 'path'       : '.:/etc/xen',
                 'builder'    : 'linux',
                 'nics'       : -1,

                 'vncunused'   : 1,
                 'xauthority' : xen.xm.create.get_xauthority(),
                 })
            

    def testHVMConfigFile(self):
        (fd, fname) = tempfile.mkstemp()
        try:
            os.write(fd,
                     '''
kernel = "/usr/lib/xen/boot/hvmloader"
builder='hvm'
memory = 128
name = "ExampleHVMDomain"
vcpus=1
vif = [ 'type=ioemu, bridge=xenbr0' ]
disk = [ 'file:/var/images/min-el3-i386.img,ioemu:hda,w' ]
device_model = '/usr/lib/xen/bin/qemu-dm'
sdl=0
vnc=1
vncviewer=1
ne2000=0
                     ''')
        finally:
            os.close(fd)

        self.t('-f %s display=fakedisplay' % fname,
               { 'kernel'      : '/usr/lib/xen/boot/hvmloader',
                 'builder'     : 'hvm',
                 'memory'      : 128,
                 'name'        : 'ExampleHVMDomain',
                 'vcpus'       : 1,
                 'nics'        : -1,
                 'vif'         : ['type=ioemu, bridge=xenbr0'],
                 'disk'        : [['file:/var/images/min-el3-i386.img',
                                   'ioemu:hda', 'w', None]],
                 'device_model': '/usr/lib/xen/bin/qemu-dm',

                 'extra'       : ('VNC_VIEWER=%s:%d ' %
                                  (xen.xm.create.get_host_addr(),
                                   xen.xm.create.VNC_BASE_PORT +
                                   xen.xm.create.choose_vnc_display())),
                 'vnc'         : 1,
                 'vncunused'   : 1,
                 'vncviewer'   : 1,

                 'xm_file'     : fname,
                 'defconfig'   : fname,
                 'display'     : 'fakedisplay',

                 'boot'        : 'c',
                 'dhcp'        : 'off',
                 'interface'   : 'eth0',
                 'path'        : '.:/etc/xen',

                 'xauthority'  : xen.xm.create.get_xauthority(),
               })


def test_suite():
    return unittest.makeSuite(test_create)
