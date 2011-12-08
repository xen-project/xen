# Copyright (c) 2005, XenSource Ltd.
import string, re, os

from xen.xend.server.blkif import BlkifController
from xen.xend.XendLogging import log
from xen.util.xpopen import xPopen3

phantomDev = 0;
phantomId = 0;

blktap1_disk_types = [
    'aio',
    'sync',
    'vmdk',
    'ram',
    'qcow',
    'qcow2',
    'ioemu',
    ]

blktap2_disk_types = [
    'aio',
    'ram',
    'qcow',
    'vhd',
    'remus',
    ]

blktap_disk_types = blktap1_disk_types + blktap2_disk_types

def doexec(args, inputtext=None):
    """Execute a subprocess, then return its return code, stdout and stderr"""
    proc = xPopen3(args, True)
    if inputtext != None:
        proc.tochild.write(inputtext)
    stdout = proc.fromchild
    stderr = proc.childerr
    rc = proc.wait()
    return (rc,stdout,stderr)

# blktap1 device controller
class BlktapController(BlkifController):
    def __init__(self, vm):
        BlkifController.__init__(self, vm)
        
    def frontendRoot(self):
        """@see DevController#frontendRoot"""
        
        return "%s/device/vbd" % self.vm.getDomainPath()

    def getDeviceDetails(self, config):
        (devid, back, front) = BlkifController.getDeviceDetails(self, config)

        phantomDevid = 0
        wrapped = False

        try:
            imagetype = self.vm.info['image']['type']
        except:
            imagetype = ""

        if imagetype == 'hvm':
            tdevname = back['dev']
            index = ['c', 'd', 'e', 'f', 'g', 'h', 'i', \
                     'j', 'l', 'm', 'n', 'o', 'p']
            while True:
                global phantomDev
                global phantomId
                import os, stat

                phantomId = phantomId + 1
                if phantomId == 16:
                    if index[phantomDev] == index[-1]:
                        if wrapped:
                            raise VmError(" No loopback block \
                                       devices are available. ")
                        wrapped = True
                        phantomDev = 0
                    else:
                        phantomDev = phantomDev + 1
                    phantomId = 1
                devname = 'xvd%s%d' % (index[phantomDev], phantomId)
                try:
                    info = os.stat('/dev/%s' % devname)
                except:
                    break

            vbd = { 'mode': 'w', 'device': devname }
            fn = 'tap:%s' % back['params']

            # recurse ... by creating the vbd, then fallthrough
            # and finish creating the original device

            from xen.xend import XendDomain
            dom0 = XendDomain.instance().privilegedDomain()
            phantomDevid = dom0.create_phantom_vbd_with_vdi(vbd, fn)
            # we need to wait for this device at a higher level
            # the vbd that gets created will have a link to us
            # and will let them do it there

        # add a hook to point to the phantom device,
        # root path is always the same (dom0 tap)
        if phantomDevid != 0:
            front['phantom_vbd'] = '/local/domain/0/backend/tap/0/%s' \
                                   % str(phantomDevid)

        return (devid, back, front)

class Blktap2Controller(BlktapController):
    def __init__(self, vm):
        BlktapController.__init__(self, vm)

    def backendPath(self, backdom, devid):
        if self.deviceClass == 'tap2':
            deviceClass = 'vbd'
        else:
            deviceClass = 'tap'
        return "%s/backend/%s/%s/%d" % (backdom.getDomainPath(),
                                        deviceClass,
                                        self.vm.getDomid(), devid)

    def getDeviceDetails(self, config):

        (devid, back, front) = BlktapController.getDeviceDetails(self, config)
        if self.deviceClass == 'tap2':
        # since blktap2 uses blkback as a backend the 'params' feild contains
        # the path to the blktap2 device (/dev/xen/blktap-2/tapdev*). As well,
        # we need to store the params used to create the blktap2 device
        # (tap:tapdisk:<driver>:/<image-path>)
            tapdisk_uname = config.get('tapdisk_uname', '')
            (_, tapdisk_params) = string.split(tapdisk_uname, ':', 1)
            back['tapdisk-params'] = tapdisk_params 
            
        return (devid, back, front)

    def getDeviceConfiguration(self, devid, transaction = None):

        # this is a blktap2 device, so we need to overwrite the 'params' feild
        # with the actual blktap2 parameters. (the vbd parameters are of little
        # use to us)
        config = BlktapController.getDeviceConfiguration(self, devid, transaction)
        if transaction is None:
            tapdisk_params = self.readBackend(devid, 'tapdisk-params')
        else:
            tapdisk_params = self.readBackendTxn(transaction, devid, 'tapdisk-params')
        if tapdisk_params:
            config['uname'] = 'tap:' + tapdisk_params

        return config


    def createDevice(self, config):

        uname = config.get('uname', '')
        try:
            (typ, subtyp, params, file) = string.split(uname, ':', 3)
            if subtyp not in ('tapdisk', 'ioemu'):
                raise ValueError('invalid subtype')
        except:
            (typ, params, file) = string.split(uname, ':', 2)
            subtyp = 'tapdisk'

        if typ in ('tap'):
            if subtyp in ('tapdisk', 'ioemu'):
                if params not in blktap2_disk_types or \
                        TapdiskController.check():
                    # pass this device off to BlktapController
                    log.warn('WARNING: using deprecated blktap module')
                    self.deviceClass = 'tap'
                    devid = BlktapController.createDevice(self, config)
                    self.deviceClass = 'tap2'
                    return devid

        device = TapdiskController.create(params, file)

        # modify the configutration to create a blkback for the underlying
        # blktap2 device. Note: we need to preserve the original tapdisk uname
        # (it is used during save/restore and for managed domains).
        config.update({'tapdisk_uname' : uname})
        config.update({'uname' : 'phy:' + device.rstrip()})

        devid = BlkifController.createDevice(self, config)
        config.update({'uname' : uname})
        config.pop('tapdisk_uname')
        return devid

    # This function is called from a thread when the
    # domain is detached from the disk.
    def finishDeviceCleanup(self, backpath, path):
        """Perform any device specific cleanup

        @backpath backend xenstore path.
        @path frontend device path

        """

        #Figure out what we're going to wait on.
        self.waitForBackend_destroy(backpath)
        TapdiskController.destroy(path)

class TapdiskException(Exception):
    pass

class TapdiskController(object):
    '''class which encapsulates all tapdisk control operations'''

    TAP_CTL = 'tap-ctl'
    TAP_DEV = '/dev/xen/blktap-2/tapdev'

    class Tapdisk(object):
        def __init__(self, pid=None, minor=-1, state=None,
                     dtype='', image=None, device=None):
            self.pid = pid
            self.minor = minor
            self.state = state
            self.dtype = dtype
            self.image = image
            self.device = device

        def __str__(self):
            return 'image=%s pid=%s minor=%s state=%s type=%s device=%s' \
                % (self.image, self.pid, self.minor, self.state, self.dtype,
                   self.device)

    @staticmethod
    def exc(*args):
        rc, stdout, stderr = doexec([TapdiskController.TAP_CTL] + list(args))
        out, err = stdout.read().strip(), stderr.read().strip()
        stdout.close()
        stderr.close()
        if rc:
            raise TapdiskException('%s failed (%s %s %s)' % \
                                       (args, rc, out, err))
        return out

    @staticmethod
    def check():
        try:
            TapdiskController.exc('check')
            return 0
        except Exception, e:
            log.warn("tapdisk2 check failed: %s" % e)
            return -1

    @staticmethod
    def list():
        tapdisks = []

        _list = TapdiskController.exc('list')
        if not _list: return []

        for line in _list.splitlines():
            tapdisk = TapdiskController.Tapdisk()

            # Since 'tap-ctl list' does not escape blanks in the path, hard-code the current format using 4 pairs to prevent splitting the path
            for pair in line.split(None, 3):
                key, value = pair.split('=', 1)
                if key == 'pid':
                    tapdisk.pid = value
                elif key == 'minor':
                    tapdisk.minor = int(value)
                    if tapdisk.minor >= 0:
                        tapdisk.device = '%s%s' % \
                            (TapdiskController.TAP_DEV, tapdisk.minor)
                elif key == 'state':
                    tapdisk.state = value
                elif key == 'args' and value.find(':') != -1:
                    tapdisk.dtype, tapdisk.image = value.split(':', 1)

            tapdisks.append(tapdisk)

        return tapdisks

    @staticmethod
    def fromDevice(device):
        if device.startswith(TapdiskController.TAP_DEV):
            minor = os.minor(os.stat(device).st_rdev)
            tapdisks = filter(lambda x: x.minor == minor,
                              TapdiskController.list())
            if len(tapdisks) == 1:
                return tapdisks[0]
        return None

    @staticmethod
    def create(dtype, image):
        return TapdiskController.exc('create', '-a%s:%s' % (dtype, image))

    @staticmethod
    def destroy(device):
        tapdisk = TapdiskController.fromDevice(device)
        if tapdisk:
            if tapdisk.pid:
                TapdiskController.exc('destroy',
                                      '-p%s' % tapdisk.pid,
                                      '-m%s' % tapdisk.minor)
            else:
                TapdiskController.exc('free', '-m%s' % tapdisk.minor)

    @staticmethod
    def pause(device):
        tapdisk = TapdiskController.fromDevice(device)
        if tapdisk and tapdisk.pid:
            TapdiskController.exc('pause',
                                  '-p%s' % tapdisk.pid,
                                  '-m%s' % tapdisk.minor)

    @staticmethod
    def unpause(device):
        tapdisk = TapdiskController.fromDevice(device)
        if tapdisk and tapdisk.pid:
            TapdiskController.exc('unpause',
                                  '-p%s' % tapdisk.pid,
                                  '-m%s' % tapdisk.minor)
