#============================================================================
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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005, 2006 XenSource Inc.
#============================================================================

import re
import string
import os

from xen.util import blkif
import xen.util.xsm.xsm as security
from xen.xend.XendError import VmError
from xen.xend.server.DevController import DevController
from xen.util import xsconstants, auxbin

class BlkifController(DevController):
    """Block device interface controller. Handles all block devices
    for a domain.
    """

    def __init__(self, vm):
        """Create a block device controller.
        """
        DevController.__init__(self, vm)

    def _isValidProtocol(self, protocol):
        if protocol in ('phy', 'file', 'tap'):
            return True

        return os.access(auxbin.scripts_dir() + '/block-%s' % protocol, os.X_OK)


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""
        uname = config.get('uname', '')
        dev = config.get('dev', '')
        
        if 'ioemu:' in dev:
            (_, dev) = string.split(dev, ':', 1)
        try:
            (dev, dev_type) = string.split(dev, ':', 1)
        except ValueError:
            dev_type = "disk"

        if not uname:
            if dev_type == 'cdrom':
                (typ, params) = ("", "")
            else:
                raise VmError(
                    'Block device must have physical details specified')
        else:
            try:
                (typ, params) = string.split(uname, ':', 1)
                if not self._isValidProtocol(typ):
                    raise VmError('Block device type "%s" is invalid.' % typ)
            except ValueError:
                raise VmError(
                    'Block device must have physical details specified')

        mode = config.get('mode', 'r')
        if mode not in ('r', 'w', 'w!'):
            raise VmError('Invalid mode')

        back = {'dev'    : dev,
                'type'   : typ,
                'params' : params,
                'mode'   : mode,
                }

        uuid = config.get('uuid')
        if uuid:
            back['uuid'] = uuid

        bootable = config.get('bootable', None)
        if bootable != None:
            back['bootable'] = str(bootable)

        if security.on() == xsconstants.XS_POLICY_USE:
            self.do_access_control(config, uname)

        (device_path, devid) = blkif.blkdev_name_to_number(dev)
        if devid is None:
            raise VmError('Unable to find number for device (%s)' % (dev))

        front = { device_path : "%i" % devid,
                  'device-type' : dev_type
                }

        protocol = config.get('protocol')
        if protocol:
            front['protocol'] = protocol

        return (devid, back, front)

    def do_access_control(self, config, uname):
        (label, ssidref, policy) = \
                             security.get_res_security_details(uname)
        domain_label = self.vm.get_security_label()
        if domain_label:
            rc = security.res_security_check_xapi(label, ssidref, policy,
                                                  domain_label)
            if rc == 0:
                raise VmError("VM's access to block device '%s' denied" %
                              uname)
        else:
            from xen.util.acmpolicy import ACM_LABEL_UNLABELED
            if label != ACM_LABEL_UNLABELED:
                raise VmError("VM must have a security label to access "
                              "block device '%s'" % uname)

    def reconfigureDevice(self, _, config):
        """@see DevController.reconfigureDevice"""
        (devid, new_back, new_front) = self.getDeviceDetails(config)

        (dev, mode) = self.readBackend(devid, 'dev', 'mode')
        dev_type = self.readFrontend(devid, 'device-type')

        if (dev_type == 'cdrom' and new_front['device-type'] == 'cdrom' and
            dev == new_back['dev'] and mode == 'r'):
            # dummy device
            self.writeBackend(devid,
                              'type', new_back['type'],
                              'params', '')
            # new backend-device
            self.writeBackend(devid,
                              'type', new_back['type'],
                              'params', new_back['params'])
            return new_back.get('uuid')
        else:
            raise VmError('Refusing to reconfigure device %s:%d to %s' %
                          (self.deviceClass, devid, config))


    def getDeviceConfiguration(self, devid, transaction = None):
        """Returns the configuration of a device.

        @note: Similar to L{configuration} except it returns a dict.
        @return: dict
        """
        config = DevController.getDeviceConfiguration(self, devid, transaction)
        if transaction is None:
            devinfo = self.readBackend(devid, 'dev', 'type', 'params', 'mode',
                                       'uuid', 'bootable')
        else:
            devinfo = self.readBackendTxn(transaction, devid,
                                          'dev', 'type', 'params', 'mode', 'uuid',
                                          'bootable')
        dev, typ, params, mode, uuid, bootable = devinfo
        
        if dev:
            if transaction is None:
                dev_type = self.readFrontend(devid, 'device-type')
            else:
                dev_type = self.readFrontendTxn(transaction, devid, 'device-type')
            if dev_type:
                dev += ':' + dev_type
            config['dev'] = dev
        if typ and params:
            config['uname'] = typ +':' + params
        else:
            config['uname'] = None
        if mode:
            config['mode'] = mode
        if uuid:
            config['uuid'] = uuid
        if bootable != None:
            config['bootable'] = int(bootable)

        proto = self.readFrontend(devid, 'protocol')
        if proto:
            config['protocol'] = proto

        return config

    def destroyDevice(self, devid, force):
        """@see DevController.destroyDevice"""

        # vbd device IDs can be either string or integer.  Further, the
        # following string values are possible:
        #    - devicetype/deviceid (vbd/51728)
        #    - devicetype/devicename (/dev/xvdb)
        #    - devicename (xvdb)
        # Let our superclass handle integer or devicetype/deviceid forms.
        # If we are given a device name form, then look up the device ID
        # from it, and destroy that ID instead.
        try:
            DevController.destroyDevice(self, devid, force)
        except ValueError:
            dev = self.convertToDeviceNumber(devid)

            for i in self.deviceIDs():
                if i == dev:
                    DevController.destroyDevice(self, i, force)
                    return
            raise VmError("Device %s not connected" % devid)

    def convertToDeviceNumber(self, devid):
        try:
            dev = int(devid)
        except ValueError:
            if type(devid) is not str:
                raise VmError("devid %s is wrong type" % str(devid))
            try:
                dev = devid.split('/')[-1]
                dev = int(dev)
            except ValueError:
                (device_path, dev) = blkif.blkdev_name_to_number(dev)
        return dev
