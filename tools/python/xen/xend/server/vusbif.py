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
# Copyright (C) 2009, FUJITSU LABORATORIES LTD.
#  Author: Noboru Iwamatsu <n_iwamatsu@jp.fujitsu.com>
#============================================================================

"""Support for virtual USB host controllers.
"""
import re
import string

import types

from xen.xend import sxp
from xen.xend.XendError import VmError
from xen.xend.XendLogging import log

from xen.xend.server.DevController import DevController
from xen.xend.server.DevConstants import xenbusState
from xen.xend.xenstore.xstransact import xstransact

from xen.util import vusb_util

class VUSBController(DevController):
    """VUSB Devices.
    """
    def __init__(self, vm):
        """Create a VUSB Devices.
        """
        DevController.__init__(self, vm)

    def sxprs(self):
        """@see DevController.sxprs"""
        devslist = []
        for devid in self.deviceIDs():
            vusb_config = []
            backid = self.readFrontend(devid, 'backend-id')
            vusb_config.append(['backend-id', backid])
            state = self.readFrontend(devid, 'state')
            vusb_config.append(['state', state])
            backpath = self.readFrontend(devid, 'backend')
            vusb_config.append(['backend', backpath]) 
            usbver = self.readBackend(devid, 'usb-ver')
            vusb_config.append(['usb-ver', usbver])
            numports = self.readBackend(devid, 'num-ports') 
            vusb_config.append(['num-ports', numports])             

            portpath = "port/"
            ports = ['port']
            for i in range(1, int(numports) + 1):
                bus = self.readBackend(devid, portpath + '%i' % i)
                ports.append(['%i' % i, str(bus)])

            vusb_config.append(ports)             
            devslist.append([devid, vusb_config])

        return devslist

    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""
        back = {}
        devid = self.allocateDeviceID()
        usbver = config.get('usb-ver', '')
        numports = config.get('num-ports', '')
        back['usb-ver'] = str(usbver)
        back['num-ports'] = str(numports)
        for i in range(1, int(numports) + 1):
            back['port/%i' % i] = config['port-%i' % i]
        return (devid, back, {})

    def getDeviceConfiguration(self, devid, transaction = None):
        """@see DevController.configuration"""
        config = DevController.getDeviceConfiguration(self, devid, transaction)
        if transaction is None:
            hcinfo = self.readBackend(devid, 'usb-ver', 'num-ports')
        else:
            hcinfo = self.readBackendTxn(transaction, devid,
                                          'usb-ver', 'num-ports')
        (usbver, numports) = hcinfo
        config['usb-ver'] = str(usbver)
        config['num-ports'] = str(numports)
        for i in range(1, int(numports) + 1):
            if transaction is None:
                config['port-%i' % i] = self.readBackend(devid, 'port/%i' % i)
            else:
                config['port-%i' % i] = self.readBackendTxn(transaction, devid,
                                                             'port/%i' % i)
        return config

    def reconfigureDevice(self, devid, config):
        """@see DevController.reconfigureDevice"""
        cur_config = self.getDeviceConfiguration(devid)

        numports = cur_config['num-ports']
        for i in range(1, int(numports) + 1):
            if config.has_key('port-%i' % i):
                if not config['port-%i' % i] == cur_config['port-%i' % i]:
                    if not cur_config['port-%i' % i] == "":
                        vusb_util.unbind_usb_device(cur_config['port-%i' % i])
                    self.writeBackend(devid, 'port/%i' % i, 
                                      config['port-%i' % i])
                    if not config['port-%i' % i] == "":
                        vusb_util.bind_usb_device(config['port-%i' % i])

        return self.readBackend(devid, 'uuid')

    def waitForBackend(self, devid):
        return (0, "ok - no hotplug")

    def waitForBackend_destroy(self, backpath):
        return 0

    def migrate(self, deviceConfig, network, dst, step, domName):
        raise VmError('Migration not permitted with assigned USB device.')
