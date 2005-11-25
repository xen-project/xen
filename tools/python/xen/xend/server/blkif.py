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
# Copyright (C) 2005 XenSource Ltd
#============================================================================


import re
import string

from xen.util import blkif
from xen.xend import sxp
from xen.xend.XendError import VmError

from xen.xend.server.DevController import DevController


class BlkifController(DevController):
    """Block device interface controller. Handles all block devices
    for a domain.
    """
    
    def __init__(self, vm):
        """Create a block device controller.
        """
        DevController.__init__(self, vm)


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""
        
        dev = sxp.child_value(config, 'dev')
        if re.match('^ioemu:', dev):
            return (None,{},{})

        devid = blkif.blkdev_name_to_number(dev)

        (typ, params) = string.split(sxp.child_value(config, 'uname'), ':', 1)
        back = { 'dev' : dev,
                 'type' : typ,
                 'params' : params
                 }

        if 'r' == sxp.child_value(config, 'mode', 'r'):
            back['read-only'] = ""  # existence indicates read-only

        front = { 'virtual-device' : "%i" % devid }

        return (devid, back, front)


    def configuration(self, devid):
        """@see DevController.configuration"""

        result = DevController.configuration(self, devid)

        (dev, typ, params, ro) = self.readBackend(devid,
                                                  'dev', 'type', 'params',
                                                  'read-only')

        if dev:
            result.append(['dev', dev])
        if typ and params:
            result.append(['uname', typ + ":" + params])
        if ro:
            result.append(['mode', 'r'])
        else:
            result.append(['mode', 'w'])

        return result


    def destroyDevice(self, devid):
        """@see DevController.destroyDevice"""

        # If we are given a device name, then look up the device ID from it,
        # and destroy that ID instead.  If what we are given is an integer,
        # then assume it's a device ID and pass it straight through to our
        # superclass's method.

        try:
            DevController.destroyDevice(self, int(devid))
        except ValueError:
            devid_end = type(devid) is str and devid.split('/')[-1] or None

            for i in self.deviceIDs():
                d = self.readBackend(i, 'dev')
                if d == devid or (devid_end and d == devid_end):
                    DevController.destroyDevice(self, i)
                    return
            raise VmError("Device %s not connected" % devid)
