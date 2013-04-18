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
# Copyright (C) 2005 Jody Belka
#============================================================================
# This code based on tools/python/xen/xend/server/iopif.py and modified
# to handle interrupts
#============================================================================


import types

import xen.lowlevel.xc

from xen.xend import sxp
from xen.xend.XendError import VmError

from xen.xend.server.DevController import DevController


xc = xen.lowlevel.xc.xc()


class IRQController(DevController):

    def __init__(self, vm):
        DevController.__init__(self, vm)

    valid_cfg = ['irq', 'uuid']

    def getDeviceConfiguration(self, devid, transaction = None):
        result = DevController.getDeviceConfiguration(self, devid, transaction)
        if transaction is None:
            devinfo = self.readBackend(devid, *self.valid_cfg)
        else:
            devinfo = self.readBackendTxn(transaction, devid, *self.valid_cfg)
        config = dict(zip(self.valid_cfg, devinfo))
        config = dict([(key, val) for key, val in config.items()
                       if val != None])
        return config

    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        def get_param(field):
            try:
                val = config.get(field)

                if not val:
                    raise VmError('irq: Missing %s config setting' % field)

                if isinstance(val, types.StringType):
                    return int(val,10)
                    radix = 10
                else:
                    return val
            except:
                raise VmError('irq: Invalid config setting %s: %s' %
                              (field, val))
       
        pirq = get_param('irq')

        rc = xc.physdev_map_pirq(domid = self.getDomid(),
                                 index = pirq,
                                 pirq  = pirq)
        if rc < 0:
            raise VmError('irq: Failed to map irq %x' % (pirq))

        rc = xc.domain_irq_permission(domid        = self.getDomid(),
                                      pirq         = pirq,
                                      allow_access = True)

        if rc < 0:
            #todo non-fatal
            raise VmError(
                'irq: Failed to configure irq: %d' % (pirq))
        back = dict([(k, config[k]) for k in self.valid_cfg if k in config])
        return (self.allocateDeviceID(), back, {})

    def waitForDevice(self, devid):
        # don't wait for hotplug
        return
