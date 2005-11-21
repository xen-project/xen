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


import types

import xen.lowlevel.xc;

from xen.xend import sxp
from xen.xend.XendError import VmError

from xen.xend.server.DevController import DevController


xc = xen.lowlevel.xc.xc()


def parse_pci(val):
    """Parse a pci field.
    """
    if isinstance(val, types.StringType):
        radix = 10
        if val.startswith('0x') or val.startswith('0X'):
            radix = 16
        v = int(val, radix)
    else:
        v = val
    return v


class PciController(DevController):

    def __init__(self, vm):
        DevController.__init__(self, vm)


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        def get_param(field):
            try:
                val = sxp.child_value(config, field)

                if not val:
                    raise VmError('pci: Missing %s config setting' % field)

                return parse_pci(val)
            except:
                raise VmError('pci: Invalid config setting %s: %s' %
                              (field, val))
        
        bus  = get_param('bus')
        dev  = get_param('dev')
        func = get_param('func')

        rc = xc.physdev_pci_access_modify(dom    = self.getDomid(),
                                          bus    = bus,
                                          dev    = dev,
                                          func   = func,
                                          enable = True)
        if rc < 0:
            #todo non-fatal
            raise VmError(
                'pci: Failed to configure device: bus=%s dev=%s func=%s' %
                (bus, dev, func))

        return (dev, {}, {})
