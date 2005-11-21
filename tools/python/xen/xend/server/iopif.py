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


import types

import xen.lowlevel.xc;

from xen.xend import sxp
from xen.xend.XendError import VmError

from xen.xend.server.DevController import DevController


xc = xen.lowlevel.xc.xc()


def parse_ioport(val):
    """Parse an i/o port field.
    """
    if isinstance(val, types.StringType):
        radix = 10
        if val.startswith('0x') or val.startswith('0X'):
            radix = 16
        v = int(val, radix)
    else:
        v = val
    return v


class IOPortsController(DevController):

    def __init__(self, vm):
        DevController.__init__(self, vm)


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        def get_param(field):
            try:
                val = sxp.child_value(config, field)

                if not val:
                    raise VmError('ioports: Missing %s config setting' % field)

                return parse_ioport(val)
            except:
                raise VmError('ioports: Invalid config setting %s: %s' %
                              (field, val))
       
        io_from = get_param('from')
        io_to = get_param('to') 

        if io_to < io_from or io_to >= 65536:
            raise VmError('ioports: Invalid i/o range: %s - %s' %
                          (io_from, io_to))

        rc = xc.domain_ioport_permission(dom          = self.getDomid(),
                                         first_port   = io_from,
                                         nr_ports     = io_to - io_from + 1,
                                         allow_access = True)

        if rc < 0:
            #todo non-fatal
            raise VmError(
                'ioports: Failed to configure legacy i/o range: %s - %s' %
                (io_from, io_to))

        return (dev, {}, {})
