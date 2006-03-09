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

import xen.lowlevel.xc;

from xen.xend import sxp
from xen.xend.XendError import VmError

from xen.xend.server.DevController import DevController


xc = xen.lowlevel.xc.xc()


class IRQController(DevController):

    def __init__(self, vm):
        DevController.__init__(self, vm)


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        def get_param(field):
            try:
                val = sxp.child_value(config, field)

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

        rc = xc.domain_irq_permission(dom          = self.getDomid(),
                                      pirq         = pirq,
                                      allow_access = True)

        if rc < 0:
            #todo non-fatal
            raise VmError(
                'irq: Failed to configure irq: %d' % (pirq))

        return (None, {}, {})
