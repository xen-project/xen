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
        
        typedev = sxp.child_value(config, 'dev')
        if re.match('^ioemu:', typedev):
            return

        devid = blkif.blkdev_name_to_number(sxp.child_value(config, 'dev'))

        (typ, params) = string.split(sxp.child_value(config, 'uname'), ':', 1)
        back = { 'type' : typ,
                 'params' : params
                 }

        if 'r' == sxp.child_value(config, 'mode', 'r'):
            back['read-only'] = ""  # existence indicates read-only

        front = { 'virtual-device' : "%i" % devid }

        return (devid, back, front)
