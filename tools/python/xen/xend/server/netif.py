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


"""Support for virtual network interfaces.
"""

import os

from xen.xend import sxp

from xen.xend.server.DevController import DevController


class NetifController(DevController):
    """Network interface controller. Handles all network devices for a domain.
    """
    
    def __init__(self, vm):
        DevController.__init__(self, vm)


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        from xen.xend import XendRoot
        xroot = XendRoot.instance()

        def _get_config_ipaddr(config):
            val = []
            for ipaddr in sxp.children(config, elt='ip'):
                val.append(sxp.child0(ipaddr))
            return val

        script = os.path.join(xroot.network_script_dir,
                              sxp.child_value(config, 'script',
                                              xroot.get_vif_script()))
        bridge = sxp.child_value(config, 'bridge',
                                 xroot.get_vif_bridge())
        mac = sxp.child_value(config, 'mac')
        ipaddr = _get_config_ipaddr(config)

        devid = self.allocateDeviceID()

        back = { 'script' : script,
                 'mac' : mac,
                 'bridge' : bridge,
                 'handle' : "%i" % devid }
        if ipaddr:
            back['ip'] = ' '.join(ipaddr)

        front = { 'handle' : "%i" % devid,
                  'mac' : mac }

        return (devid, back, front)
