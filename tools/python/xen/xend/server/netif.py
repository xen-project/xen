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
import random

from xen.xend import sxp
from xen.xend import XendRoot

from xen.xend.server.DevController import DevController


xroot = XendRoot.instance()


def randomMAC():
    """Generate a random MAC address.

    Uses OUI (Organizationally Unique Identifier) 00-16-3E, allocated to
    Xensource, Inc. The OUI list is available at
    http://standards.ieee.org/regauth/oui/oui.txt.

    The remaining 3 fields are random, with the first bit of the first
    random field set 0.

    @return: MAC address string
    """
    mac = [ 0x00, 0x16, 0x3e,
            random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))


class NetifController(DevController):
    """Network interface controller. Handles all network devices for a domain.
    """
    
    def __init__(self, vm):
        DevController.__init__(self, vm)


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        def _get_config_ipaddr(config):
            val = []
            for ipaddr in sxp.children(config, elt='ip'):
                val.append(sxp.child0(ipaddr))
            return val

        script = os.path.join(xroot.network_script_dir,
                              sxp.child_value(config, 'script',
                                              xroot.get_vif_script()))
        type = sxp.child_value(config, 'type')
        if type == 'ioemu':
            return (None,{},{})
        bridge = sxp.child_value(config, 'bridge')
        mac    = sxp.child_value(config, 'mac')
        ipaddr = _get_config_ipaddr(config)

        devid = self.allocateDeviceID()

        if not mac:
            mac = randomMAC()

        back = { 'script' : script,
                 'mac'    : mac,
                 'handle' : "%i" % devid }
        if ipaddr:
            back['ip'] = ' '.join(ipaddr)
        if bridge:
            back['bridge'] = bridge

        front = { 'handle' : "%i" % devid,
                  'mac'    : mac }

        return (devid, back, front)


    def configuration(self, devid):
        """@see DevController.configuration"""

        result = DevController.configuration(self, devid)

        (script, ip, bridge, mac) = self.readBackend(devid,
                                                     'script', 'ip', 'bridge',
                                                     'mac')

        if script:
            result.append(['script',
                           script.replace(xroot.network_script_dir + os.sep,
                                          "")])
        if ip:
            result.append(['ip', ip.split(" ")])
        if bridge:
            result.append(['bridge', bridge])
        if mac:
            result.append(['mac', mac])

        return result
