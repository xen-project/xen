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
import re

from xen.xend import XendOptions
from xen.xend.server.DevController import DevController

xoptions = XendOptions.instance()

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

rate_re = re.compile("^([0-9]+)([GMK]?)([Bb])/s(@([0-9]+)([mu]?)s)?$")

def parseRate(ratestr):
    """if parsing fails this will return default of unlimited rate"""
    bytes_per_interval = 0xffffffffL # 0xffffffff # big default
    interval_usecs     = 0L          # disabled

    m = rate_re.match(ratestr)
    if m:
        bytes_per_sec = long(m.group(1))

        if m.group(2) == 'G':
            bytes_per_sec *= 1000 * 1000 * 1000
        elif m.group(2) == 'M':
            bytes_per_sec *= 1000 * 1000
        elif m.group(2) == 'K':
            bytes_per_sec *= 1000

        if m.group(3) == 'b':
            bytes_per_sec /= 8

        if m.group(5) is None:
            interval_usecs = 50000L      # 50ms default
        else:
            interval_usecs = long(m.group(5))
            if m.group(6) == '':
                interval_usecs *= 1000 * 1000
            elif m.group(6) == 'm':
                interval_usecs *= 1000

        bytes_per_interval = (bytes_per_sec * interval_usecs) / 1000000L

        # overflow / underflow checking: default to unlimited rate
        if bytes_per_interval == 0 or bytes_per_interval > 0xffffffffL or \
           interval_usecs == 0 or interval_usecs > 0xffffffffL:
            bytes_per_interval = 0xffffffffL
            interval_usecs     = 0L

    return "%lu,%lu" % (bytes_per_interval, interval_usecs)


class NetifController(DevController):
    """Network interface controller. Handles all network devices for a domain.
    """
    
    def __init__(self, vm):
        DevController.__init__(self, vm)

    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        script  = config.get('script', xoptions.get_vif_script())
        typ     = config.get('type')
        bridge  = config.get('bridge')
        mac     = config.get('mac')
        vifname = config.get('vifname')
        rate    = config.get('rate')
        uuid    = config.get('uuid')
        ipaddr  = config.get('ip')
        model   = config.get('model')

        if not typ:
            typ = xoptions.netback_type

        if not mac:
            mac = randomMAC()

        devid = self.allocateDeviceID()

        back = { 'script' : script,
                 'mac'    : mac,
                 'type'   : typ }
        if ipaddr:
            back['ip'] = ipaddr
        if bridge:
            back['bridge'] = bridge
        if vifname:
            back['vifname'] = vifname
        if rate:
            back['rate'] = rate
        if uuid:
            back['uuid'] = uuid
        if model:
            back['model'] = model

        config_path = "device/%s/%d/" % (self.deviceClass, devid)
        for x in back:
            self.vm._writeVm(config_path + x, back[x])

        back['handle'] = "%i" % devid
        back['script'] = os.path.join(xoptions.network_script_dir, script)
        if rate:
            back['rate'] = parseRate(rate)

        front = {}
        if typ != 'ioemu':
            front = { 'handle' : "%i" % devid,
                      'mac'    : mac }

        return (devid, back, front)


    def getDeviceConfiguration(self, devid):
        """@see DevController.configuration"""

        result = DevController.getDeviceConfiguration(self, devid)

        config_path = "device/%s/%d/" % (self.deviceClass, devid)
        devinfo = ()
        for x in ( 'script', 'ip', 'bridge', 'mac',
                   'type', 'vifname', 'rate', 'uuid', 'model' ):
            y = self.vm._readVm(config_path + x)
            devinfo += (y,)
        (script, ip, bridge, mac, typ, vifname, rate, uuid, model) = devinfo

        if script:
            result['script'] = script
        if ip:
            result['ip'] = ip
        if bridge:
            result['bridge'] = bridge
        if mac:
            result['mac'] = mac
        if typ:
            result['type'] = typ
        if vifname:
            result['vifname'] = vifname
        if rate:
            result['rate'] = rate
        if uuid:
            result['uuid'] = uuid
        if model:
            result['model'] = model
            
        return result
