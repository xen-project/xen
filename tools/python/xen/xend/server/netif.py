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


write_rate_G_re = re.compile('^([0-9]+)000000000(B/s@[0-9]+us)$')
write_rate_M_re = re.compile('^([0-9]+)000000(B/s@[0-9]+us)$')
write_rate_K_re = re.compile('^([0-9]+)000(B/s@[0-9]+us)$')
write_rate_s_re = re.compile('^([0-9]+[GMK]?B/s@[0-9]+)000000us$')
write_rate_m_re = re.compile('^([0-9]+[GMK]?B/s@[0-9]+)000us$')

def formatRate(rate):
    (bytes_per_interval, interval_usecs) = map(long, rate.split(','))

    if interval_usecs != 0:
        bytes_per_second = (bytes_per_interval * 1000 * 1000) / interval_usecs
    else:
        bytes_per_second = 0xffffffffL

    ratestr = "%uB/s@%uus" % (bytes_per_second, interval_usecs)

    # look for '000's
    m = write_rate_G_re.match(ratestr)
    if m:
        ratestr = m.group(1) + "G" + m.group(2)
    else:
        m = write_rate_M_re.match(ratestr)
        if m:
            ratestr = m.group(1) + "M" + m.group(2)
        else:
            m = write_rate_K_re.match(ratestr)
            if m:
                ratestr = m.group(1) + "K" + m.group(2)

    m = write_rate_s_re.match(ratestr)
    if m:
        ratestr = m.group(1) + "s"
    else:
        m = write_rate_m_re.match(ratestr)
        if m:
            ratestr = m.group(1) + "ms"

    return ratestr


class NetifController(DevController):
    """Network interface controller. Handles all network devices for a domain.
    """
    
    def __init__(self, vm):
        DevController.__init__(self, vm)

    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        script = os.path.join(xoptions.network_script_dir,
                              config.get('script', xoptions.get_vif_script()))
        typ     = config.get('type')
        bridge  = config.get('bridge')
        mac     = config.get('mac')
        vifname = config.get('vifname')
        rate    = config.get('rate')
        uuid    = config.get('uuid')
        ipaddr  = config.get('ip')
        model   = config.get('model')

        devid = self.allocateDeviceID()

        if not typ:
            typ = xoptions.netback_type
            
        if not mac:
            mac = randomMAC()

        back = { 'script' : script,
                 'mac'    : mac,
                 'handle' : "%i" % devid,
                 'type'   : typ }

        if typ == 'ioemu':
            front = {}
        else:
            front = { 'handle' : "%i" % devid,
                      'mac'    : mac }
        if ipaddr:
            back['ip'] = ipaddr
        if bridge:
            back['bridge'] = bridge
        if vifname:
            back['vifname'] = vifname
        if rate:
            back['rate'] = parseRate(rate)
        if uuid:
            back['uuid'] = uuid
        if model:
            back['model'] = model

        return (devid, back, front)


    def getDeviceConfiguration(self, devid):
        """@see DevController.configuration"""

        result = DevController.getDeviceConfiguration(self, devid)
        devinfo =  self.readBackend(devid, 'script', 'ip', 'bridge',
                                    'mac', 'type', 'vifname', 'rate',
                                    'uuid', 'model')
        (script, ip, bridge, mac, typ, vifname, rate, uuid, model) = devinfo

        if script:
            network_script_dir = xoptions.network_script_dir + os.sep
            result['script'] = script.replace(network_script_dir, "")
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
            result['rate'] = formatRate(rate)
        if uuid:
            result['uuid'] = uuid
        if model:
            result['model'] = model
            
        return result

