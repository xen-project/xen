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

        def _get_config_ipaddr(config):
            val = []
            for ipaddr in sxp.children(config, elt='ip'):
                val.append(sxp.child0(ipaddr))
            return val

        script = os.path.join(xroot.network_script_dir,
                              sxp.child_value(config, 'script',
                                              xroot.get_vif_script()))
        typ = sxp.child_value(config, 'type')
        bridge  = sxp.child_value(config, 'bridge')
        mac     = sxp.child_value(config, 'mac')
        vifname = sxp.child_value(config, 'vifname')
        rate    = sxp.child_value(config, 'rate')
        ipaddr  = _get_config_ipaddr(config)

        devid = self.allocateDeviceID()

        if not mac:
            mac = randomMAC()

        back = { 'script' : script,
                 'mac'    : mac,
                 'handle' : "%i" % devid }

        if typ == 'ioemu':
            front = {}
            back['type'] = 'ioemu'
        else:
            front = { 'handle' : "%i" % devid,
                      'mac'    : mac }
        if ipaddr:
            back['ip'] = ' '.join(ipaddr)
        if bridge:
            back['bridge'] = bridge
        if vifname:
            back['vifname'] = vifname
        if rate:
            back['rate'] = parseRate(rate)

        return (devid, back, front)


    def configuration(self, devid):
        """@see DevController.configuration"""

        result = DevController.configuration(self, devid)

        (script, ip, bridge, mac, typ, vifname, rate) = self.readBackend(
            devid, 'script', 'ip', 'bridge', 'mac', 'type', 'vifname', 'rate')

        if script:
            result.append(['script',
                           script.replace(xroot.network_script_dir + os.sep,
                                          "")])
        if ip:
            for i in ip.split(" "):
                result.append(['ip', i])
        if bridge:
            result.append(['bridge', bridge])
        if mac:
            result.append(['mac', mac])
        if typ:
            result.append(['type', typ])
        if vifname:
            result.append(['vifname', vifname])
        if rate:
            result.append(['rate', formatRate(rate)])

        return result
