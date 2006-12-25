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
# Copyright (c) 2006 Xensource Inc.
#============================================================================

import os
import commands
import re
import socket

from xen.xend.XendRoot import instance as xendroot
from xen.xend.XendLogging import log

MAC_RE = ':'.join(['[0-9a-f]{2}'] * 6)
IP_IFACE_RE = r'^\d+: (\w+):.*mtu (\d+) .* link/\w+ ([0-9a-f:]+)'

def linux_phy_to_virt(pif_name):
    return 'eth' + re.sub(r'^[a-z]+', '', pif_name)

def linux_get_phy_ifaces():
    """Returns a list of physical interfaces.

    Identifies PIFs as those that have a interface name starting with 'p'
    and have the fake 'fe:ff:ff:ff:ff:ff' MAC address.

    See /etc/xen/scripts/network-bridge for how the devices are renamed.

    @rtype: array of 3-element tuple (name, mtu, mac)
    """
    
    ip_cmd = '/sbin/ip -o link show'
    rc, output = commands.getstatusoutput(ip_cmd)
    ifaces = {}
    phy_ifaces = []
    if rc == 0:
        # parse all interfaces into (name, mtu, mac)
        for line in output.split('\n'):
            has_if = re.search(IP_IFACE_RE, line)
            if has_if:
                ifaces[has_if.group(1)] = has_if.groups()
                
        # resolve pifs' mac addresses
        for name, mtu, mac in ifaces.values():
            if name[0] == 'p' and mac == 'fe:ff:ff:ff:ff:ff':
                bridged_ifname = linux_phy_to_virt(name)
                bridged_if = ifaces.get(bridged_ifname)
                if bridged_if:
                    bridged_mac = bridged_if[2]
                phy_ifaces.append((name, int(mtu), bridged_mac))
                
    return phy_ifaces

def linux_set_mac(iface, mac):
    if not re.search(MAC_RE, mac):
        return False

    ip_mac_cmd = '/sbin/ip link set %s addr %s' % \
                 (linux_phy_to_virt(iface), mac)
    rc, output = commands.getstatusoutput(ip_mac_cmd)
    if rc == 0:
        return True

    return False

def linux_set_mtu(iface, mtu):
    try:
        ip_mtu_cmd = '/sbin/ip link set %s mtu %d' % \
                     (linux_phy_to_virt(iface), int(mtu))
        rc, output = commands.getstatusoutput(ip_mtu_cmd)
        if rc == 0:
            return True
        return False
    except ValueError:
        return False

def same_dir_rename(old_path, new_path):
    """Ensure that the old_path and new_path refer to files in the same
    directory."""
    old_abs = os.path.normpath(old_path)
    new_abs = os.path.normpath(new_path)
    if os.path.dirname(old_abs) == os.path.dirname(new_abs):
        os.rename(old_abs, new_abs)
    else:
        log.warning("Unable to ensure name is new name is safe: %s" % new_abs)
    

class XendPIF:
    """Representation of a Physical Network Interface."""
    
    def __init__(self, uuid, name, mtu, mac, network, host):
        self.uuid = uuid
        self.name = name
        self.mac = mac
        self.mtu = mtu
        self.vlan = ''
        self.network = network
        self.host = host

    def set_name(self, new_name):
        self.name = new_name
            
    def set_mac(self, new_mac):
        success = linux_set_mac(new_mac)
        if success:
            self.mac = new_mac
        return success

    def set_mtu(self, new_mtu):
        success = linux_set_mtu(new_mtu)
        if success:
            self.mtu = new_mtu
        return success

    def get_io_read_kbs(self):
        return 0.0

    def get_io_write_kbs(self):
        return 0.0

    def get_record(self, transient = True):
        result = {'name': self.name,
                  'MAC': self.mac,
                  'MTU': self.mtu,
                  'VLAN': self.vlan,
                  'host': self.host.uuid,
                  'network': self.network.uuid}
        if transient:
            result['io_read_kbs'] = self.get_io_read_kbs()
            result['io_write_kbs'] = self.get_io_write_kbs()
        return result
