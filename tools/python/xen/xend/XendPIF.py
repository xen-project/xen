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

import commands
import logging
import os
import re


log = logging.getLogger("xend.XendPIF")
log.setLevel(logging.TRACE)


MAC_RE = re.compile(':'.join(['[0-9a-f]{2}'] * 6))
IP_IFACE_RE = re.compile(r'^\d+: (\w+):.*mtu (\d+) .* link/\w+ ([0-9a-f:]+)')

def linux_phy_to_virt(pif_name):
    return 'eth' + re.sub(r'^[a-z]+', '', pif_name)

def linux_get_phy_ifaces():
    """Returns a list of physical interfaces.

    Identifies PIFs as those that have a interface name starting with 'p'
    and have the fake 'fe:ff:ff:ff:ff:ff' MAC address.

    See /etc/xen/scripts/network-bridge for how the devices are renamed.

    @rtype: array of 3-element tuple (name, mtu, mac)
    """
    
    ip_cmd = 'ip -o link show'
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

    ip_mac_cmd = 'ip link set %s addr %s' % \
                 (linux_phy_to_virt(iface), mac)
    rc, output = commands.getstatusoutput(ip_mac_cmd)
    if rc == 0:
        return True

    return False

def linux_set_mtu(iface, mtu):
    try:
        ip_mtu_cmd = 'ip link set %s mtu %d' % \
                     (linux_phy_to_virt(iface), int(mtu))
        rc, output = commands.getstatusoutput(ip_mtu_cmd)
        if rc == 0:
            return True
        return False
    except ValueError:
        return False

class XendPIF:
    """Representation of a Physical Network Interface."""
    
    def __init__(self, uuid, metrics, device, mtu, vlan, mac, network,
                 host):
        self.uuid = uuid
        self.metrics = metrics
        self.device = device
        self.mac = mac
        self.mtu = mtu
        self.vlan = vlan
        self.network = network
        self.host = host

    def set_device(self, new_device):
        self.device = new_device

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

    def get_record(self):
        return {'uuid': self.uuid,
                'device': self.device,
                'MAC': self.mac,
                'MTU': self.mtu,
                'VLAN': self.vlan,
                'host': self.host.uuid,
                'network': self.network.uuid,
                'metrics': self.metrics.uuid}

    def refresh(self, bridges):
        ifname = self.interface_name()
        rc, _ = _cmd('ip link show %s', ifname)
        if rc != 0:
            # Interface does not exist.  If it's a physical interface, then
            # there's nothing we can do -- this should have been set up with
            # the network script.  Otherwise, we can use vconfig to derive
            # a subinterface.
            if self.vlan == -1:
                return
            
            rc, _ = _cmd('vconfig add %s %d', self.device, self.vlan)
            if rc != 0:
                log.error('Could not refresh VLAN for interface %s', ifname)
                return
            
            log.info('Created network interface %s', ifname)

        for brname, nics in bridges.items():
            if ifname in nics:
                log.debug('%s is already attached to %s', ifname, brname)
                return

        # The interface is not attached to a bridge.  Create one, and attach
        # the interface to it.
        brname = _new_bridge_name(bridges)
        rc, _ = _cmd('brctl addbr %s', brname)
        if rc != 0:
            log.error('Could not create bridge %s for interface %s', brname,
                      ifname)
            return
        log.info('Created network bridge %s', brname)
        
        rc, _ = _cmd('brctl addif %s %s', brname, ifname)
        if rc != 0:
            log.error('Could not add %s to %s', ifname, brname)
            return
        log.info('Added network interface %s to bridge %s', ifname, brname)


    def interface_name(self):
        if self.vlan != -1:
            return '%s.%d' % (self.device, self.vlan)
        else:
            return self.device


def _cmd(cmd, *args):
    if len(args) > 0:
        cmd = cmd % args
    rc, output = commands.getstatusoutput(cmd)
    if rc != 0:
        log.debug('%s failed with code %d' % (cmd, rc))
    log.trace('%s: %s' % (cmd, output))
    return rc, output


def _new_bridge_name(bridges):
    n = 0
    while True:
        brname = 'xenbr%d' % n
        if brname not in bridges:
            return brname
        n += 1
