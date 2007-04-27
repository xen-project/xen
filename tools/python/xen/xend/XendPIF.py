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
from xen.xend import uuid as genuuid
from xen.xend import XendAPIStore
from xen.xend.XendBase import XendBase
from xen.xend.XendPIFMetrics import XendPIFMetrics
from xen.xend.XendError import *

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

def _create_VLAN(dev, vlan):
    rc, _ = commands.getstatusoutput('vconfig add %s %d' %
                                     (dev, vlan))
    if rc != 0:
        return False

    rc, _ = commands.getstatusoutput('ifconfig %s.%d up' %
                                     (dev, vlan))
    return rc == 0

def _destroy_VLAN(dev, vlan):
    rc, _ = commands.getstatusoutput('ifconfig %s.%d down' %
                                     (dev, vlan))
    if rc != 0:
        return False
                                     
    rc, _ = commands.getstatusoutput('vconfig rem %s.%d' %
                                     (dev, vlan))
    return rc == 0

class XendPIF(XendBase):
    """Representation of a Physical Network Interface."""

    def getClass(self):
        return "PIF"

    def getAttrRO(self):
        attrRO = ['network',
                  'host',
                  'metrics',
                  'device',
                  'VLAN']
        return XendBase.getAttrRO() + attrRO
    
    def getAttrRW(self):
        attrRW = ['MAC',
                  'MTU']
        return XendBase.getAttrRW() + attrRW

    def getAttrInst(self):
        attrInst = ['network',
                    'device',
                    'MAC',
                    'MTU',
                    'VLAN']
        return attrInst

    def getMethods(self):
        methods = ['plug',
                   'unplug',
                   'destroy']
        return XendBase.getMethods() + methods

    def getFuncs(self):
        funcs = ['create_VLAN']
        return XendBase.getFuncs() + funcs

    getClass    = classmethod(getClass)
    getAttrRO   = classmethod(getAttrRO)
    getAttrRW   = classmethod(getAttrRW)
    getAttrInst = classmethod(getAttrInst)
    getMethods  = classmethod(getMethods)
    getFuncs    = classmethod(getFuncs)
    
    def create_phy(self, network_uuid, device,
                   MAC, MTU):
        """
        Called when a new physical PIF is found
        Could be a VLAN...
        """
        # Create new uuids
        pif_uuid = genuuid.createString()
        metrics_uuid = genuuid.createString()

        # Create instances
        metrics = XendPIFMetrics(metrics_uuid, pif_uuid)

        # Is this a VLAN?
        VLANdot = device.split(".")
        VLANcolon = device.split(":")

        if len(VLANdot) > 1:
            VLAN = VLANdot[1]
            device = VLANdot[0]
        elif len(VLANcolon) > 1:
            VLAN = VLANcolon[1]
            device = VLANcolon[0] 
        else:
            VLAN = -1
            
        record = {
            'network': network_uuid,
            'device':  device,
            'MAC':     MAC,
            'MTU':     MTU,
            'VLAN':    VLAN
            }
        pif = XendPIF(record, pif_uuid, metrics_uuid)

        return pif_uuid

    def recreate(self, record, uuid):
        """Called on xend start / restart"""        
        pif_uuid = uuid
        metrics_uuid = record['metrics']

        # Create instances
        metrics = XendPIFMetrics(metrics_uuid, pif_uuid)
        pif = XendPIF(record, pif_uuid, metrics_uuid)

        # If physical PIF, check exists
        # If VLAN, create if not exist
        ifs = [dev for dev, _1, _2 in linux_get_phy_ifaces()]
        if pif.get_VLAN() == -1:
            if pif.get_device() not in ifs:
                pif.destroy()
                metrics.destroy()
                return None
        else:
            if pif.get_interface_name() not in ifs:
                _create_VLAN(pif.get_device(), pif.get_VLAN())
                pif.plug()

        return pif_uuid

    def create_VLAN(self, device, network_uuid, host_ref, vlan):
        """Exposed via API - create a new VLAN from existing VIF"""
        
        ifs = [name for name, _, _ in linux_get_phy_ifaces()]

        vlan = int(vlan)

        # Check VLAN tag is valid
        if vlan < 0 or vlan >= 4096:
            raise VLANTagInvalid(vlan)
        
        # Check device exists
        if device not in ifs:
            raise InvalidDeviceError(device)

        # Check VLAN doesn't already exist
        if "%s.%d" % (device, vlan) in ifs:
            raise DeviceExistsError("%s.%d" % (device, vlan))

        # Check network ref is valid
        from XendNetwork import XendNetwork
        if network_uuid not in XendNetwork.get_all():
            raise InvalidHandleError("Network", network_uuid)

        # Check host_ref is this host
        import XendNode
        if host_ref != XendNode.instance().get_uuid():
            raise InvalidHandleError("Host", host_ref)

        # Create the VLAN
        _create_VLAN(device, vlan)

        # Create new uuids
        pif_uuid = genuuid.createString()
        metrics_uuid = genuuid.createString()

        # Create the record
        record = {
            "device":  device,
            "MAC":     '',
            "MTU":     '',
            "network": network_uuid,
            "VLAN":    vlan
            }

        # Create instances
        metrics = XendPIFMetrics(metrics_uuid, pif_uuid)
        pif = XendPIF(record, pif_uuid, metrics_uuid)

        # Not sure if they should be created plugged or not...
        pif.plug()

        XendNode.instance().save_PIFs()
        return pif_uuid

    create_phy  = classmethod(create_phy)
    recreate    = classmethod(recreate)
    create_VLAN = classmethod(create_VLAN)
    
    def __init__(self, record, uuid, metrics_uuid):
        XendBase.__init__(self, uuid, record)
        self.metrics = metrics_uuid

    def plug(self):
        """Plug the PIF into the network"""
        network = XendAPIStore.get(self.network,
                                   "network")
        bridge_name = network.get_name_label()

        from xen.util import Brctl
        Brctl.vif_bridge_add({
            "bridge": bridge_name,
            "vif":    self.get_interface_name()
            })

    def unplug(self):
        """Unplug the PIF from the network"""
        network = XendAPIStore.get(self.network,
                                   "network")
        bridge_name = network.get_name_label()

        from xen.util import Brctl
        Brctl.vif_bridge_rem({
            "bridge": bridge_name,
            "vif":    self.get_interface_name()
            })

    def destroy(self):
        # Figure out if this is a physical device
        if self.get_interface_name() == \
           self.get_device():
            raise PIFIsPhysical(self.get_uuid())

        self.unplug()

        if _destroy_VLAN(self.get_device(), self.get_VLAN()):
            XendBase.destroy(self)
            import XendNode
            XendNode.instance().save_PIFs()
        else:
            raise NetworkError("Unable to delete VLAN", self.get_uuid())

    def get_interface_name(self):
        if self.get_VLAN() == -1:
            return self.get_device()
        else:
            return "%s.%d" % (self.get_device(), self.get_VLAN())
        
    def get_device(self):
        """
        This is the base interface.
        For phy if (VLAN == -1) this is same as
        if name.
        For VLANs, this it the bit before the period
        """
        return self.device

    def get_network(self):
        return self.network

    def get_host(self):
        from xen.xend import XendNode
        return XendNode.instance().get_uuid()

    def get_metrics(self):
        return self.metrics

    def get_MAC(self):
        return self.MAC

    def set_MAC(self, new_mac):
        success = linux_set_mac(self.device, new_mac)
        if success:
            self.MAC = new_mac
            import XendNode
            XendNode.instance().save_PIFs()
        return success

    def get_MTU(self):
        return self.MTU

    def set_MTU(self, new_mtu):
        success = linux_set_mtu(self.device, new_mtu)
        if success:
            self.MTU = new_mtu
            import XendNode
            XendNode.instance().save_PIFs()
        return success

    def get_VLAN(self):
        return self.VLAN
