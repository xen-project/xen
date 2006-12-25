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
# Copyright (c) 2006 Xensource Inc.
#============================================================================

import os
import commands
import re
import struct
import socket

from xen.xend.XendRoot import instance as xendroot

IP_ROUTE_RE = r'^default via ([\d\.]+) dev (\w+)'

def linux_get_default_network():
    """Returns the network details of the host."""

    ip_cmd = '/sbin/ip route'
    rc, output = commands.getstatusoutput(ip_cmd)
    default_route = None
    default_dev = None
    default_netmask = None
    if rc == 0:
        # find default route/device
        for line in output.split('\n'):
            is_default = re.search(IP_ROUTE_RE, line)
            if is_default:
                default_route = is_default.group(1)
                default_dev = is_default.group(2)

        # find network address and network mask
        if default_dev:
            dev_re = r'^([\d\.]+)/(\d+) dev %s' % default_dev
            for line in output.split('\n'):
                is_dev = re.search(dev_re, line)
                if is_dev:
                    # convert integer netmask to string representation
                    netmask = 0xffffffff ^ (2**(32-int(is_dev.group(2))) - 1)
                    packed = struct.pack('!I', netmask)
                    default_netmask = socket.inet_ntoa(packed)

    return (default_route, default_netmask)


class XendNetwork:
    def __init__(self, uuid, name, description, gateway, netmask):
        self.uuid = uuid
        self.name_label = name 
        self.name_description = description
        self.default_gateway = gateway
        self.default_netmask = netmask
        self.vifs = {}
        self.pifs = {}

    def get_name_label(self):
        return self.name_label

    def set_name_label(self, new_name):
        self.name_label = new_name

    def get_name_description(self):
        return self.name_description

    def set_name_description(self, new_desc):
        self.name_description = new_desc

    def get_default_gateway(self):
        return self.default_gateway

    def set_default_gateway(self, new_gateway):
        if re.search('^\d+\.\d+\.\d+\.\d+$', new_gateway):
            self.default_gateway = new_gateway

    def get_default_netmask(self):
        return self.default_netmask

    def set_default_netmask(self, new_netmask):
        if re.search('^\d+\.\d+\.\d+\.\d+$', new_netmask):
            self.default_netmask = new_netmask

    def add_pif(self, pif):
        self.pifs[pif.get_uuid()] = pif

    def remove_pif(self, pif_uuid):
        if pif_uuid in self.pifs:
            del self.pifs[pif_uuid]

    def add_vif(self, vif):
        self.vifs[vif.get_uuid()] = vif

    def remove_vif(self, vif_uuid):
        if vif_uuid in self.vifs:
            del self.vifs[vif_uuid]
        
    def get_record(self):
        return {
            'uuid': self.uuid,
            'name_label': self.name_label,
            'name_description': self.name_description,
            'default_gateway': self.default_gateway,
            'default_netmask': self.default_netmask,
            'VIFs': self.vifs.keys(),
            'PIFs': self.pifs.keys()
        }
           
