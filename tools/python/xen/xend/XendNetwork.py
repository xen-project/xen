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
import struct
import socket

import XendNode
from XendLogging import log

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

    def set_name_label(self, new_name):
        self.name_label = new_name

    def set_name_description(self, new_desc):
        self.name_description = new_desc

    def set_default_gateway(self, new_gateway):
        if re.search('^\d+\.\d+\.\d+\.\d+$', new_gateway):
            self.default_gateway = new_gateway

    def set_default_netmask(self, new_netmask):
        if re.search('^\d+\.\d+\.\d+\.\d+$', new_netmask):
            self.default_netmask = new_netmask

    def get_VIF_UUIDs(self):
        return []

    def get_PIF_UUIDs(self):
        return [x.uuid for x in XendNode.instance().pifs.values()
                if x.network == self]

    def get_record(self, transient = True):
        result = {
            'uuid': self.uuid,
            'name_label': self.name_label,
            'name_description': self.name_description,
            'default_gateway': self.default_gateway,
            'default_netmask': self.default_netmask,
        }
        if transient:
            result['VIFs'] = self.get_VIF_UUIDs()
            result['PIFs'] = self.get_PIF_UUIDs()
        return result
