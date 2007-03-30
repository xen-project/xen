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

import XendDomain
import XendNode
from XendLogging import log

IP_ROUTE_RE = r'^default via ([\d\.]+) dev (\w+)'

class XendNetwork:
    def __init__(self, uuid, record):
        self.uuid = uuid
        self.name_label = record.get('name_label', '')
        self.name_description = record.get('name_description', '')
        self.other_config = record.get('other_config', {})

    def get_name_label(self):
        return self.name_label

    def get_name_description(self):
        return self.name_description

    def set_name_label(self, new_name):
        self.name_label = new_name
        XendNode.instance().save_networks()

    def set_name_description(self, new_desc):
        self.name_description = new_desc
        XendNode.instance().save_networks()

    def get_VIFs(self):
        result = []
        vms = XendDomain.instance().get_all_vms()
        for vm in vms:
            vifs = vm.get_vifs()
            for vif in vifs:
                vif_cfg = vm.get_dev_xenapi_config('vif', vif)
                if vif_cfg.get('network') == self.uuid:
                    result.append(vif)
        return result

    def get_PIFs(self):
        return [x.uuid for x in XendNode.instance().pifs.values()
                if x.network == self]

    def get_other_config(self):
        return self.other_config

    def set_other_config(self, value):
        self.other_config = value
        XendNode.instance().save_networks()

    def add_to_other_config(self, key, value):
        self.other_config[key] = value
        XendNode.instance().save_networks()

    def remove_from_other_config(self, key):
        if key in self.other_config:
            del self.other_config[key]
        XendNode.instance().save_networks()

    def get_record(self):
        return self.get_record_internal(True)

    def get_record_internal(self, transient):
        result = {
            'uuid': self.uuid,
            'name_label': self.name_label,
            'name_description': self.name_description,
            'other_config' : self.other_config,
        }
        if transient:
            result['VIFs'] = self.get_VIFs()
            result['PIFs'] = self.get_PIFs()
        return result
