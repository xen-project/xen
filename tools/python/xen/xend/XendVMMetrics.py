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
# Copyright (c) 2006-2007 Xensource Inc.
#============================================================================

from xen.xend.XendLogging import log

instances = {}

class XendVMMetrics:
    """VM Metrics."""

    def get_by_uuid(_, uuid):
        return instances[uuid]

    get_by_uuid = classmethod(get_by_uuid)

    def is_valid_vm_metrics(_, uuid):
        return uuid in instances

    is_valid_vm_metrics = classmethod(is_valid_vm_metrics)
   
    def __init__(self, uuid, xend_domain_instance):
        self.uuid = uuid
        self.xend_domain_instance = xend_domain_instance
        instances[uuid] = self

    def get_uuid(self):
        return self.uuid

    def get_memory_actual(self):
        return self.get_record()["memory_actual"]

    def get_vcpus_number(self):
        return self.get_record()["vcpus_number"]
    
    def get_vcpus_utilisation(self):
        return self.xend_domain_instance.get_vcpus_util()

    def get_record(self):
        domInfo = self.xend_domain_instance.getDomInfo()
        if domInfo:
            return { 'uuid'              : self.uuid,
                     'memory_actual'     : domInfo["mem_kb"] * 1024,
                     'vcpus_number'      : domInfo["online_vcpus"],
                     'vcpus_utilisation' : self.get_vcpus_utilisation()
                   }
        else:
            return { 'uuid'              : self.uuid,
                     'memory_actual'     : 0,
                     'vcpus_number'      : 0,
                     'vcpus_utilisation' : {}
                   }
