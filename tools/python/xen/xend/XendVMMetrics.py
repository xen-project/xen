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
# Copyright (c) 2007 Tom Wilkie
#============================================================================

from xen.xend.XendLogging import log
from xen.xend.XendBase import XendBase
import xen.lowlevel.xc

xc = xen.lowlevel.xc.xc()

class XendVMMetrics(XendBase):
    """VM Metrics."""

    def getClass(self):
        return "VM_metrics"
    
    def getAttrRO(self):
        attrRO = ['memory_actual',
                  'VCPUs_number',
                  'VCPUs_utilisation',
                  'VCPUs_CPU',
                  'VCPUs_flags',
                  'VCPUs_params',
                  'state',
                  'start_time',
                  'last_updated']
        return XendBase.getAttrRO() + attrRO

    getClass    = classmethod(getClass)
    getAttrRO   = classmethod(getAttrRO)

    def __init__(self, uuid, xend_domain_instance):
        XendBase.__init__(self, uuid, {})
        self.xend_domain_instance = xend_domain_instance
        
    def get_memory_actual(self):
        domInfo = self.xend_domain_instance.getDomInfo()
        if domInfo:
            return domInfo["mem_kb"] * 1024
        else:
            return 0

    def get_VCPUs_number(self):
        domInfo = self.xend_domain_instance.getDomInfo()
        if domInfo:
            return domInfo["online_vcpus"]
        else:
            return 0
    
    def get_VCPUs_utilisation(self):
        return self.xend_domain_instance.get_vcpus_util()

    def get_VCPUs_CPU(self):
        domid = self.xend_domain_instance.getDomid()
        if domid is not None:
            vcpus_cpu = {}
            vcpus_max = self.xend_domain_instance.info['VCPUs_max']
            for i in range(0, vcpus_max):
                info = xc.vcpu_getinfo(domid, i)
                vcpus_cpu[i] = info['cpu']
            return vcpus_cpu
        else:
            return {}

    def get_VCPUs_flags(self):
        domid = self.xend_domain_instance.getDomid()
        if domid is not None:
            vcpus_flags = {}
            vcpus_max = self.xend_domain_instance.info['VCPUs_max']
            for i in range(0, vcpus_max):
                info = xc.vcpu_getinfo(domid, i)
                flags = []
                def set_flag(flag):
                    if info[flag] == 1:
                        flags.append(flag)
                set_flag('blocked')
                set_flag('online')
                set_flag('running')
                vcpus_flags[i] = flags
            return vcpus_flags
        else:
            return {}

    def get_state(self):
        try:
            domid = self.xend_domain_instance.getDomid()
            domlist = xc.domain_getinfo(domid, 1)
            if domlist and domid == domlist[0]['domid']:
                dominfo = domlist[0]

                states = []
                def addState(key):
                    if dominfo[key] == 1:
                        states.append(key)

                addState("running")
                addState("blocked")
                addState("paused")
                addState("dying")
                addState("crashed")
                addState("shutdown")
                return states
        except Exception, err:
            # ignore missing domain
            log.trace("domain_getinfo(%d) failed, ignoring: %s", domid, str(err))
        return ""

    def get_VCPUs_params(self):
        domid = self.xend_domain_instance.getDomid()
        if domid is not None:
            params_live = {}
            vcpus_max = self.xend_domain_instance.info['VCPUs_max']
            for i in range(0, vcpus_max):
                info = xc.vcpu_getinfo(domid, i)
                params_live['cpumap%i' % i] = \
                    ",".join(map(str, info['cpumap']))

            params_live.update(xc.sched_credit_domain_get(domid))
            
            return params_live
        else:
            return {}

    def get_start_time(self):
        import xen.xend.XendAPI as XendAPI
        return XendAPI.datetime(
            self.xend_domain_instance.info.get("start_time", 0))
    
    def get_last_updated(self):
        import xen.xend.XendAPI as XendAPI
        return XendAPI.now()
