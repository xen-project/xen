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
# Copyright (c) 2008 NEC Corporation
#       Yosuke Iwamatsu <y-iwamatsu at ab jp nec com>
#============================================================================

from xen.xend.XendBase import XendBase
from xen.xend.XendBase import XendAPIStore
from xen.xend import uuid as genuuid

from xen.util.pci import parse_hex

class XendPPCI(XendBase):
    """Representation of a physical PCI device."""

    def getClass(self):
        return "PPCI"

    def getAttrRO(self):
        attrRO = ['host',
                  'domain',
                  'bus',
                  'slot',
                  'func',
                  'name',
                  'vendor_id',
                  'vendor_name',
                  'device_id',
                  'device_name',
                  'revision_id',
                  'class_code',
                  'class_name',
                  'subsystem_vendor_id',
                  'subsystem_vendor_name',
                  'subsystem_id',
                  'subsystem_name',
                  'driver']
        return XendBase.getAttrRO() + attrRO

    def getAttrRW(self):
        attrRW = []
        return XendBase.getAttrRW() + attrRW

    def getAttrInst(self):
        attrInst = []
        return XendBase.getAttrInst() + attrInst

    def getMethods(self):
        methods = []
        return XendBase.getMethods() + methods

    def getFuncs(self):
        funcs = []
        return XendBase.getFuncs() + funcs

    getClass    = classmethod(getClass)
    getAttrRO   = classmethod(getAttrRO)
    getAttrRW   = classmethod(getAttrRW)
    getAttrInst = classmethod(getAttrInst)
    getMethods  = classmethod(getMethods)
    getFuncs    = classmethod(getFuncs)
 
    def get_by_sbdf(self, domain, bus, slot, func):
        for ppci in XendAPIStore.get_all("PPCI"):
            if ppci.get_domain() == parse_hex(domain) and \
               ppci.get_bus() == parse_hex(bus) and \
               ppci.get_slot() == parse_hex(slot) and \
               ppci.get_func() == parse_hex(func):
                return ppci.get_uuid()
        return None

    get_by_sbdf = classmethod(get_by_sbdf)

    def __init__(self, uuid, record):
        self.domain = record['domain']
        self.bus = record['bus']
        self.slot = record['slot']
        self.func = record['func']
        self.vendor_id = record['vendor_id']
        self.vendor_name = record['vendor_name']
        self.device_id = record['device_id']
        self.device_name = record['device_name']
        self.revision_id = record['revision_id']
        self.class_code = record['class_code']
        self.class_name = record['class_name']
        self.subsystem_vendor_id = record['subsystem_vendor_id']
        self.subsystem_vendor_name = record['subsystem_vendor_name']
        self.subsystem_id = record['subsystem_id']
        self.subsystem_name = record['subsystem_name']
        self.driver = record['driver']
        XendBase.__init__(self, uuid, record)

    def get_host(self):
        from xen.xend import XendNode
        return XendNode.instance().get_uuid()

    def get_domain(self):
        return self.domain

    def get_bus(self):
        return self.bus

    def get_slot(self):
        return self.slot

    def get_func(self):
        return self.func

    def get_name(self):
        return "%04x:%02x:%02x.%01x" % (self.domain, self.bus, self.slot,
                                        self.func)

    def get_vendor_id(self):
        return self.vendor_id

    def get_vendor_name(self):
        return self.vendor_name

    def get_device_id(self):
        return self.device_id

    def get_device_name(self):
        return self.device_name

    def get_class_code(self):
        return self.class_code

    def get_class_name(self):
        return self.class_name

    def get_revision_id(self):
        return self.revision_id

    def get_subsystem_vendor_id(self):
        return self.subsystem_vendor_id

    def get_subsystem_vendor_name(self):
        return self.subsystem_vendor_name

    def get_subsystem_id(self):
        return self.subsystem_id

    def get_subsystem_name(self):
        return self.subsystem_name

    def get_driver(self):
        return self.driver

