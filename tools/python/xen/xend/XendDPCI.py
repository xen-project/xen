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
from xen.xend.XendPPCI import XendPPCI
from xen.xend import XendAPIStore
from xen.xend import uuid as genuuid

import XendDomain, XendNode

from XendError import *
from XendTask import XendTask
from XendLogging import log

class XendDPCI(XendBase):
    """Representation of a passthrough PCI device."""

    def getClass(self):
        return "DPCI"

    def getAttrRO(self):
        attrRO = ['virtual_domain',
                  'virtual_bus',
                  'virtual_slot',
                  'virtual_func',
                  'virtual_name',
                  'VM',
                  'PPCI',
                  'hotplug_slot',
                  'key',
                  'options']
        return XendBase.getAttrRO() + attrRO

    def getAttrRW(self):
        attrRW = []
        return XendBase.getAttrRW() + attrRW

    def getAttrInst(self):
        attrInst = ['VM',
                    'PPCI',
                    'hotplug_slot',
                    'key']
        return XendBase.getAttrInst() + attrInst

    def getMethods(self):
        methods = ['destroy']
        return XendBase.getMethods() + methods

    def getFuncs(self):
        funcs = ['create']
        return XendBase.getFuncs() + funcs

    getClass    = classmethod(getClass)
    getAttrRO   = classmethod(getAttrRO)
    getAttrRW   = classmethod(getAttrRW)
    getAttrInst = classmethod(getAttrInst)
    getMethods  = classmethod(getMethods)
    getFuncs    = classmethod(getFuncs)
 
    def create(self, dpci_struct):

        # Check if VM is valid
        xendom = XendDomain.instance()
        if not xendom.is_valid_vm(dpci_struct['VM']):
            raise InvalidHandleError('VM', dpci_struct['VM'])
        dom = xendom.get_vm_by_uuid(dpci_struct['VM'])

        # Check if PPCI is valid
        xennode = XendNode.instance()
        ppci_uuid = xennode.get_ppci_by_uuid(dpci_struct['PPCI'])
        if not ppci_uuid:
            raise InvalidHandleError('PPCI', dpci_struct['PPCI'])
        for existing_dpci in XendAPIStore.get_all('DPCI'):
            if ppci_uuid == existing_dpci.get_PPCI():
                raise DirectPCIError("Device is in use")

        # Assign PPCI to VM
        try:
            dpci_ref = XendTask.log_progress(0, 100, dom.create_dpci,
                                             dpci_struct)
        except XendError, e:
            raise DirectPCIError("Failed to assign device")

        # TODO: Retrive virtual pci device infomation.

        return dpci_ref

    create = classmethod(create)

    def get_by_VM(cls, VM_ref):
        result = []
        for dpci in XendAPIStore.get_all("DPCI"):
            if dpci.get_VM() == VM_ref:
                result.append(dpci.get_uuid())
        return result

    get_by_VM = classmethod(get_by_VM)

    def __init__(self, uuid, record):
        XendBase.__init__(self, uuid, record)

        self.virtual_domain = -1
        self.virtual_bus = -1
        self.virtual_slot = -1
        self.virtual_func = -1

        self.VM = record['VM']
        self.PPCI = record['PPCI']
        self.hotplug_slot = int(record['hotplug_slot'], 16)
        self.key = record['key']
        if 'options' in record.keys():
            self.options = record['options']

    def destroy(self):
        xendom = XendDomain.instance()
        dom = xendom.get_vm_by_uuid(self.get_VM())
        if not dom:
            raise InvalidHandleError("VM", self.get_VM())
        XendTask.log_progress(0, 100, dom.destroy_dpci, self.get_uuid())

    def get_virtual_domain(self):
        return self.virtual_domain

    def get_virtual_bus(self):
        return self.virtual_bus

    def get_virtual_slot(self):
        return self.virtual_slot

    def get_virtual_func(self):
        return self.virtual_func

    def get_virtual_name(self):
        return "%04x:%02x:%02x.%01x" % (self.virtual_domain, self.virtual_bus,
                                        self.virtual_slot, self.virtual_func)

    def get_VM(self):
        return self.VM

    def get_PPCI(self):
        return self.PPCI

    def get_hotplug_slot(self):
        return "%d" % self.hotplug_slot

    def get_key(self):
        return self.key

    def get_options(self):
        return self.options
