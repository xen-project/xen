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
# Copyright FUJITSU LIMITED 2008
#       Masaki Kanno <kanno.masaki@jp.fujitsu.com>
#============================================================================

from xen.xend.XendBase import XendBase
from xen.xend.XendPSCSI import XendPSCSI
from xen.xend import XendAPIStore
from xen.xend import sxp
from xen.xend import uuid as genuuid

import XendDomain, XendNode

from XendError import *
from XendTask import XendTask
from XendLogging import log

class XendDSCSI(XendBase):
    """Representation of a half-virtualized SCSI device."""

    def getClass(self):
        return "DSCSI"

    def getAttrRO(self):
        attrRO = ['VM',
                  'PSCSI',
                  'HBA',
                  'virtual_host',
                  'virtual_channel',
                  'virtual_target',
                  'virtual_lun',
                  'virtual_HCTL',
                  'runtime_properties']
        return XendBase.getAttrRO() + attrRO

    def getAttrRW(self):
        attrRW = []
        return XendBase.getAttrRW() + attrRW

    def getAttrInst(self):
        attrInst = ['VM',
                    'PSCSI',
                    'HBA',
                    'virtual_HCTL']
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
 
    def create(self, dscsi_struct):

        # Check if VM is valid
        xendom = XendDomain.instance()
        if not xendom.is_valid_vm(dscsi_struct['VM']):
            raise InvalidHandleError('VM', dscsi_struct['VM'])
        dom = xendom.get_vm_by_uuid(dscsi_struct['VM'])

        # Check if PSCSI is valid
        xennode = XendNode.instance()
        pscsi_uuid = xennode.get_pscsi_by_uuid(dscsi_struct['PSCSI'])
        if not pscsi_uuid:
            raise InvalidHandleError('PSCSI', dscsi_struct['PSCSI'])

        # Assign PSCSI to VM
        try:
            dscsi_ref = XendTask.log_progress(0, 100, \
                                              dom.create_dscsi, \
                                              dscsi_struct)
        except XendError, e:
            log.exception("Error in create_dscsi")
            raise

        return dscsi_ref

    create = classmethod(create)

    def get_by_VM(cls, VM_ref):
        result = []
        for dscsi in XendAPIStore.get_all("DSCSI"):
            if dscsi.get_VM() == VM_ref:
                result.append(dscsi.get_uuid())
        return result

    get_by_VM = classmethod(get_by_VM)

    def __init__(self, uuid, record):
        XendBase.__init__(self, uuid, record)
        v_hctl = self.virtual_HCTL.split(':')
        self.virtual_host = int(v_hctl[0])
        self.virtual_channel = int(v_hctl[1])
        self.virtual_target = int(v_hctl[2])
        self.virtual_lun = int(v_hctl[3])

    def get_VM(self):
        return self.VM

    def get_PSCSI(self):
        return self.PSCSI

    def get_HBA(self):
        return self.HBA

    def get_virtual_host(self):
        return self.virtual_host

    def get_virtual_channel(self):
        return self.virtual_channel

    def get_virtual_target(self):
        return self.virtual_target

    def get_virtual_lun(self):
        return self.virtual_lun

    def get_virtual_HCTL(self):
        return self.virtual_HCTL

    def get_runtime_properties(self):
        xendom = XendDomain.instance()
        dominfo = xendom.get_vm_by_uuid(self.VM)

        try:
            device_dict = {}
            for device_sxp in dominfo.getDeviceSxprs('vscsi'):
                target_dev = None
                for dev in device_sxp[1][0][1]:
                    vdev = sxp.child_value(dev, 'v-dev')
                    if vdev == self.virtual_HCTL:
                        target_dev = dev
                        break
                if target_dev is None:
                    continue

                dev_dict = {}
                for info in target_dev[1:]:
                    dev_dict[info[0]] = info[1]
                device_dict['dev'] = dev_dict
                for info in device_sxp[1][1:]:
                    device_dict[info[0]] = info[1]

            return device_dict
        except Exception, exn:
            log.exception(exn)
            return {}

    def destroy(self):
        xendom = XendDomain.instance()
        dom = xendom.get_vm_by_uuid(self.get_VM())
        if not dom:
            raise InvalidHandleError("VM", self.get_VM())
        XendTask.log_progress(0, 100, \
                              dom.destroy_dscsi, \
                              self.get_uuid())


class XendDSCSI_HBA(XendBase):
    """Representation of a half-virtualized SCSI HBA."""

    def getClass(self):
        return "DSCSI_HBA"

    def getAttrRO(self):
        attrRO = ['VM',
                  'PSCSI_HBAs',
                  'DSCSIs',
                  'virtual_host',
                  'assignment_mode']
        return XendBase.getAttrRO() + attrRO

    def getAttrRW(self):
        attrRW = []
        return XendBase.getAttrRW() + attrRW

    def getAttrInst(self):
        attrInst = ['VM',
                    'virtual_host',
                    'assignment_mode']
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
 
    def create(self, dscsi_HBA_struct):

        # Check if VM is valid
        xendom = XendDomain.instance()
        if not xendom.is_valid_vm(dscsi_HBA_struct['VM']):
            raise InvalidHandleError('VM', dscsi_HBA_struct['VM'])
        dom = xendom.get_vm_by_uuid(dscsi_HBA_struct['VM'])

        # Check if PSCSI_HBA is valid
        xennode = XendNode.instance()
        pscsi_HBA_uuid = xennode.get_pscsi_HBA_by_uuid(dscsi_HBA_struct['PSCSI_HBA'])
        if not pscsi_HBA_uuid:
            raise InvalidHandleError('PSCSI_HBA', dscsi_HBA_struct['PSCSI_HBA'])

        # Assign PSCSI_HBA and PSCSIs to VM
        try:
            dscsi_HBA_ref = XendTask.log_progress(0, 100, \
                                                  dom.create_dscsi_HBA, \
                                                  dscsi_HBA_struct)
        except XendError, e:
            log.exception("Error in create_dscsi_HBA")
            raise

        return dscsi_HBA_ref

    create = classmethod(create)

    def get_by_VM(cls, VM_ref):
        result = []
        for dscsi_HBA in XendAPIStore.get_all("DSCSI_HBA"):
            if dscsi_HBA.get_VM() == VM_ref:
                result.append(dscsi_HBA.get_uuid())
        return result

    get_by_VM = classmethod(get_by_VM)

    def __init__(self, uuid, record):
        XendBase.__init__(self, uuid, record)
        self.virtual_host = record['virtual_host']
        self.assignment_mode = record['assignment_mode']

    def get_VM(self):
        return self.VM

    def get_PSCSI_HBAs(self):
        PSCSIs = []
        uuid = self.get_uuid()
        for dscsi in XendAPIStore.get_all('DSCSI'):
            if dscsi.get_VM() == self.VM and dscsi.get_HBA() == uuid:
                PSCSIs.append(dscsi.get_PSCSI())
        PSCSI_HBAs = []
        for pscsi_uuid in PSCSIs:
            pscsi_HBA_uuid = XendAPIStore.get(pscsi_uuid, 'PSCSI').get_HBA()
            if not pscsi_HBA_uuid in PSCSI_HBAs:
                PSCSI_HBAs.append(pscsi_HBA_uuid)
        return PSCSI_HBAs

    def get_DSCSIs(self):
        DSCSIs = []
        uuid = self.get_uuid()
        for dscsi in XendAPIStore.get_all('DSCSI'):
            if dscsi.get_VM() == self.VM and dscsi.get_HBA() == uuid:
                DSCSIs.append(dscsi.get_uuid())
        return DSCSIs

    def get_virtual_host(self):
        return self.virtual_host

    def get_assignment_mode(self):
        return self.assignment_mode

    def destroy(self):
        xendom = XendDomain.instance()
        dom = xendom.get_vm_by_uuid(self.get_VM())
        if not dom:
            raise InvalidHandleError("VM", self.get_VM())
        XendTask.log_progress(0, 100, \
                              dom.destroy_dscsi_HBA, \
                              self.get_uuid())

