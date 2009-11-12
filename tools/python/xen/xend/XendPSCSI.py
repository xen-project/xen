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
from xen.xend.XendBase import XendAPIStore
from xen.xend import uuid as genuuid

class XendPSCSI(XendBase):
    """Representation of a physical SCSI device."""

    def getClass(self):
        return "PSCSI"

    def getAttrRO(self):
        attrRO = ['host',
                  'physical_host',
                  'physical_channel',
                  'physical_target',
                  'physical_lun',
                  'physical_HCTL',
                  'HBA',
                  'vendor_name',
                  'model',
                  'type_id',
                  'type',
                  'dev_name',
                  'sg_name',
                  'revision',
                  'scsi_id',
                  'scsi_level']
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
 
    def get_by_HCTL(self, physical_HCTL):
        for pscsi in XendAPIStore.get_all("PSCSI"):
            if pscsi.get_physical_HCTL() == physical_HCTL:
                return pscsi.get_uuid()
        return None

    get_by_HCTL = classmethod(get_by_HCTL)

    def __init__(self, uuid, record):
        self.physical_HCTL = record['physical_HCTL']
        self.physical_HBA = record['HBA']
        self.vendor_name = record['vendor_name']
        self.model = record['model']
        self.type_id = record['type_id']
        self.type = record['type']
        self.dev_name = record['dev_name']
        self.sg_name = record['sg_name']
        self.revision = record['revision']
        self.scsi_id = record['scsi_id']
        self.scsi_level = record['scsi_level']

        p_hctl = self.physical_HCTL.split(':')
        self.physical_host = int(p_hctl[0])
        self.physical_channel = int(p_hctl[1])
        self.physical_target = int(p_hctl[2])
        self.physical_lun = int(p_hctl[3])

        XendBase.__init__(self, uuid, record)

    def get_host(self):
        from xen.xend import XendNode
        return XendNode.instance().get_uuid()

    def get_physical_host(self):
        return self.physical_host

    def get_physical_channel(self):
        return self.physical_channel

    def get_physical_target(self):
        return self.physical_target

    def get_physical_lun(self):
        return self.physical_lun

    def get_physical_HCTL(self):
        return self.physical_HCTL

    def get_HBA(self):
        return self.physical_HBA

    def get_vendor_name(self):
        return self.vendor_name

    def get_model(self):
        return self.model

    def get_type_id(self):
        return self.type_id

    def get_type(self):
        return self.type

    def get_dev_name(self):
        return self.dev_name

    def get_sg_name(self):
        return self.sg_name

    def get_revision(self):
        return self.revision

    def get_scsi_id(self):
        return self.scsi_id

    def get_scsi_level(self):
        return self.scsi_level


class XendPSCSI_HBA(XendBase):
    """Representation of a physical SCSI HBA."""

    def getClass(self):
        return "PSCSI_HBA"

    def getAttrRO(self):
        attrRO = ['host',
                  'physical_host',
                  'PSCSIs']
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
 
    def get_by_physical_host(self, physical_host):
        for pscsi_HBA in XendAPIStore.get_all('PSCSI_HBA'):
            if pscsi_HBA.get_physical_host() == physical_host:
                return pscsi_HBA.get_uuid()
        return None

    get_by_physical_host = classmethod(get_by_physical_host)

    def __init__(self, uuid, record):
        self.physical_host = record['physical_host']
        XendBase.__init__(self, uuid, record)

    def get_host(self):
        from xen.xend import XendNode
        return XendNode.instance().get_uuid()

    def get_physical_host(self):
        return self.physical_host

    def get_PSCSIs(self):
        PSCSIs = []
        uuid = self.get_uuid()
        for pscsi in XendAPIStore.get_all('PSCSI'):
            if pscsi.get_HBA() == uuid:
                PSCSIs.append(pscsi.get_uuid())
        return PSCSIs

