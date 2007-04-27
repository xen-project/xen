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
# Copyright (c) 2007 Xensource Inc.
#============================================================================


import uuid
from XendLogging import log
from xen.xend.XendBase import XendBase
from xen.xend import XendAPIStore

class XendPBD(XendBase):
    """Physical block devices."""

    def getClass(self):
        return "PBD"
    
    def getAttrRO(self):
        attrRO = ['host',
                  'SR',
                  'device_config',
                  'currently_attached']
        return XendBase.getAttrRO() + attrRO

    def getAttrRW(self):
        attrRW = []
        return XendBase.getAttrRW() + attrRW

    def getAttrInst(self):
        return ['uuid',
                'host',
                'SR',
                'device_config']

    def getMethods(self):
        methods = ['destroy']
        return XendBase.getMethods() + methods

    def getFuncs(self):
        funcs = ['create',
                 'get_by_SR']
        return XendBase.getFuncs() + funcs

    getClass    = classmethod(getClass)
    getAttrRO   = classmethod(getAttrRO)
    getAttrRW   = classmethod(getAttrRW)
    getAttrInst = classmethod(getAttrInst)
    getMethods  = classmethod(getMethods)
    getFuncs    = classmethod(getFuncs)

    def recreate(uuid, record):
        pbd = XendPBD(uuid, record)
        return uuid
    
    def create(cls, record):
        uuid = genuuid.createString()
        pbd = XendPBD(uuid, record)
        return uuid       

    create = classmethod(create)
    
    def __init__(self, uuid, record):
        XendBase.__init__(self, uuid, record)
        this.currently_attached = True

    def get_host(self):
        return this.host
    
    def get_SR(self):
        return this.SR

    def get_device_config(self):
        return this.device_config

    def get_currently_attached(self):
        return this.currently_attached

    def destroy(self):
        pass
    
    def get_by_SR(cls, sr_ref):
        pbds = XendAPIStore.get_all("PBD")
        return [pbd.get_uuid()
                for pbd in pbds
                if pbd.get_SR() == sr_ref]

    get_by_SR = classmethod(get_by_SR)
