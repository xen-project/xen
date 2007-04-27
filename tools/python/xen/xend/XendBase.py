#!/usr/bin/python
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
# Copyright (C) 2007 Tom Wilkie <tom.wilkie@gmail.com>
#============================================================================
"""
Base class for all XenAPI classes
"""

from xen.xend.XendError import *
from xen.xend import XendAPIStore

class XendBase:
    #
    # These functions describe the object, and what is exposed via the API
    #
    def getClass(self):
        return "Base"
    
    def getAttrRO(self):
        return ['uuid']

    def getAttrRW(self):
        return []

    def getAttrInst(self):
        return []

    def getMethods(self):
        return ["get_record"]

    def getFuncs(self):
        return ["get_all", "get_by_uuid", "get_all_records"]

    getClass    = classmethod(getClass)
    getAttrRO   = classmethod(getAttrRO)
    getAttrRW   = classmethod(getAttrRW)
    getAttrInst = classmethod(getAttrInst)
    getMethods  = classmethod(getMethods)
    getFuncs    = classmethod(getFuncs)
    
    def __init__(self, uuid, record):
        self.__uuid = uuid
        
        # First check this class implements all the correct methods:
        for attr_ro in self.getAttrRO() + self.getAttrRW():
            if not hasattr(self, "get_%s" % attr_ro):
                raise ImplementationError(self.getClass(),
                                          "get_%s" % attr_ro)

        for attr_rw in self.getAttrRW():
            if not hasattr(self, "set_%s" % attr_rw):
                raise ImplementationError(self.getClass(),
                                          "set_%s" % attr_rw)

        for method in self.getMethods():
            if not hasattr(self, method):
                raise ImplementationError(self.getClass(),
                                          method)

        for func in self.getFuncs():
            if not hasattr(self.__class__, func):
                raise ImplementationError(self.getClass(),
                                          func)

        # Next check that the class is being created with the correct
        # parameters
        if not isinstance(record, dict):
            raise CreateUnspecifiedAttributeError(
                    "record" , self.getClass())
        
        for attr_inst in self.getAttrInst():
            if attr_inst not in record:
                raise CreateUnspecifiedAttributeError(
                    attr_inst, self.getClass())
            setattr(self, attr_inst, record[attr_inst])

        # Finally register it
        XendAPIStore.register(uuid, self.getClass(), self)

    def destroy(self):
        XendAPIStore.deregister(self.get_uuid(), self.getClass())

    def get_uuid(self):
        return self.__uuid

    def get_record(self):
        keys = self.getAttrRO() + self.getAttrRW()
        return dict([(key, getattr(self, "get_%s" % key)())
                     for key in keys])

    #
    # Class methods
    #

    def get_all(cls):
        return XendAPIStore.get_all_uuid(cls.getClass())

    def get_by_uuid(cls, uuid):
        # Sanity check the uuid is one of us
        me = XendAPIStore.get(uuid, cls.getClass())
        if me is not None and me.getClass() == cls.getClass():
            # In OSS, ref == uuid
            return uuid
        else:
            raise "Big Error.. TODO!"

    def get_all_records(cls):
        return dict([(inst.get_uuid(), inst.get_record())
                     for inst in XendAPIStore.get_all(cls.getClass())])

    get_all = classmethod(get_all)
    get_by_uuid = classmethod(get_by_uuid)
    get_all_records = classmethod(get_all_records)
