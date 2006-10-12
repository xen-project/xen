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
# Copyright (C) 2006 XenSource Ltd.
#============================================================================
#
# Representation of a Xen API VDI
#

KB = 1024
MB = 1024 * 1024

class XendVDI:
    def __init__(self, uuid, sr_uuid):
        self.uuid = uuid
        self.sr_uuid = sr_uuid

class XendQCOWVDI(XendVDI):
    vdi_type = "system"

    def __init__(self, uuid, sr_uuid, qcow_path, image_path, vsize, psize):
        XendVDI.__init__(self, uuid, sr_uuid)
        self.qcow_path = qcow_path
        self.image_path = image_path
        self.vsize = vsize
        self.psize = psize

    def get_physical_utilisation(self):
        return self.psize * KB

    def get_virtual_size(self):
        return self.vsize * KB
