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
# Copyright (C) 2007 XenSource Ltd.
#============================================================================
#
# A pseudo-StorageRepository to provide a representation for the images
# that can be specified by xm.
#

import commands
import logging
import os
import stat
import threading
import re
import sys
import struct

from xen.util import mkdir
from xen.xend import uuid
from xen.xend.XendError import XendError
from xen.xend.XendVDI import *
from xen.xend.XendTask import XendTask
from xen.xend.XendStorageRepository import XendStorageRepository
from xen.xend.XendStateStore import XendStateStore
from xen.xend.XendOptions import instance as xendoptions

MB = 1024 * 1024

log = logging.getLogger("xend.XendLocalStorageRepo")

class XendLocalStorageRepo(XendStorageRepository):
    """A backwards compatibility storage repository so that
    traditional file:/dir/file.img and phy:/dev/hdxx images can
    still be represented in terms of the Xen API.
    """
    
    def __init__(self, sr_uuid, sr_type = 'local',
                 name_label = 'Local',
                 name_description = 'Traditional Local Storage Repo'):
        """
        @ivar    images: mapping of all the images.
        @type    images: dictionary by image uuid.
        @ivar    lock:   lock to provide thread safety.
        """

        XendStorageRepository.__init__(self, sr_uuid, sr_type,
                                       name_label, name_description,
                                       '/')
        
        self.state = XendStateStore(xendoptions().get_xend_state_path()
                                    + '/local_sr')

        stored_images = self.state.load_state('vdi')
        if stored_images:
            for image_uuid, image in stored_images.items():
                self.images[image_uuid] = XendLocalVDI(image)

    def create_vdi(self, vdi_struct):
        """ Creates a fake VDI image for a traditional image string.

        The image uri is stored in the attribute 'uri'
        """
        vdi_struct['uuid'] = uuid.createString()
        vdi_struct['SR'] = self.uuid
        new_image =  XendLocalVDI(vdi_struct)
        self.images[new_image.uuid] = new_image
        self.save_state()
        return new_image.uuid

    def save_state(self):
        vdi_records = dict([(k, v.get_record(transient = False))
                            for k, v in self.images.items()])
        self.state.save_state('vdi', vdi_records)

    def destroy_vdi(self, vdi_uuid):
        if vdi_uuid in self.images:
            del self.images[vdi_uuid]

        self.save_state()

