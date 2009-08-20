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
# Copyright (C) 2006, 2007 XenSource Ltd.
#============================================================================
#
# Abstract class for XendStorageRepositories
#

import threading
import sys

from XendError import XendError
from XendVDI import *
from XendPBD import XendPBD

XEND_STORAGE_NO_MAXIMUM = sys.maxint

class XendStorageRepository:
    """ Base class for Storage Repos. """

    def __init__(self, uuid,
                 sr_type = "unknown",
                 name_label = 'Unknown',
                 name_description = 'Not Implemented',
                 storage_max = XEND_STORAGE_NO_MAXIMUM):
        """
        @keyword storage_max: Maximum disk space to use in bytes.
        @type    storage_max: int

        @ivar    storage_free: storage space free for this repository
        @ivar    images: mapping of all the images.
        @type    images: dictionary by image uuid.
        @ivar    lock:   lock to provide thread safety.
        """

        # XenAPI Parameters
        self.uuid = uuid
        self.type = sr_type
        self.name_label = name_label
        self.name_description = name_description
        self.images = {}

        self.physical_size = storage_max
        self.physical_utilisation = 0
        self.virtual_allocation = 0
        self.content_type = ''
 
        self.lock = threading.RLock()

    def get_record(self, transient = True):
        retval = {'uuid': self.uuid,
                  'name_label': self.name_label,
                  'name_description': self.name_description,
                  'virtual_allocation': self.virtual_allocation,
                  'physical_utilisation': self.physical_utilisation,
                  'physical_size': self.physical_size,
                  'type': self.type,
                  'content_type': self.content_type,
                  'VDIs': self.images.keys()}
        if not transient:
            retval ['PBDs'] = XendPBD.get_by_SR(self.uuid)
        return retval


    def is_valid_vdi(self, vdi_uuid):
        return (vdi_uuid in self.images)

    def get_vdi_by_uuid(self, image_uuid):
        self.lock.acquire()
        try:
            return self.images.get(image_uuid)
        finally:
            self.lock.release()

    def get_vdi_by_name_label(self, label):
        self.lock.acquire()
        try:
            for image_uuid, image in self.images.items():
                if image.name_label == label:
                    return image_uuid
            return None
        finally:
            self.lock.release()

    def get_vdis(self):
        return self.images.keys()

    def create_vdi(self, vdi_struct):
        raise NotImplementedError()

    def destroy_vdi(self, vdi_struct):
        raise NotImplementedError()

    def list_images(self):
        """ List all the available images by UUID.

        @rtype: list of strings.
        @return: list of UUIDs
        """
        self.lock.acquire()
        try:
            return self.images.keys()
        finally:
            self.lock.release()

