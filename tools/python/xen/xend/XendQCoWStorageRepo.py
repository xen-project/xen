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
# Copyright (C) 2006,2007 XenSource Ltd.
#============================================================================
#
# The default QCOW Xen API Storage Repository
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
import uuid
from XendPBD import XendPBD
from XendError import XendError
from XendVDI import *
from XendTask import XendTask
from XendStorageRepository import XendStorageRepository
from XendOptions import instance as xendoptions

XEND_STORAGE_NO_MAXIMUM = sys.maxint
XEND_STORAGE_QCOW_FILENAME = "%s.qcow"
XEND_STORAGE_VDICFG_FILENAME = "%s.vdi.xml"
QCOW_CREATE_COMMAND = "/usr/sbin/qcow-create -r %d %s"

MB = 1024 * 1024

log = logging.getLogger("xend.XendQCowStorageRepo")


def qcow_virtual_size(qcow_file):
    """Read the first 32 bytes of the QCoW header to determine its size.

    See: http://www.gnome.org/~markmc/qcow-image-format.html.
    """
    try:
        qcow_header = open(qcow_file, 'rb').read(32)
        parts = struct.unpack('>IIQIIQ', qcow_header)
        return parts[-1]
    except IOError:
        return -1

class XendQCoWStorageRepo(XendStorageRepository):
    """A simple file backed QCOW Storage Repository.

    This class exposes the interface to create VDI's via the
    Xen API. The backend is a file-backed QCOW format that is stored
    in XEND_STORAGE_DIR or any that is specified in the constructor.

    The actual images are created in the format <uuid>.img and <uuid>.qcow.
    """
    
    def __init__(self, sr_uuid,
                 sr_type = "qcow_file",
                 name_label = "QCoW",
                 name_description = "Xend QCoW Storage Repository",
                 storage_max = XEND_STORAGE_NO_MAXIMUM):
        """
        @keyword storage_max: Maximum disk space to use in bytes.
        @type    storage_max: int

        @ivar    storage_free: storage space free for this repository
        @ivar    images: mapping of all the images.
        @type    images: dictionary by image uuid.
        @ivar    lock:   lock to provide thread safety.
        """

        XendStorageRepository.__init__(self, sr_uuid, sr_type, name_label,
                                       name_description, storage_max)
        self.storage_free = 0
        self.location = xendoptions().get_xend_storage_path()
        self._refresh()

    def get_record(self, transient = True):
        retval = {'uuid': self.uuid,
                  'name_label': self.name_label,
                  'name_description': self.name_description,
                  'virtual_allocation': self.virtual_allocation,
                  'physical_utilisation': self.physical_utilisation,
                  'physical_size': self.physical_size,
                  'type': self.type,
                  'content_type': self.content_type,
                  'VDIs': self.images.keys(),
                  'PBDs': XendPBD.get_by_SR(self.uuid)}
        
        if self.physical_size == XEND_STORAGE_NO_MAXIMUM:
            stfs = os.statvfs(self.location)
            retval['physical_size'] = stfs.f_blocks * stfs.f_frsize

        return retval
        
    def _refresh(self):
        """Internal function that refreshes the state of the disk and
        updates the list of images available.
        """
        self.lock.acquire()
        try:
            mkdir.parents(self.location, stat.S_IRWXU)

            # scan the directory and populate self.images
            virtual_alloc = 0
            physical_used = 0
            seen_images = []
            for filename in os.listdir(self.location):
                if filename[-5:] == XEND_STORAGE_QCOW_FILENAME[-5:]:
                    image_uuid = filename[:-5]
                    seen_images.append(image_uuid)

                    qcow_file = XEND_STORAGE_QCOW_FILENAME % image_uuid
                    cfg_file = XEND_STORAGE_VDICFG_FILENAME % image_uuid
                    qcow_path = os.path.join(self.location, qcow_file)
                    cfg_path = os.path.join(self.location, cfg_file)
                    
                    phys_size = os.stat(qcow_path).st_size
                    virt_size = qcow_virtual_size(qcow_path)
                    
                    # add this image if we haven't seen it before
                    if image_uuid not in self.images:
                        vdi = XendQCoWVDI(image_uuid, self.uuid,
                                          qcow_path, cfg_path,
                                          virt_size, phys_size)
                        
                        if cfg_path and os.path.exists(cfg_path):
                            try:
                                vdi.load_config(cfg_path)
                            except:
                                log.error('Corrupt VDI configuration file %s' %
                                          cfg_path)
                        
                        self.images[image_uuid] = vdi

                    physical_used += phys_size
                    virtual_alloc += virt_size

            # remove images that aren't valid
            for image_uuid in self.images.keys():
                if image_uuid not in seen_images:
                    try:
                        os.unlink(self.images[image_uuid].qcow_path)
                    except OSError:
                        pass
                    del self.images[image_uuid]

            self.virtual_allocation = virtual_alloc
            self.physical_utilisation = physical_used

            # update free storage if we have to track that
            if self.physical_size == XEND_STORAGE_NO_MAXIMUM:
                self.storage_free = self._get_free_space()
            else:
                self.storage_free = self.physical_size - self.virtual_allocation
                        
        finally:
            self.lock.release()

    def _get_free_space(self):
        """Returns the amount of free space in bytes available in the storage
        partition. Note that this may not be used if the storage repository
        is initialised with a maximum size in storage_max.

        @rtype: int
        """
        stfs = os.statvfs(self.location)
        return stfs.f_bavail * stfs.f_frsize

    def _has_space_available_for(self, size_bytes):
        """Returns whether there is enough space for an image in the
        partition which the storage_dir resides on.

        @rtype: bool
        """
        if self.physical_size != XEND_STORAGE_NO_MAXIMUM:
            return self.storage_free > size_bytes
        
        bytes_free = self._get_free_space()
        if size_bytes < bytes_free:
            return True
        return False

    def _create_image_files(self, desired_size_bytes):
        """Create an image and return its assigned UUID.

        @param desired_size_bytes: Desired image size in bytes
        @type  desired_size_bytes: int
        @rtype: string
        @return: uuid

        @raises XendError: If an error occurs.
        """
        self.lock.acquire()
        try:
            if not self._has_space_available_for(desired_size_bytes):
                raise XendError("Not enough space (need %d)" %
                                desired_size_bytes)

            image_uuid = uuid.createString()
            qcow_path = os.path.join(self.location,
                                     XEND_STORAGE_QCOW_FILENAME % image_uuid)
            
            if qcow_path and os.path.exists(qcow_path):
                raise XendError("Image with same UUID alreaady exists:" %
                                image_uuid)
            
            cmd = QCOW_CREATE_COMMAND % (desired_size_bytes/MB, qcow_path)
            rc, output = commands.getstatusoutput(cmd)
            
            if rc != 0:
                # cleanup the image file
                os.unlink(qcow_path)
                raise XendError("Failed to create QCOW Image: %s" % output)

            self._refresh()
            return image_uuid
        finally:
            self.lock.release()

    def destroy_vdi(self, image_uuid):
        """Destroy an image that is managed by this storage repository.

        @param image_uuid: Image UUID
        @type  image_uuid: String
        @rtype: String
        """
        self.lock.acquire()
        try:
            if image_uuid in self.images:
                # TODO: check if it is being used?
                qcow_path = self.images[image_uuid].qcow_path
                cfg_path = self.images[image_uuid].cfg_path
                try:
                    os.unlink(qcow_path)
                    if cfg_path and os.path.exists(cfg_path):
                        os.unlink(cfg_path)
                except OSError:
                    log.exception("Failed to destroy image")
                del self.images[image_uuid]
                self._refresh()
                return True
        finally:
            self.lock.release()
        
        return False

    def free_space_bytes(self):
        """Returns the amount of available space in KB.
        @rtype: int
        """
        self.lock.acquire()
        try:
            return self.storage_free
        finally:
            self.lock.release()
            
    def total_space_bytes(self):
        """Returns the total usable space of the storage repo in KB.
        @rtype: int
        """
        self.lock.acquire()
        try:
            if self.physical_size == XEND_STORAGE_NO_MAXIMUM:
                stfs = os.statvfs(self.location)
                return stfs.f_blocks * stfs.f_frsize
            else:
                return self.physical_size
        finally:
            self.lock.release()
            
    def used_space_bytes(self):
        """Returns the total amount of space used by this storage repository.
        @rtype: int
        """
        self.lock.acquire()
        try:
            return self.physical_utilisation
        finally:
            self.lock.release()

    def virtual_allocation(self):
        """Returns the total virtual space allocated within the storage repo.
        @rtype: int
        """
        self.lock.acquire()
        try:
            return self.virtual_allocation
        finally:
            self.lock.release()


    def create_vdi(self, vdi_struct):
        image_uuid = None
        try:
            size_bytes = int(vdi_struct.get('virtual_size', 0))

            image_uuid = self._create_image_files(size_bytes)
            
            image = self.images[image_uuid]
            image_cfg = {
                'virtual_size': size_bytes,
                'type': vdi_struct.get('type', 'system'),
                'name_label': vdi_struct.get('name_label', ''),
                'name_description': vdi_struct.get('name_description', ''),
                'sharable': bool(vdi_struct.get('sharable', False)),
                'read_only': bool(vdi_struct.get('read_only', False)),
            }

            # load in configuration from vdi_struct
            image.load_config_dict(image_cfg)

            # save configuration to file
            cfg_filename =  XEND_STORAGE_VDICFG_FILENAME % image_uuid
            cfg_path = os.path.join(self.location, cfg_filename)
            image.save_config(cfg_path)
            
        except Exception, e:
            # cleanup before raising exception
            if image_uuid:
                self.destroy_vdi(image_uuid)
                
            raise

        return image_uuid
