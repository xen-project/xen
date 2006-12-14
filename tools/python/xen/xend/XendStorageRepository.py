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
# The default QCOW Xen API Storage Repository
#

import commands
import logging
import os
import stat
import threading

from xen.util import mkdir
from xen.xend import uuid
from xen.xend.XendError import XendError
from xen.xend.XendVDI import *

XEND_STORAGE_MAX_IGNORE = -1
XEND_STORAGE_DIR = "/var/lib/xend/storage/"
XEND_STORAGE_QCOW_FILENAME = "%s.qcow"
XEND_STORAGE_VDICFG_FILENAME = "%s.vdi.xml"
QCOW_CREATE_COMMAND = "/usr/sbin/qcow-create %d %s"

MB = 1024 * 1024

log = logging.getLogger("xend.XendStorageRepository")


class DeviceInvalidError(Exception):
    pass

class XendStorageRepository:
    """A simple file backed QCOW Storage Repository.

    This class exposes the interface to create VDI's via the
    Xen API. The backend is a file-backed QCOW format that is stored
    in XEND_STORAGE_DIR or any that is specified in the constructor.

    The actual images are created in the format <uuid>.img and <uuid>.qcow.
    """
    
    def __init__(self, storage_dir = XEND_STORAGE_DIR,
                 storage_max = XEND_STORAGE_MAX_IGNORE):
        """
        @keyword storage_dir: Where the images will be stored.
        @type    storage_dir: string
        @keyword storage_max: Maximum disk space to use in bytes.
        @type    storage_max: int

        @ivar    storage_free: storage space free for this repository
        @ivar    images: mapping of all the images.
        @type    images: dictionary by image uuid.
        @ivar    lock:   lock to provide thread safety.
        """
        
        self.storage_dir = storage_dir
        self.storage_max = storage_max
        self.storage_free = 0
        self.images = {}

        # XenAPI Parameters
        self.uuid = self._sr_uuid()
        self.type = "qcow-file"
        self.location = self.storage_dir
        self.name_label = "Local"
        self.name_description = "Xend Storage Repository"

        self.lock = threading.RLock()
        self._refresh()        

    def _sr_uuid(self):
        uuid_file = os.path.join(XEND_STORAGE_DIR, 'uuid')
        try:
            if uuid_file and os.path.exists(uuid_file):
                return open(uuid_file, 'r').read().strip()
            else:
                new_uuid = uuid.createString()
                open(uuid_file, 'w').write(new_uuid + '\n')
                return new_uuid
        except IOError:
            log.exception("Failed to determine SR UUID")

        return uuid.createString()

    def _refresh(self):
        """Internal function that refreshes the state of the disk and
        updates the list of images available.
        """
        self.lock.acquire()
        try:
            mkdir.parents(XEND_STORAGE_DIR, stat.S_IRWXU)

            # scan the directory and populate self.images
            total_used = 0
            seen_images = []
            for filename in os.listdir(XEND_STORAGE_DIR):
                if filename[-5:] == XEND_STORAGE_QCOW_FILENAME[-5:]:
                    image_uuid = filename[:-5]
                    seen_images.append(image_uuid)
                    
                    # add this image if we haven't seen it before
                    if image_uuid not in self.images:
                        qcow_file = XEND_STORAGE_QCOW_FILENAME % image_uuid
                        cfg_file = XEND_STORAGE_VDICFG_FILENAME % image_uuid
                        qcow_path = os.path.join(XEND_STORAGE_DIR, qcow_file)
                        cfg_path = os.path.join(XEND_STORAGE_DIR, cfg_file)

                        qcow_size = os.stat(qcow_path).st_size

                        # TODO: no way to stat virtual size of qcow
                        vdi = XendQCOWVDI(image_uuid, self.uuid,
                                          qcow_path, cfg_path,
                                          qcow_size, qcow_size) 
                        
                        if cfg_path and os.path.exists(cfg_path):
                            vdi.load_config(cfg_path)
                        
                        self.images[image_uuid] = vdi
                        total_used += qcow_size

            # remove images that aren't valid
            for image_uuid in self.images.keys():
                if image_uuid not in seen_images:
                    try:
                        os.unlink(self.images[image_uuid].qcow_path)
                    except OSError:
                        pass
                    del self.images[image_uuid]

            # update free storage if we have to track that
            if self.storage_max != XEND_STORAGE_MAX_IGNORE:
                self.storage_free = self.storage_max - total_used
            else:
                self.storage_free = self._get_free_space()
                        
        finally:
            self.lock.release()

    def _get_free_space(self):
        """Returns the amount of free space in bytes available in the storage
        partition. Note that this may not be used if the storage repository
        is initialised with a maximum size in storage_max.

        @rtype: int
        """
        stfs = os.statvfs(self.storage_dir)
        return stfs.f_bavail * stfs.f_frsize

    def _has_space_available_for(self, size_bytes):
        """Returns whether there is enough space for an image in the
        partition which the storage_dir resides on.

        @rtype: bool
        """
        if self.storage_max != -1:
            return self.storage_free
        
        bytes_free = self._get_free_space()
        try:
            if size_bytes < bytes_free:
                return True
        except DeviceInvalidError:
            pass
        return False

    def _create_image_files(self, desired_size_bytes):
        """Create an image and return its assigned UUID.

        @param desired_size_kb: Desired image size in KB.
        @type  desired_size_kb: int
        @rtype: string
        @return: uuid

        @raises XendError: If an error occurs.
        """
        self.lock.acquire()
        try:
            if not self._has_space_available_for(desired_size_bytes):
                raise XendError("Not enough space")

            image_uuid = uuid.createString()
            qcow_path = os.path.join(XEND_STORAGE_DIR,
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

    def destroy_image(self, image_uuid):
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
                return True
        finally:
            self.lock.release()
        
        return False

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
            if self.storage_max != XEND_STORAGE_MAX_IGNORE:
                return self.storage_max
            else:
                return self.free_space_bytes() + self.used_space_bytes()
        finally:
            self.lock.release()
            
    def used_space_bytes(self):
        """Returns the total amount of space used by this storage repository.
        @rtype: int
        """
        self.lock.acquire()
        try:
            total_used = 0
            for val in self.images.values():
                total_used += val.physical_utilisation
            return total_used
        finally:
            self.lock.release()

    def is_valid_vdi(self, vdi_uuid):
        return (vdi_uuid in self.images)

    def create_image(self, vdi_struct):
        image_uuid = None
        try:
            sector_count = int(vdi_struct.get('virtual_size', 0))
            sector_size = int(vdi_struct.get('sector_size', 1024))
            size_bytes = (sector_count * sector_size)
            
            image_uuid = self._create_image_files(size_bytes)
            image = self.images[image_uuid]
            image_cfg = {
                'sector_size': sector_size,
                'virtual_size': sector_count,
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
            cfg_path = os.path.join(XEND_STORAGE_DIR, cfg_filename)
            image.save_config(cfg_path)
            
        except Exception, e:
            # cleanup before raising exception
            if image_uuid:
                self.destroy_image(image_uuid)
                
            raise

        return image_uuid
        
    def xen_api_get_by_label(self, label):
        self.lock.acquire()
        try:
            for image_uuid, val in self.images.values():
                if val.name_label == label:
                    return image_uuid
            return None
        finally:
            self.lock.release()

    def xen_api_get_by_uuid(self, image_uuid):
        self.lock.acquire()
        try:
            return self.images.get(image_uuid)
        finally:
            self.lock.release()        
    

# remove everything below this line!!
if __name__ == "__main__":
    xsr = XendStorageRepository()
    print 'Free Space: %d MB' % (xsr.free_space_bytes()/MB)
    print "Create Image:",
    print xsr._create_image_files(10 * MB)
    print 'Delete all images:'
    for image_uuid in xsr.list_images():
        print image_uuid,
        xsr._destroy_image_files(image_uuid)

    print
