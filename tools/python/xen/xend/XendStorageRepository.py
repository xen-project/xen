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

import os
import commands
import threading

from xen.xend import uuid
from xen.xend.XendError import XendError
from xen.xend.XendVDI import *

XEND_STORAGE_MAX_IGNORE = -1
XEND_STORAGE_DIR = "/var/lib/xend/storage/"
XEND_STORAGE_QCOW_FILENAME = "%s.qcow"
XEND_STORAGE_IMG_FILENAME = "%s.img"
DF_COMMAND = "df -kl"
QCOW_CREATE_COMMAND = "/usr/sbin/qcow-create %d %s %s"

KB = 1024
MB = 1024 *1024

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
        @keyword storage_max: Maximum disk space to use in KB.
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
            if os.path.exists(uuid_file):
                return open(uuid_file, 'r').read().strip()
            else:
                new_uuid = uuid.createString()
                open(uuid_file, 'w').write(new_uuid + '\n')
                return new_uuid
        except IOError:
            # TODO: log warning
            pass

        return uuid.createString()

    def _refresh(self):
        """Internal function that refreshes the state of the disk and
        updates the list of images available.
        """
        self.lock.acquire()
        try:
            if not os.path.exists(XEND_STORAGE_DIR):
                os.makedirs(XEND_STORAGE_DIR)
                os.chmod(XEND_STORAGE_DIR, 0700)

            # scan the directory and populate self.images
            total_used = 0
            seen_images = []
            for filename in os.listdir(XEND_STORAGE_DIR):
                if filename[-5:] == XEND_STORAGE_QCOW_FILENAME[-5:]:
                    image_uuid = filename[:-5]
                    seen_images.append(image_uuid)
                    if image_uuid not in self.images:
                        image_file = XEND_STORAGE_IMG_FILENAME % image_uuid
                        qcow_file = XEND_STORAGE_QCOW_FILENAME % image_uuid
                        image_path = os.path.join(XEND_STORAGE_DIR,
                                                  image_file)
                        qcow_path = os.path.join(XEND_STORAGE_DIR, qcow_file)
                        image_size_kb = (os.stat(image_path).st_size)/1024

                        vdi = XendQCOWVDI(image_uuid, self.uuid,
                                          qcow_path, image_path,
                                          image_size_kb, image_size_kb)
                        self.images[image_uuid] = vdi
                        total_used += image_size_kb

            # remove images that aren't valid
            for image_uuid in self.images.keys():
                if image_uuid not in seen_images:
                    try:
                        os.unlink(self.images[image_uuid].qcow_path)
                        os.unlink(self.images[image_uuid].image_path)
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

    def _get_df(self):
        """Returns the output of 'df' in a dictionary where the keys
        are the Linux device numbers, and the values are it's corresponding
        free space in KB.

        @rtype: dictionary
        """
        df = commands.getoutput(DF_COMMAND)
        devnum_free = {}
        for line in df.split('\n')[1:]:
            words = line.split()
            mount_point = words[-1]
            dev_no = os.stat(mount_point).st_dev
            free_blks = int(words[3])
            devnum_free[dev_no] = free_blks
        return devnum_free

    def _get_free_space(self):
        """Returns the amount of free space in KB available in the storage
        partition. Note that this may not be used if the storage repository
        is initialised with a maximum size in storage_max.

        @rtype: int
        """
        df = self._get_df()
        devnum = os.stat(self.storage_dir).st_dev
        if df.has_key(devnum):
            return df[devnum]
        raise DeviceInvalidError("Device not found for storage path: %s" %
                                 self.storage_dir)

    def _has_space_available_for(self, size_kb):
        """Returns whether there is enough space for an image in the
        partition which the storage_dir resides on.

        @rtype: bool
        """
        if self.storage_max != -1:
            return self.storage_free
        
        kb_free = self._get_free_space()
        try:
            if size_kb < kb_free:
                return True
        except DeviceInvalidError:
            pass
        return False

    def create_image(self, desired_size_kb):
        """Create an image and return its assigned UUID.

        @param desired_size_kb: Desired image size in KB.
        @type  desired_size_kb: int
        @rtype: string
        @return: uuid

        @raises XendError: If an error occurs.
        """
        self.lock.acquire()
        try:
            if not self._has_space_available_for(desired_size_kb):
                raise XendError("Not enough space")

            image_uuid = uuid.createString()
            # create file based image
            image_path = os.path.join(XEND_STORAGE_DIR,
                                      XEND_STORAGE_IMG_FILENAME % image_uuid)
            block = '\x00' * 1024
            img = open(image_path, 'w')
            for i in range(desired_size_kb):
                img.write(block)
            img.close()
            
            # TODO: create qcow image
            qcow_path = os.path.join(XEND_STORAGE_DIR,
                                     XEND_STORAGE_QCOW_FILENAME % image_uuid)
            cmd = QCOW_CREATE_COMMAND % (desired_size_kb/1024,
                                         qcow_path, image_path)

            rc, output = commands.getstatusoutput(cmd)
            if rc != 0:
                # cleanup the image file
                os.unlink(image_path)
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
                image_path = self.images[image_uuid].image_path
                try:
                    os.unlink(qcow_path)
                    os.unlink(image_path)
                except OSError:
                    # TODO: log warning
                    pass
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

    def free_space_kb(self):
        """Returns the amount of available space in KB.
        @rtype: int
        """
        self.lock.acquire()
        try:
            return self.storage_free
        finally:
            self.lock.release()
            
    def total_space_kb(self):
        """Returns the total usable space of the storage repo in KB.
        @rtype: int
        """
        self.lock.acquire()
        try:
            if self.storage_max != XEND_STORAGE_MAX_IGNORE:
                return self.storage_max
            else:
                return self.free_space_kb() + self.used_space_kb()
        finally:
            self.lock.release()
            
    def used_space_kb(self):
        """Returns the total amount of space used by this storage repository.
        @rtype: int
        """
        self.lock.acquire()
        try:
            total_used = 0
            for val in self.images.values():
                total_used += val.get_physical_utilisation()
            return total_used
        finally:
            self.lock.release()

    def used_space_bytes(self):
        return self.used_space_kb() * KB
    def free_space_bytes(self):
        return self.free_space_kb() * KB
    def total_space_bytes(self):
        return self.total_space_kb() * KB

    def is_valid_vdi(self, vdi_uuid):
        return (vdi_uuid in self.images)

# remove everything below this line!!
if __name__ == "__main__":
    xsr = XendStorageRepository()
    print 'Free Space: %d MB' % (xsr.free_space_kb()/1024)
    print "Create Image:",
    print xsr.create_image(10 * 1024)
    print 'Delete all images:'
    for image_uuid in xsr.list_images():
        print image_uuid,
        xsr.destroy_image(image_uuid)

    print
