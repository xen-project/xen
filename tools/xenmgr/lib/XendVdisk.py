# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Handler for vdisk operations.

"""

import os
import os.path

from xenctl import vdisk
    
import sxp

class XendVdiskInfo:

    def __init__(self, info):
        self.info = info
        self.id = info['vdisk_id']

    def __str__(self):
        return ("vdisk id=%(vdisk_id)s size=%(size)d expires=%(expires)d expiry_time=%(expiry_time)d"
                % self.info)

    def sxpr(self):
        val = ['vdisk']
        for (k,v) in self.info.items():
            val.append([k, str(v)])
        return val     

class XendVdisk:
    """Index of all vdisks. Singleton.
    """

    dbpath = "vdisk"

    def __init__(self):
        # Table of vdisk info indexed by vdisk id.
        self.vdisk = {}
        if not os.path.isfile(vdisk.VD_DB_FILE):
            vdisk.vd_init_db(vdisk.VD_DB_FILE)
        self.vdisk_refresh()

    def vdisk_refresh(self):
        # vdisk = {vdisk_id, size, expires, expiry_time}
        try:
            vdisks = vdisk.vd_list()
        except:
            vdisks = []
        for vdisk in vdisks:
            vdiskinfo = XendVdiskInfo(vdisk)
            self.vdisk[vdiskinfo.id] = vdiskinfo

    def vdisk_ls(self):
        """List all vdisk ids.
        """
        return self.vdisk.keys()

    def vdisks(self):
        return self.vdisk.values()
    
    def vdisk_get(self, id):
        """Get a vdisk.

        id	vdisk id
        """
        return self.vdisk.get(id)

    def vdisk_create(self, info):
        """Create a vdisk.

        info	config
        """
        # Need to configure for real.
        # vdisk.vd_create(size, expiry)

    def vdisk_configure(self, info):
        """Configure a vdisk.
        id	vdisk id
        info	config
        """
        # Need to configure for real.
        # Make bigger: vdisk.vd_enlarge(id, extra_size)
        # Update expiry time: vdisk.vd_refresh(id, expiry)
        # Try to recover an expired vdisk : vdisk.vd_undelete(id, expiry)
        

    def vdisk_delete(self, id):
        """Delete a vdisk.

        id	vdisk id
        """
        # Need to delete vdisk for real. What if fails?
        del self.vdisk[id]
        vdisk.vd_delete(id)

    # def vdisk_copy: copy contents to file, vdisk still exists
    # def vdisk_export: copy contents to file then delete the vdisk 
    # def vdisk_import: create a vdisk from a file
    # def vdisk_space: space left for new vdisks

    # def vdisk_recover: recover an expired vdisk

    # def vdisk_init_partition: setup a physical partition for vdisks

def instance():
    global inst
    try:
        inst
    except:
        inst = XendVdisk()
    return inst
